//! Normalized authority-input frontiers. Ordinary messages, names and consents
//! do not create new authority scopes when their cert/revoke inputs are the same.

use super::authority::{Grant, Query, Scope};
use super::facts::{hash_key, position, Table, Write};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};

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
                .map_err(|_| invalid("authority context hash"))?,
        )),
        _ => Err(invalid("authority context hash arity")),
    }
}

#[derive(Clone)]
pub(super) struct CachedQuery {
    scope: Scope,
    target: Digest32,
    author: Option<Digest32>,
    digest: Digest32,
    normalized: bool,
    query: Option<Query>,
}

impl CachedQuery {
    pub(super) fn new(scope: Scope, target: Digest32) -> Self {
        Self {
            scope,
            target,
            author: None,
            digest: sha256(b"vox/governance-authority-input/v1"),
            normalized: false,
            query: None,
        }
    }

    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(6);
        option(e, self.scope.0);
        e.bytes(&self.target);
        option(e, self.author);
        e.bytes(&self.digest).uint(u64::from(self.normalized));
        match &self.query {
            Some(query) => {
                e.array(1);
                query.write(e);
            }
            None => {
                e.array(0);
            }
        }
    }

    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 6 {
            return Err(invalid("authority context arity"));
        }
        let scope = Scope(read_option(d)?);
        let target = d
            .bytes()?
            .try_into()
            .map_err(|_| invalid("authority context target"))?;
        let author = read_option(d)?;
        let digest = d
            .bytes()?
            .try_into()
            .map_err(|_| invalid("authority context digest"))?;
        let normalized = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("authority context boolean")),
        };
        let query = match d.array()? {
            0 => None,
            1 => Some(Query::read(d)?),
            _ => return Err(invalid("authority context query arity")),
        };
        if !normalized && query.is_some() {
            return Err(invalid("authority query before context"));
        }
        Ok(Self {
            scope,
            target,
            author,
            digest,
            normalized,
            query,
        })
    }

    pub(super) fn advance(
        &mut self,
        writer: &mut Write<'_, '_>,
        root: &Digest32,
        now_ms: u64,
        generation: u64,
    ) -> Result<Option<Grant>> {
        if self.target == *root {
            return Ok(Some(Grant::root()));
        }
        if !self.normalized {
            self.normalize(writer)?;
            return Ok(None);
        }
        let mut key = hash_key(&self.digest);
        key[32..].copy_from_slice(&self.target);
        if self.query.is_none() {
            if let Some(record) = writer.get(Table::AuthorityCache, &key)? {
                let bytes = writer.record(record)?;
                let mut d = Decoder::new(&bytes);
                if d.array()? != 3 || d.uint()? != 1 {
                    return Err(invalid("authority cache format"));
                }
                let prior_generation = d.uint()?;
                let grant = Grant::read(&mut d)?;
                d.finish()?;
                if prior_generation == generation {
                    return Ok(Some(grant));
                }
                if prior_generation > generation {
                    return Err(invalid("authority cache generation regressed"));
                }
            }
            self.query = Some(Query::new(self.scope, self.target));
        }
        let query = self
            .query
            .as_mut()
            .ok_or(invalid("authority context query missing"))?;
        let Some(grant) = query.advance(writer, root, now_ms, generation)? else {
            return Ok(None);
        };
        let old = writer.get(Table::AuthorityCache, &key)?;
        let mut e = Encoder::new();
        e.array(3).uint(1).uint(generation);
        grant.write(&mut e);
        let record = writer.save_record(old, &e.finish())?;
        writer.put(Table::AuthorityCache, key, Some(record))?;
        Ok(Some(grant))
    }

    fn normalize(&mut self, writer: &Write<'_, '_>) -> Result<()> {
        let coordinate = match self.scope.0 {
            Some(scope) => writer.frontier_after(&scope, self.author)?,
            None => {
                let after = self.author.map(|author| {
                    let mut key = hash_key(&author);
                    key[32..].fill(u8::MAX);
                    key
                });
                match writer.first(Table::AuthorityPositions, after)? {
                    Some((key, _)) => Some((
                        key[..32]
                            .try_into()
                            .map_err(|_| invalid("authority context author"))?,
                        u64::MAX,
                    )),
                    None => None,
                }
            }
        };
        let Some((author, seq)) = coordinate else {
            self.normalized = true;
            return Ok(());
        };
        self.author = Some(author);
        let mut before = position(&author, seq);
        before[40] = 1; // include the coordinate's exact zero-padded position
        let mut row = writer
            .last(Table::AuthorityPositions, Some(before))?
            .filter(|(key, _)| key[..32] == author[..]);
        if let (Some(scope), Some((key, log))) = (self.scope.0, row) {
            let entry = writer.entry(log)?;
            if entry.entry_hash() == scope {
                row = writer
                    .last(Table::AuthorityPositions, Some(key))?
                    .filter(|(key, _)| key[..32] == author[..]);
            }
        }
        if let Some((key, _)) = row {
            if key[40..].iter().any(|b| *b != 0) {
                return Err(invalid("authority context position"));
            }
            // This exact normalized vector determines all in-scope cert/revoke
            // facts in one generation. No historical entry set is copied.
            let mut input = [0; 72];
            input[..32].copy_from_slice(&self.digest);
            input[32..64].copy_from_slice(&author);
            input[64..].copy_from_slice(&key[32..40]);
            self.digest = sha256(&input);
        }
        Ok(())
    }
}
