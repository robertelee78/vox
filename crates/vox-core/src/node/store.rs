//! The node's persistent store (ADR-016 §"Persistence: redb, sealed segments,
//! XDG layout").
//!
//! One `redb` file per profile. The API is **typed to sealed artifacts**: the only
//! things that can be written are ADR-010 [`SealedSegment`]s (log pages, plaintext
//! cache pages, indices, key material — each sealed under the channel SEK by
//! [`crate::atrest::store::seal_segment`] *before* it reaches here) and
//! [`SekWrap`]s (the double-locked SEK). The store therefore never holds plaintext
//! or a raw key, which is the ADR-010 at-rest property expressed as a type
//! signature rather than a convention.
//!
//! ## Tables
//! - `segments`: `(channel_id, kind, segment_id) → canonical SealedSegment bytes`
//! - `sek_wraps`: `channel_id → canonical SekWrap bytes`
//! - `meta`: `name → bytes` (currently only the schema version)
//!
//! (The `rendezvous` table is M14's.)
//!
//! ## Transactions
//! Single writes are one transaction each (committed and durable on return).
//! [`Store::batch`] groups several writes into one atomic transaction — a log
//! append and the chain-state advance it implies must land together or not at all.
//! `redb` has one writer at a time; the `Node` actor is that writer.
//!
//! ## Space
//! Deleting (TTL pruning) does not shrink the file; [`Store::compact`] does, and
//! the node schedules it after pruning (ADR-016 §Consequences).

use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};

use crate::atrest::sek::SekWrap;
use crate::atrest::store::{
    sealed_segment_from_slice, sealed_segment_to_vec, SealedSegment, SegmentKind,
};
use crate::error::{Error, Result};
use crate::hash::Digest32;

/// The on-disk schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

type SegmentKey = (Digest32, u8, u64);
const SEGMENTS: TableDefinition<SegmentKey, &[u8]> = TableDefinition::new("segments");
const SEK_WRAPS: TableDefinition<Digest32, &[u8]> = TableDefinition::new("sek_wraps");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const META_SCHEMA: &str = "schema_version";

/// Stable on-disk code for a [`SegmentKind`] (part of the key; never reordered).
const fn kind_code(kind: SegmentKind) -> u8 {
    match kind {
        SegmentKind::LogDb => 1,
        SegmentKind::PlaintextCache => 2,
        SegmentKind::Index => 3,
        SegmentKind::KeyMaterial => 4,
        SegmentKind::PrekeyRing => 5,
        SegmentKind::AnchorLog => 6,
        SegmentKind::AnchorMeta => 7,
        // The keyring is not stored as a segment (it is a sealed blob in `meta`,
        // because it belongs to no channel), but a kind must map to a stable code
        // or this match stops being exhaustive.
        SegmentKind::Trust => 8,
    }
}

fn storage<E: std::fmt::Display>(op: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Storage {
        op,
        detail: e.to_string(),
    }
}

/// The profile store.
pub struct Store {
    db: RwLock<Backing>,
    path: PathBuf,
}

/// How the store's file is open.
///
/// **Read-only until the identity is unlocked.** Opening a redb file writable writes to it —
/// its header and allocator state change on open and on close even if no transaction commits —
/// and a profile used to be opened writable the moment a node started, before any passphrase
/// was tried. So a command refused for a wrong passphrase had already written the profile,
/// changing its bytes and mtime (found 2026-09-25, on a real profile). A locked profile only
/// needs to read its public facts; it becomes writable in [`Store::make_writable`], which
/// `Profile::unlock` calls once the passphrase has been proved.
///
/// The single-writer rule is unchanged: a read-only open of a file some process holds open
/// for writing is refused just as a second writable open is, as [`Error::ProfileBusy`].
enum Backing {
    Writable(Database),
    ReadOnly(ReadOnlyDatabase),
    /// Only between releasing the read-only handle and taking the writable one.
    Closed,
}

impl Backing {
    fn begin_read(&self) -> Result<redb::ReadTransaction> {
        match self {
            Backing::Writable(db) => db.begin_read().map_err(storage("begin read")),
            Backing::ReadOnly(db) => db.begin_read().map_err(storage("begin read")),
            Backing::Closed => Err(Error::Storage {
                op: "begin read",
                detail: "the store is being reopened".into(),
            }),
        }
    }
}

/// redb names the busy case precisely; do not lose that by flattening it into a generic
/// storage failure. A profile that is merely *busy* is not a profile that is broken, and only
/// the caller can say what to do about it.
fn open_error(e: redb::DatabaseError) -> Error {
    if matches!(e, redb::DatabaseError::DatabaseAlreadyOpen) {
        Error::ProfileBusy
    } else {
        storage("open")(e)
    }
}

impl Store {
    /// Open (creating if absent) the store at `path` **writable**, set the file to `0600`, and
    /// initialize or verify the schema version. A file this build cannot read
    /// (garbage, or a newer schema) is a [`Error::Storage`], never a panic.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path).map_err(open_error)?;
        super::paths::set_private_file_mode(path)?;
        let store = Self {
            db: RwLock::new(Backing::Writable(db)),
            path: path.to_owned(),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an existing store **read-only**, writing nothing to it, for a profile whose
    /// identity is still locked — see `Backing`. It becomes writable with
    /// [`Self::make_writable`].
    ///
    /// A store that cannot be read as it is — tables missing, or a file redb must repair first —
    /// is opened writable instead, as [`Self::open`] would: that is a store that needs writing
    /// whoever opens it.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let db = match redb::Builder::new().open_read_only(path) {
            Ok(db) => db,
            Err(redb::DatabaseError::DatabaseAlreadyOpen) => return Err(Error::ProfileBusy),
            Err(_) => return Self::open(path),
        };
        let store = Self {
            db: RwLock::new(Backing::ReadOnly(db)),
            path: path.to_owned(),
        };
        if store.schema_is_current()? {
            Ok(store)
        } else {
            drop(store);
            Self::open(path)
        }
    }

    /// Reopen a read-only store writable; a no-op for one that already is.
    ///
    /// # Errors
    /// [`Error::ProfileBusy`] if another process took the profile in between, or a storage
    /// error — in which case the store stays readable as it was.
    pub fn make_writable(&self) -> Result<()> {
        let mut backing = self.db.write().unwrap_or_else(PoisonError::into_inner);
        if matches!(*backing, Backing::Writable(_)) {
            return Ok(());
        }
        // The read-only handle is released first: redb refuses a writable open of a file this
        // process still holds open.
        drop(std::mem::replace(&mut *backing, Backing::Closed));
        match Database::create(&self.path) {
            Ok(db) => {
                super::paths::set_private_file_mode(&self.path)?;
                *backing = Backing::Writable(db);
                Ok(())
            }
            Err(e) => {
                if let Ok(db) = redb::Builder::new().open_read_only(&self.path) {
                    *backing = Backing::ReadOnly(db);
                }
                Err(open_error(e))
            }
        }
    }

    /// Begin a read transaction on whichever handle is open.
    fn begin_read(&self) -> Result<redb::ReadTransaction> {
        self.db
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .begin_read()
    }

    /// Begin a write transaction — refused, writing nothing, while the store is read-only.
    fn begin_write(&self) -> Result<redb::WriteTransaction> {
        match &*self.db.read().unwrap_or_else(PoisonError::into_inner) {
            Backing::Writable(db) => db.begin_write().map_err(storage("begin write")),
            Backing::ReadOnly(_) | Backing::Closed => Err(Error::Storage {
                op: "begin write",
                detail: "the store is read-only until the identity is unlocked".into(),
            }),
        }
    }

    fn init_schema(&self) -> Result<()> {
        // **Read first; write only a store that needs it.** This used to open a write
        // transaction and commit it on every open, schema present or not — and every one-shot
        // verb opens the store before the identity passphrase is tried, so a command refused
        // for a wrong passphrase had already committed a write to the profile, changing its
        // bytes and mtime (found 2026-09-25, on a real profile). A store whose tables exist and
        // whose schema matches needs nothing written, so nothing is. The file lock that makes a
        // second process on the profile a `ProfileBusy` is taken by `Database::create`, not by
        // this transaction, so the single-writer rule is unchanged.
        if self.schema_is_current()? {
            return Ok(());
        }
        let txn = self.begin_write()?;
        {
            let mut meta = txn.open_table(META).map_err(storage("open meta"))?;
            // Ensure the other tables exist so readers never see "table missing".
            txn.open_table(SEGMENTS).map_err(storage("open segments"))?;
            txn.open_table(SEK_WRAPS)
                .map_err(storage("open sek_wraps"))?;
            // Copy the stored version out before any mutable use of the table.
            let found: Option<[u8; 4]> =
                match meta.get(META_SCHEMA).map_err(storage("read schema"))? {
                    None => None,
                    Some(v) => Some(v.value().try_into().map_err(|_| Error::Storage {
                        op: "read schema",
                        detail: "schema version is not 4 bytes".into(),
                    })?),
                };
            match found {
                None => {
                    meta.insert(META_SCHEMA, SCHEMA_VERSION.to_be_bytes().as_slice())
                        .map_err(storage("write schema"))?;
                }
                Some(bytes) => {
                    let found = u32::from_be_bytes(bytes);
                    if found != SCHEMA_VERSION {
                        return Err(Error::Storage {
                            op: "schema check",
                            detail: format!(
                                "on-disk schema {found}, this build reads {SCHEMA_VERSION}"
                            ),
                        });
                    }
                }
            }
        }
        txn.commit().map_err(storage("commit"))
    }

    /// Whether every table exists and the stored schema is this build's — a store that needs
    /// no write to be opened. A schema from another build is an error here, as it is below.
    fn schema_is_current(&self) -> Result<bool> {
        let txn = self.begin_read()?;
        let (Ok(meta), Ok(_), Ok(_)) = (
            txn.open_table(META),
            txn.open_table(SEGMENTS),
            txn.open_table(SEK_WRAPS),
        ) else {
            // A table that does not exist yet is what the write path creates.
            return Ok(false);
        };
        let Some(v) = meta.get(META_SCHEMA).map_err(storage("read schema"))? else {
            return Ok(false);
        };
        let bytes: [u8; 4] = v.value().try_into().map_err(|_| Error::Storage {
            op: "read schema",
            detail: "schema version is not 4 bytes".into(),
        })?;
        let found = u32::from_be_bytes(bytes);
        if found != SCHEMA_VERSION {
            return Err(Error::Storage {
                op: "schema check",
                detail: format!("on-disk schema {found}, this build reads {SCHEMA_VERSION}"),
            });
        }
        Ok(true)
    }

    /// The store's schema version (always [`SCHEMA_VERSION`] once opened).
    pub fn schema_version(&self) -> Result<u32> {
        let txn = self.begin_read()?;
        let meta = txn.open_table(META).map_err(storage("open meta"))?;
        let v = meta
            .get(META_SCHEMA)
            .map_err(storage("read schema"))?
            .ok_or(Error::Storage {
                op: "read schema",
                detail: "missing".into(),
            })?;
        let bytes: [u8; 4] = v.value().try_into().map_err(|_| Error::Storage {
            op: "read schema",
            detail: "schema version is not 4 bytes".into(),
        })?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Write one sealed segment (its own durable transaction).
    pub fn put_segment(
        &self,
        channel: &Digest32,
        kind: SegmentKind,
        id: u64,
        seg: &SealedSegment,
    ) -> Result<()> {
        let mut b = self.batch()?;
        b.put_segment(channel, kind, id, seg)?;
        b.commit()
    }

    /// Read one sealed segment.
    pub fn get_segment(
        &self,
        channel: &Digest32,
        kind: SegmentKind,
        id: u64,
    ) -> Result<Option<SealedSegment>> {
        let txn = self.begin_read()?;
        let t = txn.open_table(SEGMENTS).map_err(storage("open segments"))?;
        let key: SegmentKey = (*channel, kind_code(kind), id);
        match t.get(key).map_err(storage("read segment"))? {
            None => Ok(None),
            Some(v) => sealed_segment_from_slice(v.value()).map(Some),
        }
    }

    /// Every sealed segment of `kind` in `channel`, ordered by id ascending.
    pub fn segments(
        &self,
        channel: &Digest32,
        kind: SegmentKind,
    ) -> Result<Vec<(u64, SealedSegment)>> {
        let txn = self.begin_read()?;
        let t = txn.open_table(SEGMENTS).map_err(storage("open segments"))?;
        let lo: SegmentKey = (*channel, kind_code(kind), 0);
        let hi: SegmentKey = (*channel, kind_code(kind), u64::MAX);
        let mut out = Vec::new();
        for item in t.range(lo..=hi).map_err(storage("range segments"))? {
            let (k, v) = item.map_err(storage("iterate segments"))?;
            out.push((k.value().2, sealed_segment_from_slice(v.value())?));
        }
        Ok(out)
    }

    /// Delete one sealed segment; returns whether it existed.
    pub fn delete_segment(&self, channel: &Digest32, kind: SegmentKind, id: u64) -> Result<bool> {
        let mut b = self.batch()?;
        let existed = b.delete_segment(channel, kind, id)?;
        b.commit()?;
        Ok(existed)
    }

    /// Persist a channel's double-locked SEK wrap (its own durable transaction).
    pub fn put_sek_wrap(&self, channel: &Digest32, wrap: &SekWrap) -> Result<()> {
        let mut b = self.batch()?;
        b.put_sek_wrap(channel, wrap)?;
        b.commit()
    }

    /// Read a channel's SEK wrap.
    pub fn get_sek_wrap(&self, channel: &Digest32) -> Result<Option<SekWrap>> {
        let txn = self.begin_read()?;
        let t = txn
            .open_table(SEK_WRAPS)
            .map_err(storage("open sek_wraps"))?;
        match t.get(*channel).map_err(storage("read sek wrap"))? {
            None => Ok(None),
            Some(v) => SekWrap::from_canonical_slice(v.value()).map(Some),
        }
    }

    /// Every channel that has a SEK wrap, in key order.
    pub fn channels(&self) -> Result<Vec<Digest32>> {
        let txn = self.begin_read()?;
        let t = txn
            .open_table(SEK_WRAPS)
            .map_err(storage("open sek_wraps"))?;
        let mut out = Vec::new();
        for item in t.iter().map_err(storage("iterate sek_wraps"))? {
            let (k, _) = item.map_err(storage("iterate sek_wraps"))?;
            out.push(k.value());
        }
        Ok(out)
    }

    /// Every channel this store holds an **anchor** copy of (an `AnchorMeta` segment),
    /// in unspecified order — how a restarted anchor finds the rooms it was serving.
    pub fn anchored_channels(&self) -> Result<Vec<Digest32>> {
        let txn = self.begin_read()?;
        let t = txn.open_table(SEGMENTS).map_err(storage("open segments"))?;
        let mut out: Vec<Digest32> = Vec::new();
        for item in t.iter().map_err(storage("iterate segments"))? {
            let (k, _) = item.map_err(storage("iterate segments"))?;
            let (channel, kind, _) = k.value();
            if kind == kind_code(SegmentKind::AnchorMeta) && !out.contains(&channel) {
                out.push(channel);
            }
        }
        Ok(out)
    }

    /// Write a public metadata entry (its own durable transaction). Meta holds
    /// only public facts (schema version, identity fingerprint, creation time).
    pub fn put_meta(&self, name: &str, value: &[u8]) -> Result<()> {
        let txn = self.begin_write()?;
        {
            let mut meta = txn.open_table(META).map_err(storage("open meta"))?;
            meta.insert(name, value).map_err(storage("write meta"))?;
        }
        txn.commit().map_err(storage("commit"))
    }

    /// Read a public metadata entry.
    pub fn get_meta(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.begin_read()?;
        let meta = txn.open_table(META).map_err(storage("open meta"))?;
        Ok(meta
            .get(name)
            .map_err(storage("read meta"))?
            .map(|v| v.value().to_vec()))
    }

    /// Begin an atomic multi-write batch. Nothing is visible until
    /// [`Batch::commit`]; a dropped batch writes nothing.
    pub fn batch(&self) -> Result<Batch<'_>> {
        let txn = self.begin_write()?;
        Ok(Batch { txn, _store: self })
    }

    /// Reclaim space after deletions. Returns whether anything was compacted.
    pub fn compact(&mut self) -> Result<bool> {
        match self.db.get_mut().unwrap_or_else(PoisonError::into_inner) {
            Backing::Writable(db) => db.compact().map_err(storage("compact")),
            Backing::ReadOnly(_) | Backing::Closed => Ok(false),
        }
    }
}

/// An open write transaction over the store (see [`Store::batch`]).
pub struct Batch<'a> {
    txn: redb::WriteTransaction,
    _store: &'a Store,
}

impl Batch<'_> {
    /// Queue a sealed segment write.
    pub fn put_segment(
        &mut self,
        channel: &Digest32,
        kind: SegmentKind,
        id: u64,
        seg: &SealedSegment,
    ) -> Result<()> {
        let mut t = self
            .txn
            .open_table(SEGMENTS)
            .map_err(storage("open segments"))?;
        let key: SegmentKey = (*channel, kind_code(kind), id);
        t.insert(key, sealed_segment_to_vec(seg).as_slice())
            .map_err(storage("write segment"))?;
        Ok(())
    }

    /// Queue a sealed segment delete; returns whether it existed.
    pub fn delete_segment(
        &mut self,
        channel: &Digest32,
        kind: SegmentKind,
        id: u64,
    ) -> Result<bool> {
        let mut t = self
            .txn
            .open_table(SEGMENTS)
            .map_err(storage("open segments"))?;
        let key: SegmentKey = (*channel, kind_code(kind), id);
        let existed = t.remove(key).map_err(storage("delete segment"))?.is_some();
        Ok(existed)
    }

    /// Queue a SEK wrap write.
    pub fn put_sek_wrap(&mut self, channel: &Digest32, wrap: &SekWrap) -> Result<()> {
        let mut t = self
            .txn
            .open_table(SEK_WRAPS)
            .map_err(storage("open sek_wraps"))?;
        t.insert(*channel, wrap.to_canonical_vec().as_slice())
            .map_err(storage("write sek wrap"))?;
        Ok(())
    }

    /// Commit every queued write atomically and durably.
    pub fn commit(self) -> Result<()> {
        self.txn.commit().map_err(storage("commit"))
    }
}
