//! A package-only on-disk catalog. Publication cursors increase on late body fills too;
//! retrying keys never scans unrelated message bodies and keeps one live locator per log row.
use super::*;

fn key(cursor: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&cursor.to_be_bytes());
    key
}
fn cursor(key: &Key) -> Result<u64> {
    if key[8..].iter().any(|v| *v != 0) {
        return Err(invalid("key-package cursor"));
    }
    Ok(u64::from_be_bytes(
        key[..8]
            .try_into()
            .map_err(|_| invalid("key-package cursor"))?,
    ))
}

impl Read<'_> {
    pub(crate) fn key_package_tip(&self) -> Result<u64> {
        if !self.directory.packages_ready {
            return Err(invalid("key-package catalog preparing"));
        }
        Ok(self.directory.active.key_tip)
    }
    pub(crate) fn key_package_after(&self, after: Option<u64>) -> Result<Option<(u64, u64)>> {
        let _ = self.key_package_tip()?;
        let Some(next) = after.unwrap_or(0).checked_add(1) else {
            return Ok(None);
        };
        match self.source().first(
            self.sek,
            self.channel,
            self.directory.active.key_packages,
            &key(next),
            0,
        )? {
            Some((at, Value::Number(log))) if log != 0 => Ok(Some((cursor(&at)?, log))),
            None => Ok(None),
            _ => Err(invalid("key-package locator")),
        }
    }
}
impl Write<'_, '_> {
    fn index_package(&mut self, mut roots: Roots, entry: &Entry, log: u64) -> Result<Roots> {
        if !entry
            .payload
            .as_deref()
            .is_some_and(crate::node::keypackage::KeyPackage::is_key_package)
        {
            return Ok(roots);
        }
        if let Some(value) = Source::Batch(self.batch).find_value(
            self.sek,
            self.channel,
            roots.key_latest,
            &key(log),
        )? {
            let Value::Number(old) = value else {
                return Err(invalid("key-package latest locator"));
            };
            roots.key_packages = self.change_value(roots.key_packages, key(old), None)?;
        }
        let at = self.directory.next_package;
        self.directory.next_package = at
            .checked_add(1)
            .ok_or(invalid("key-package cursor exhausted"))?;
        roots.key_packages =
            self.change_value(roots.key_packages, key(at), Some(Value::Number(log)))?;
        roots.key_latest =
            self.change_value(roots.key_latest, key(log), Some(Value::Number(at)))?;
        roots.key_tip = at;
        Ok(roots)
    }
}
impl EntryIndex {
    /// Only a pre-checkpoint store needs this bootstrap. Normal reopen reads its ready
    /// marker and performs no scan or write. Rows stay bounded by count and sealed bytes.
    pub(crate) fn prepare_packages(
        &self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        dag: &crate::log::dag::Dag,
    ) -> Result<()> {
        loop {
            let mut batch = store.batch()?;
            let mut writer = self.write(&mut batch, sek, room)?;
            if writer.directory.packages_ready {
                return Ok(());
            }
            let mut bytes = 0;
            let mut done = false;
            for _ in 0..PROMOTION_ENTRIES {
                let Some((id, sealed)) = writer.batch.segment_after(
                    room,
                    SegmentKind::LogDb,
                    writer.directory.packages_cursor,
                )?
                else {
                    done = true;
                    break;
                };
                let wire = open_segment(sek, SegmentKind::LogDb, id, &sealed)?;
                if bytes != 0 && bytes + wire.len() > PROMOTION_BYTES {
                    break;
                }
                bytes += wire.len();
                let entry = Entry::from_wire(&wire)?;
                if entry.skeleton.seq <= dag.verified_head(&entry.skeleton.author_id) {
                    writer.directory.active =
                        writer.index_package(writer.directory.active, &entry, id)?;
                }
                writer.directory.packages_cursor = Some(id);
            }
            if done {
                writer.directory.packages_ready = true;
                writer.directory.packages_cursor = None;
            }
            writer.seal()?;
            batch.commit()?;
            self.committed();
            if done {
                return Ok(());
            }
        }
    }
}
