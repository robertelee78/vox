//! One native private expiry quantum, shared by maintenance and receiver replay.
use super::*;

/// Remove up to one quantum of expired private Session items. Returns how many, and whether
/// nothing expired is left: the walk found none before its bounds.
pub(in crate::node::channel) fn sweep_private(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    now: u64,
    expiry: crate::node::retention::Expiry,
    mut committed: impl FnMut(Digest32),
) -> Result<(usize, bool)> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for _ in 0..WORK_ROWS {
        let snapshot = store.snapshot()?;
        let Some(id) = private_index::next_expired(&snapshot, sek, room, now, expiry)? else {
            return Ok((count, true));
        };
        let segment = snapshot
            .get_segment_bounded(
                room,
                SegmentKind::PrivateSession,
                id,
                2 * crate::node::sessionstream::MAX_RECORD,
            )?
            .ok_or(Error::MalformedAtRest("Session expiry locator missing"))?;
        let saved = Stored::read(&open_segment(
            sek,
            SegmentKind::PrivateSession,
            id,
            &segment,
        )?)?;
        let size = saved.record.message.ciphertext.len();
        if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        if !expired(&saved, now, expiry) {
            return Err(Error::MalformedAtRest("Session expiry fact differs"));
        }
        drop(snapshot);
        let mut batch = store.batch()?;
        batch.derived();
        batch.delete_segment(room, SegmentKind::PrivateSession, id)?;
        private_index::remove(&mut batch, sek, room, id, &saved)?;
        batch.commit()?;
        count = count.saturating_add(1);
        committed(saved.record.hash());
    }
    Ok((count, false))
}
