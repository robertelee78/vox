//! Last-known room anchors for the daemon's machine list (ADR-032 AN-2/3).
//!
//! This private, unsealed display cache keeps names and public anchor addresses visible when
//! room keys are closed or a node is locked. It grants no dialing, membership or trust authority:
//! only an opened room supplies those. Keeping it beside the node carries it with a rename and
//! removes it with the node. A failed read is never mistaken for an empty inventory.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::nat::bootstrap::BootstrapSet;
use crate::node::api::RoomAnchorView;
use crate::node::paths::Paths;

const FILE: &str = "anchor-inventory.cbor";
const VERSION: u64 = 1;

/// Read a node's last-known room provenance. Every returned row is stale until its room is read.
/// A missing file has no observations yet; unreadable or unsupported data is refused unchanged.
pub fn load(paths: &Paths) -> Result<Vec<RoomAnchorView>> {
    let path = paths.profile_dir.join(FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Error::Path {
                op: "read anchor inventory",
                detail: format!("{}: {error}", path.display()),
            });
        }
    };
    let mut d = Decoder::new(&bytes);
    if d.array()? != 2 || d.uint()? != VERSION {
        return Err(Error::MalformedIpc("unsupported anchor inventory format"));
    }
    let count = d.array()?;
    let mut rooms = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        if d.array()? != 4 {
            return Err(Error::MalformedIpc("anchor inventory room arity"));
        }
        let room = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedIpc("anchor inventory room identity"))?;
        if rooms
            .last()
            .is_some_and(|previous: &RoomAnchorView| previous.room >= room)
        {
            return Err(Error::MalformedIpc("anchor inventory room order"));
        }
        let name = d.text()?.to_owned();
        rooms.push(RoomAnchorView {
            room,
            name: (!name.is_empty()).then_some(name),
            anchors: BootstrapSet::from_bytes(d.bytes()?)?,
            stale: true,
            observed_at: d.uint()?,
        });
    }
    d.finish()?;
    Ok(rooms)
}

/// Atomically and durably replace a node's display inventory; freshness is never persisted.
pub(crate) fn save(paths: &Paths, rooms: &[RoomAnchorView]) -> Result<()> {
    let mut e = Encoder::new();
    e.array(2).uint(VERSION).array(rooms.len());
    for room in rooms {
        e.array(4)
            .bytes(&room.room)
            .text(room.name.as_deref().unwrap_or_default())
            .bytes(&room.anchors.to_bytes())
            .uint(room.observed_at);
    }
    crate::node::paths::write_private_file(&paths.profile_dir.join(FILE), &e.finish())
}
