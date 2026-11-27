//! Decode bounded-history requests on the typed Sync stream.

use crate::cbor::Decoder;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::history_stream::Preamble;
use crate::transport::framing::read_frame;

/// The largest sync preamble either side will read.
const MAX_SYNC_PREAMBLE: usize = crate::node::history_stream::MAX_PREAMBLE;

/// What a request stream opened with.
pub(crate) enum Opening {
    /// A history preamble of the version this node speaks.
    Request(Preamble),
    /// A valid legacy preamble, which the caller refuses explicitly.
    Legacy,
    /// A history preamble of another Vox version, naming this room (R10): the caller refuses it
    /// and says so on that member's sync row (R11).
    OtherVersion(Digest32),
}

pub(crate) async fn read_request_preamble(recv: &mut quinn::RecvStream) -> Result<Opening> {
    let bytes = read_frame(recv, MAX_SYNC_PREAMBLE)
        .await?
        .ok_or(Error::MalformedGovernance(
            "sync stream closed before preamble",
        ))?;
    let mut d = Decoder::new(&bytes);
    let arity = d.array()?;
    if arity == 6 {
        return match Preamble::decode(&bytes) {
            Ok(preamble) => Ok(Opening::Request(preamble)),
            Err(error) => Preamble::other_version(&bytes)
                .map(Opening::OtherVersion)
                .ok_or(error),
        };
    }
    if arity != 2 {
        return Err(Error::MalformedGovernance("sync preamble arity"));
    }
    let _: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("sync preamble room id"))?;
    d.uint()?;
    d.finish()?;
    Ok(Opening::Legacy)
}
