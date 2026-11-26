//! Decode bounded-history requests on the typed Sync stream.

use crate::cbor::Decoder;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::read_frame;

/// The largest sync preamble either side will read.
const MAX_SYNC_PREAMBLE: usize = crate::node::history_stream::MAX_PREAMBLE;

/// A valid legacy preamble returns `None` so the caller can refuse it explicitly.
pub(crate) async fn read_request_preamble(
    recv: &mut quinn::RecvStream,
) -> Result<Option<crate::node::history_stream::Preamble>> {
    let bytes = read_frame(recv, MAX_SYNC_PREAMBLE)
        .await?
        .ok_or(Error::MalformedGovernance(
            "sync stream closed before preamble",
        ))?;
    let mut d = Decoder::new(&bytes);
    let arity = d.array()?;
    if arity == 6 {
        return crate::node::history_stream::Preamble::decode(&bytes).map(Some);
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
    Ok(None)
}
