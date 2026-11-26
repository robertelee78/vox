//! Introduce this node's board records before a room's first pull.

use crate::error::Error;
use crate::transport::quic::VoxConnection;
use crate::transport::stream_transport::Fence;

// Ledger 91: the first time this connection is used for the room, this node's own board
// records go to the peer's board, and the request waits for the board's answer. A member the
// peer does not know yet is then on its board, so the Sync stream gate takes it and the
// peer's roster admission runs on the request itself. A refusal as a stranger puts them again.

/// Put this node's own board records (its bundle, then its address record, whose key the bundle
/// carries) on the peer's board, and wait for its answer. A refusal is the peer's board policy
/// speaking (an older claim, a record it already holds): the request goes on either way.
pub(super) async fn introduce(
    conn: &VoxConnection,
    records: &[Vec<u8>],
    fence: &Fence,
    deadline: tokio::time::Instant,
) {
    if records.is_empty() {
        return;
    }
    let put = async {
        let mut client = crate::nat::service::RendezvousClient::open(conn).await?;
        for record in records {
            let _ = client.put(record).await;
        }
        client.finish();
        Ok::<_, Error>(())
    };
    tokio::select! {
        biased;
        () = fence.retired() => {}
        _ = tokio::time::timeout_at(deadline, put) => {}
    }
}
