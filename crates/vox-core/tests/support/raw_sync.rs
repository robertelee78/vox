//! A sync peer that speaks the real ADR-008 frame sequence over a real Vox connection, but
//! chooses its own `WANT` and records exactly what it is sent.
//!
//! The node's own session code cannot ask for what an attacker would ask for — it computes its
//! `WANT` from the `HAVE` it received, and it only ever names rooms it holds — so a gate that
//! has to send a hostile request needs a peer that is not a node. This is that peer, and nothing
//! more: the identity it connects with is a **real member's**, taken from that member's profile,
//! so the victim classifies it exactly as it would the member's own node.
//!
//! The frame order is `frontier_session_peer`'s, which is symmetric, so the same function
//! answers a session the victim opens and drives one this peer opens: `HELLO` → `HAVE` →
//! `WANT` → (serve nothing) `FIN` → drain `ENTRY` frames until the victim's `FIN`.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use vox_core::hash::Digest32;
use vox_core::log::sync::{
    decode_frame, encode_have, encode_hello, encode_want, SyncFrame, Transport, WantRange,
};
use vox_core::node::api::NodeView;
use vox_core::node::paths::Paths;
use vox_core::node::profile::Profile;
use vox_core::transport::quic::{QuicStreamTransport, VoxConnection, VoxEndpoint};
use vox_core::wire::SYNC_MODE_FRONTIER;

/// What one session with the victim yielded.
#[derive(Debug, Default, Clone)]
pub struct Yield {
    /// The victim answered `HELLO` — the session got past the gate.
    pub hello: bool,
    /// How many feeds the victim's `HAVE` listed.
    pub frontiers: usize,
    /// Each listed feed's `(author, max_seq)`.
    pub have: Vec<(Digest32, u64)>,
    /// How many `ENTRY` frames the victim sent.
    pub entries: usize,
    /// How many of them were different entries: `entries` minus the ones served twice.
    pub distinct: usize,
    /// The entries seen so far, by content hash, to count `distinct`.
    seen: std::collections::HashSet<[u8; 32]>,
    /// Why the session ended, if not cleanly.
    pub ended: Option<String>,
}

/// The `WANT` to send: everything the victim lists, or a fixed hostile one.
#[derive(Debug, Clone)]
pub enum Ask {
    /// `(author, 1, max_seq)` for every feed in the victim's `HAVE` — what an honest cold peer asks.
    Everything,
    /// Exactly these ranges, whatever the victim holds.
    Ranges(Vec<WantRange>),
}

/// The unix time now, in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A node's dialable loopback address, from the ADR-012 multiaddrs it advertises.
pub fn dial_addr(view: &NodeView) -> SocketAddr {
    view.listening
        .iter()
        .find_map(|m| {
            let port = m.rsplit_once("/udp/")?.1;
            format!("127.0.0.1:{port}").parse().ok()
        })
        .unwrap_or_else(|| panic!("no dialable UDP endpoint in {:?}", view.listening))
}

/// Open a member's profile — its node must already be shut down — and bind an endpoint as that
/// member. Retries while the old node's store is still being released.
pub async fn endpoint_as_member(paths: &Paths, passphrase: &[u8]) -> VoxEndpoint {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut profile = loop {
        match Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => panic!("the member's profile did not open: {e:?}"),
        }
    };
    profile
        .unlock(passphrase)
        .expect("the member's identity unlocks");
    let signer = profile.signer_arc().expect("the member's signer");
    VoxEndpoint::bind(&*signer, "127.0.0.1:0".parse().unwrap()).expect("bind as the member")
}

/// Run one session over an already-open sync transport. Blocking: call from
/// `spawn_blocking`. `sent_want` is signalled the moment the `WANT` is on the wire.
pub fn session(
    mut t: QuicStreamTransport,
    ask: &Ask,
    sent_want: Option<std::sync::mpsc::Sender<()>>,
) -> Yield {
    let mut y = Yield::default();
    if let Err(e) = t.send(&encode_hello(SYNC_MODE_FRONTIER)) {
        y.ended = Some(format!("send HELLO: {e:?}"));
        return y;
    }
    match t.recv() {
        Ok(Some(f)) if matches!(decode_frame(&f), Ok(SyncFrame::Hello(_))) => y.hello = true,
        other => {
            y.ended = Some(format!("no HELLO: {other:?}"));
            return y;
        }
    }
    if let Err(e) = t.send(&encode_have(&[])) {
        y.ended = Some(format!("send HAVE: {e:?}"));
        return y;
    }
    let have = match t.recv() {
        Ok(Some(f)) => match decode_frame(&f) {
            Ok(SyncFrame::Have(v)) => v,
            other => {
                y.ended = Some(format!("no HAVE: {other:?}"));
                return y;
            }
        },
        other => {
            y.ended = Some(format!("no HAVE: {other:?}"));
            return y;
        }
    };
    y.frontiers = have.len();
    y.have = have.iter().map(|f| (f.author_id, f.max_seq)).collect();
    let want = match ask {
        Ask::Everything => have
            .iter()
            .map(|f| WantRange {
                author_id: f.author_id,
                from_seq: 1,
                to_seq: f.max_seq,
            })
            .collect(),
        Ask::Ranges(r) => r.clone(),
    };
    if let Err(e) = t.send(&encode_want(&want)) {
        y.ended = Some(format!("send WANT: {e:?}"));
        return y;
    }
    if let Some(tx) = sent_want {
        let _ = tx.send(());
    }
    // The victim's WANT, then our (empty) serve, then FIN so its drain ends.
    match t.recv() {
        Ok(Some(f)) if matches!(decode_frame(&f), Ok(SyncFrame::Want(_))) => {}
        other => {
            y.ended = Some(format!("no WANT: {other:?}"));
            return y;
        }
    }
    t.finish();
    loop {
        match t.recv() {
            Ok(Some(f)) => match decode_frame(&f) {
                Ok(SyncFrame::Entry(wire)) => {
                    y.entries += 1;
                    if y.seen.insert(vox_core::hash::sha256(&wire)) {
                        y.distinct += 1;
                    }
                }
                other => {
                    y.ended = Some(format!("unexpected frame: {other:?}"));
                    return y;
                }
            },
            Ok(None) => return y,
            Err(e) => {
                y.ended = Some(format!("recv: {e:?}"));
                return y;
            }
        }
    }
}

/// Open a sync stream for `(channel_id, epoch)` on `conn` and run [`session`] on it.
pub async fn ask(
    conn: &VoxConnection,
    channel_id: Digest32,
    epoch: u64,
    ask: Ask,
    sent_want: Option<std::sync::mpsc::Sender<()>>,
) -> Yield {
    let handle = tokio::runtime::Handle::current();
    let t = match vox_core::node::syncstream::open_sync(conn, handle, &channel_id, epoch).await {
        Ok(t) => t,
        Err(e) => {
            return Yield {
                ended: Some(format!("open: {e:?}")),
                ..Yield::default()
            }
        }
    };
    tokio::task::spawn_blocking(move || session(t, &ask, sent_want))
        .await
        .expect("the session thread")
}

/// Answer every session the victim opens on `conn` with [`session`] (asking for everything), and
/// record per channel what it yielded — the victim pushes rooms to a fresh connection on its own,
/// and that direction must be bound by the same rule as the one this peer opens.
pub fn answer_victim(conn: Arc<VoxConnection>) -> Arc<Mutex<Vec<(Digest32, Yield)>>> {
    let got = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&got);
    tokio::spawn(async move {
        while let Ok((_kind, send, mut recv)) =
            vox_core::transport::streams::accept_typed(&conn).await
        {
            let record = Arc::clone(&record);
            tokio::spawn(async move {
                let Ok((cid, _epoch)) =
                    vox_core::node::syncstream::read_sync_request(&mut recv).await
                else {
                    return;
                };
                let t = vox_core::node::syncstream::accept_sync(
                    tokio::runtime::Handle::current(),
                    send,
                    recv,
                );
                let y = tokio::task::spawn_blocking(move || session(t, &Ask::Everything, None))
                    .await
                    .expect("the session thread");
                record.lock().unwrap().push((cid, y));
            });
        }
    });
    got
}
