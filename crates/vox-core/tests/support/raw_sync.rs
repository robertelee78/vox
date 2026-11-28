//! Identity and endpoint helpers for test-side wire peers.

#![allow(dead_code)]

use vox_core::hash::Digest32;
use vox_core::node::paths::Paths;
use vox_core::node::profile::Profile;
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};

/// The unix time now, in milliseconds (what a dial stamps its session record with).
pub fn now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
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
    VoxEndpoint::bind(signer, "127.0.0.1:0".parse().unwrap()).expect("bind as the member")
}

/// The full id of the room whose id begins with `prefix`, and its epoch, from a node's
/// `vox status --json`: what a wire peer's history exchange names. `None` while the node does
/// not hold the room open (not listed, or still preparing it).
pub fn room_and_epoch(status: &str, prefix: &str) -> Option<(Digest32, u64)> {
    let v: serde_json::Value =
        serde_json::from_str(status.trim()).expect("APPARATUS: vox status --json printed JSON");
    let room = v["rooms"].as_array().and_then(|rooms| {
        rooms
            .iter()
            .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(prefix)))
    })?;
    let id = vox_core::node::link::b32_decode(room["id"].as_str().unwrap_or_default(), "room")
        .unwrap_or_else(|e| {
            panic!(
                "PRODUCT (staging): vox status names a room id that does not decode ({e:?}): \
                 {status}"
            )
        });
    Some((id, room["epoch"].as_u64().unwrap_or(0)))
}

/// One version-3 history exchange for `room` at `epoch` on `conn`, as a member's node makes one
/// on every connection: a Have (here of nothing: the wire peer tells no history), which the node
/// answers with `HELLO` and `DONE`. A node writes a room key only on a connection that completed
/// one for that room and epoch (ADR-055 FO-10 item 2). Spoken byte for byte from the wire format
/// (`history_stream.rs`: `Preamble::encode`, `Frame::encode_bytes`, `Query::encode`). Returns the
/// node's `DONE` status (0: complete).
pub async fn exchange_history(
    conn: &VoxConnection,
    room: &Digest32,
    epoch: u64,
) -> Result<u64, String> {
    use vox_core::cbor::{Decoder, Encoder};
    use vox_core::transport::framing::{read_frame, write_frame};
    use vox_core::transport::streams::{open_typed, StreamKind};
    let frame = |tag: u8, body: &dyn Fn(&mut Encoder)| -> Vec<u8> {
        let mut e = Encoder::new();
        body(&mut e);
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&e.finish());
        bytes
    };
    let mut request = [0u8; 16];
    request[..8].copy_from_slice(&now().to_be_bytes());
    request[8..].copy_from_slice(&room[..8]);
    // Version 3, the room, its epoch, the public scope, purpose Control, the request.
    let mut e = Encoder::new();
    e.array(6)
        .uint(3)
        .bytes(room)
        .uint(epoch)
        .uint(0)
        .uint(0)
        .bytes(&request);
    let preamble = e.finish();
    let hello = frame(0x01, &|e| {
        e.uint(u64::from(vox_core::wire::SYNC_MODE_BOUNDED_HISTORY));
    });
    // WANT of the Have query, with no head target.
    let want = frame(0x03, &|e| {
        e.array(3).bytes(&request);
        e.array(1).uint(10);
        e.array(0);
    });
    let holding = frame(0x0C, &|e| {
        e.array(0);
    });
    let failed = |e: &dyn std::fmt::Debug| format!("{e:?}");
    let (mut send, mut recv) = open_typed(conn, StreamKind::Sync)
        .await
        .map_err(|e| failed(&e))?;
    for f in [&preamble, &hello, &want, &holding] {
        write_frame(&mut send, f).await.map_err(|e| failed(&e))?;
    }
    let mut status = Err("the node ended the exchange without DONE".to_owned());
    while let Some(f) = read_frame(&mut recv, 1 << 20)
        .await
        .map_err(|e| failed(&e))?
    {
        if f.first() == Some(&0x08) {
            let mut d = Decoder::new(&f[1..]);
            d.array().map_err(|e| failed(&e))?;
            d.bytes().map_err(|e| failed(&e))?;
            status = d.uint().map_err(|e| failed(&e));
            break;
        }
    }
    let _ = send.finish();
    status
}
