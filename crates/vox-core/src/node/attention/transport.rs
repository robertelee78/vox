//! One private selected query per existing app stream; own mutations use the owned IPC lease.
use super::*;
use crate::cbor::{Decoder, Encoder};
use crate::node::ipc::{self, Frame, IpcClient, NodeSocket, Request};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

const OWN: u64 = 8750;
const ANSWER: u64 = 8751;
const WITHIN: std::time::Duration = std::time::Duration::from_secs(15);

/// Attention request on an authenticated owned node socket. Remote peers cannot submit this.
#[derive(Debug, Clone)]
pub struct OwnRequest {
    /// Exact saved room.
    pub room: Digest32,
    /// Captured local room incarnation, checked by the actor with the operation.
    pub instance: Option<[u8; 16]>,
    /// One bounded operation.
    pub operation: Operation,
}
impl OwnRequest {
    /// Decode only this extension's bounded complete frame.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() > MAX_BYTES {
            return None;
        }
        let mut d = Decoder::new(body);
        if d.array().ok()? != 4 || d.uint().ok()? != OWN {
            return None;
        }
        let room = d.bytes().ok()?.try_into().ok()?;
        let instance = match d.bytes().ok()? {
            [] => None,
            bytes => Some(bytes.try_into().ok()?),
        };
        let operation = serde_json::from_str(d.text().ok()?).ok()?;
        d.finish().ok()?;
        Some(Self {
            room,
            instance,
            operation,
        })
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        let json = serde_json::to_string(&self.operation).map_err(|e| e.to_string())?;
        let mut e = Encoder::new();
        e.array(4)
            .uint(OWN)
            .bytes(&self.room)
            .bytes(self.instance.as_ref().map_or(&[], |i| i.as_slice()))
            .text(&json);
        let bytes = e.finish();
        if bytes.len() > MAX_BYTES {
            return Err("attention request exceeds its bound".into());
        }
        Ok(bytes)
    }
    /// Encode one result for the owned node IPC client.
    ///
    /// # Errors
    /// Serialization failed or the encoded answer exceeds the private transport bound.
    pub fn answer(result: &Result<Reply, String>) -> Result<Vec<u8>, String> {
        let json = serde_json::to_string(result).map_err(|e| e.to_string())?;
        if json.len() > MAX_BYTES {
            return Err("attention answer exceeds its bound".into());
        }
        let mut e = Encoder::new();
        e.array(2).uint(ANSWER).text(&json);
        let bytes = e.finish();
        if bytes.len() > MAX_BYTES {
            return Err("attention answer exceeds its bound".into());
        }
        Ok(bytes)
    }
}
async fn own(stream: &mut tokio::net::UnixStream, request: OwnRequest) -> Result<Reply, String> {
    ipc::write_frame(stream, &request.bytes()?)
        .await
        .map_err(|e| e.to_string())?;
    let body = ipc::read_frame(stream)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("attention request closed without an answer")?;
    if body.len() > MAX_BYTES {
        return Err("attention answer exceeds its bound".into());
    }
    let mut d = Decoder::new(&body);
    if d.array().ok() != Some(2) || d.uint().ok() != Some(ANSWER) {
        return match Frame::from_bytes(&body) {
            Ok(Frame::Error { reason }) => Err(reason),
            _ => Err("unexpected attention answer".into()),
        };
    }
    let result: Result<Reply, String> =
        serde_json::from_str(d.text().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    d.finish().map_err(|e| e.to_string())?;
    result
}

/// One local daemon/hook operation, bound to the selected actor and room incarnation.
/// Cancellation after a mutation write is uncertain; callers must reconcile, never infer failure.
///
/// # Errors
/// Current identity, room or Session changed, authority refused, or the bounded request failed.
pub async fn local(
    at: &NodeSocket,
    actor: Digest32,
    room: Digest32,
    instance: Option<[u8; 16]>,
    operation: Operation,
) -> Result<Reply, String> {
    tokio::time::timeout(WITHIN, async {
        let (mut stream, me) = ipc::open_as(at).await.map_err(|e| e.to_string())?;
        if me != Some(actor) {
            return Err("the selected node changed; refresh and retry".into());
        }
        own(
            &mut stream,
            OwnRequest {
                room,
                instance,
                operation,
            },
        )
        .await
    })
    .await
    .map_err(|_| "attention request did not finish; mutation outcome is unknown".to_owned())?
}
async fn check(
    at: &NodeSocket,
    actor: Digest32,
    room: Digest32,
    instance: [u8; 16],
) -> Result<(), String> {
    let mut client = IpcClient::open_at(at).await.map_err(|e| e.to_string())?;
    if client.me() != Some(actor) {
        return Err("the selected node changed; refresh and retry".into());
    }
    match client
        .request(&Request::ArrivalHead { channel_id: room })
        .await
        .map_err(|e| e.to_string())?
    {
        Frame::ArrivalHead { head } if head.instance == instance => Ok(()),
        Frame::Error { reason } => Err(reason),
        _ => Err("the selected room changed; refresh and retry".into()),
    }
}

/// Read one private selected Session's attention page. Receiver drive/member/opening checks
/// occur with the query; the retained app gate fences room removal and trust withdrawal.
/// Local actor/room checks also run after the response, before it can be published by a caller.
///
/// # Errors
/// Selection, current authority or bounded transport is unavailable. No Session is woken.
#[allow(clippy::too_many_arguments)]
pub async fn page_checked(
    at: &NodeSocket,
    room: Digest32,
    peer: Digest32,
    session: &str,
    opening: Digest32,
    actor: Digest32,
    instance: [u8; 16],
    after: Option<Cursor>,
) -> Result<Page, String> {
    tokio::time::timeout(WITHIN, async {
        check(at, actor, room, instance).await?;
        let query = Query {
            session: session.to_owned(),
            opening,
            after,
        };
        let (mut stream, me) = ipc::open_as(at).await.map_err(|e| e.to_string())?;
        if me != Some(actor) {
            return Err("the selected node changed; refresh and retry".into());
        }
        let page = if peer == actor {
            match own(
                &mut stream,
                OwnRequest {
                    room,
                    instance: Some(instance),
                    operation: Operation::Page(query),
                },
            )
            .await?
            {
                Reply::Page(page) => page,
                _ => return Err("unexpected attention page answer".into()),
            }
        } else {
            let (stream, _) =
                crate::node::appipc::open_on(stream, room, peer, vec![LABEL.into()], false)
                    .await
                    .map_err(|e| e.to_string())?;
            check(at, actor, room, instance).await?;
            let mut bytes = serde_json::to_vec(&query).map_err(|e| e.to_string())?;
            bytes.push(b'\n');
            if bytes.len() > MAX_BYTES {
                return Err("attention query exceeds its bound".into());
            }
            let (r, mut w) = stream.into_split();
            w.write_all(&bytes).await.map_err(|e| e.to_string())?;
            let mut body = String::new();
            tokio::io::BufReader::new(r)
                .take((MAX_BYTES + 1) as u64)
                .read_line(&mut body)
                .await
                .map_err(|e| e.to_string())?;
            if body.len() > MAX_BYTES || !body.ends_with('\n') {
                return Err("invalid bounded attention response".into());
            }
            serde_json::from_str::<Result<Page, String>>(&body).map_err(|e| e.to_string())??
        };
        let selection = Recipient::selection_key(room, page.instance, session, opening);
        if page.opening != opening
            || page.rows.len() > PAGE_SIZE
            || after.is_some_and(|c| {
                c.instance != page.instance
                    || c.recipient != selection
                    || c.revision != page.revision
            })
            || page.next.is_some_and(|c| {
                c.instance != page.instance
                    || c.recipient != selection
                    || c.revision != page.revision
                    || c.after <= after.map_or(0, |a| a.after)
            })
        {
            return Err("attention selection changed; refresh and retry".into());
        }
        check(at, actor, room, instance).await?;
        Ok(page)
    })
    .await
    .map_err(|_| "attention query did not finish in time".to_owned())?
}
