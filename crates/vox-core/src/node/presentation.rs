//! Optional pre-trust node presentation (#796). A nonce binds a signed answer to this lookup;
//! the root key must name the already authenticated connection peer. No room or keyring writes.
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::transport::{
    framing::{read_frame_within, write_frame},
    quic::VoxConnection,
    streams::{open_typed, StreamKind},
};
use crate::{
    cbor::{Decoder, Encoder},
    error::{Error, Result},
    hash::Digest32,
};
use quinn::{RecvStream, SendStream};
use std::time::Duration;
const PATIENCE: Duration = Duration::from_secs(3);
const MAX_FRAME: usize = 8192;
const DOMAIN: &[u8] = b"vox/node-presentation/v1\0";
/// Presentation-safe names retain the existing local alias bounds, but reject all controls.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= crate::node::trust::MAX_PETNAME
        && name.trim() == name
        && name.chars().all(|c| c.is_ascii() && !c.is_control())
}
fn body(nonce: &Digest32, fingerprint: &Digest32, name: &str, revision: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4)
        .bytes(nonce)
        .bytes(fingerprint)
        .text(name)
        .uint(revision);
    e.finish()
}
fn signing(body: &[u8]) -> Vec<u8> {
    [DOMAIN, body].concat()
}
/// Read only a fixed-size nonce, off the actor task.
pub async fn read_ask(recv: &mut RecvStream) -> Result<Digest32> {
    let f = read_frame_within(recv, 64, PATIENCE)
        .await?
        .ok_or(Error::MalformedBundle("presentation: missing nonce"))?;
    let mut d = Decoder::new(&f);
    let n = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("presentation: nonce"))?;
    d.finish()?;
    Ok(n)
}
/// Sign an answer using the normal composite identity policy. Unsupported peers never reach here.
pub fn signed_answer(
    nonce: Digest32,
    name: &str,
    revision: u64,
    signer: &impl RootSigner,
) -> Result<Vec<u8>> {
    if !safe_name(name) {
        return Err(Error::MalformedBundle("presentation: name"));
    }
    let pk = signer.public_key();
    let b = body(&nonce, &pk.fingerprint(), name, revision);
    let sig = signer.sign(&signing(&b))?;
    let mut e = Encoder::new();
    e.array(3)
        .bytes(&b)
        .bytes(&pk.to_bytes())
        .bytes(&sig.to_bytes());
    Ok(e.finish())
}
/// Only public signed bytes leave the actor; no secret survives a node lock.
pub async fn answer(mut send: SendStream, frame: Vec<u8>) {
    let _ = tokio::time::timeout(PATIENCE, write_frame(&mut send, &frame)).await;
    let _ = send.finish();
}
/// Ask on the authenticated connection; any refusal from an older peer means missing metadata.
pub async fn pull(conn: &VoxConnection) -> Result<String> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::MalformedBundle("presentation: randomness"))?;
    let (mut send, mut recv) = open_typed(conn, StreamKind::Presentation).await?;
    let mut e = Encoder::new();
    e.bytes(&nonce);
    write_frame(&mut send, &e.finish()).await?;
    let _ = send.finish();
    let f = read_frame_within(&mut recv, MAX_FRAME, PATIENCE)
        .await?
        .ok_or(Error::MalformedBundle("presentation: missing answer"))?;
    let mut d = Decoder::new(&f);
    if d.array()? != 3 {
        return Err(Error::MalformedBundle("presentation: answer"));
    }
    let b = d.bytes()?;
    let pk = CompositePublicKey::from_bytes(
        d.bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("presentation: key"))?,
    )?;
    let sig = CompositeSignature::from_bytes(
        d.bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("presentation: signature"))?,
    )?;
    d.finish()?;
    if pk.fingerprint() != conn.peer_id() {
        return Err(Error::SignatureInvalid);
    }
    pk.verify(&signing(b), &sig)?;
    let mut d = Decoder::new(b);
    if d.array()? != 4 {
        return Err(Error::MalformedBundle("presentation: body"));
    }
    if d.bytes()? != nonce || d.bytes()? != conn.peer_id() {
        return Err(Error::SignatureInvalid);
    }
    let name = d.text()?.to_owned();
    let _revision = d.uint()?;
    d.finish()?;
    if !safe_name(&name) {
        return Err(Error::MalformedBundle("presentation: name"));
    }
    Ok(name)
}
