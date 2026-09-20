//! Sealed control messages over a `pairwise` stream (ADR-016 §"Connections": the
//! stream kind that carries "SKDM and other sealed control messages").
//!
//! The only content today is the ADR-006 **sender-key distribution message**, the
//! thing that turns an admitted, consenting member into a *readable* one. It never
//! travels in the clear: the SKDM is sealed into the peer's ADR-004 pairwise session
//! (`Skdm::seal_into`), so the ratchet — not this module — provides
//! confidentiality, authenticity and forward secrecy. This module is the framing
//! and the ordering:
//!
//! | direction | frame |
//! |---|---|
//! | either | `SKDM` — the `channelID` plus one ratchet [`Message`] whose plaintext is an SKDM |
//!
//! The channelID travels **outside** the sealed message because the recipient needs
//! it to pick the session that decrypts it: an ADR-004 session is bound to a
//! `(channelID, epoch)`, a connection is per *peer*, and one peer may share several
//! channels with us. It is not a secret (it is on the board and in the invite link),
//! and the frame is inside the authenticated QUIC stream regardless.
//!
//! Both sides may send; a stream carries one frame per SKDM and the sender
//! half-closes when done, so delivering a key needs no round trip and cannot block
//! on the peer.
//!
//! ## Why the session, not the stream, is the trust boundary
//! A `pairwise` stream is only opened on a connection whose peer identity the
//! ADR-011 handshake proved, and [`crate::node::net::PeerPolicy`] admits the kind
//! only for a member. But neither fact is what makes an SKDM trustworthy: the SKDM
//! is root-signed by its author and verified against the author's admitted key by
//! [`crate::node::channel::ChannelState::accept_skdm`], and it arrives inside a
//! session bound to that identity's PQXDH handshake. A hostile relay can drop or
//! reorder these frames; it cannot forge, read or replay one into a different
//! channel or epoch.

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::skdm::Skdm;
use crate::pairwise::message::Message;
use crate::pairwise::session::Session;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

/// The largest pairwise frame either side will read. An SKDM is a chain key plus a
/// composite signature and a signing key (~3.5 KiB); the ratchet header and AEAD
/// tag add little. 64 KiB leaves room for the later control messages this stream
/// kind is reserved for without being an allocation lever.
pub const MAX_PAIRWISE_FRAME: usize = 64 * 1024;

const OP_SKDM: u64 = 1;

/// One frame on a `pairwise` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairwiseFrame {
    /// A sealed sender-key distribution message: the wire bytes of one ratchet
    /// [`Message`] whose plaintext is an [`Skdm`].
    Skdm {
        /// The channel whose session seals this message.
        channel_id: crate::hash::Digest32,
        /// `Message::to_wire` bytes.
        sealed: Vec<u8>,
    },
}

impl PairwiseFrame {
    /// Canonical frame bytes: `[1, sealed]`.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Skdm { channel_id, sealed } => {
                e.array(3).uint(OP_SKDM).bytes(channel_id).bytes(sealed);
            }
        }
        e.finish()
    }

    /// Parse a pairwise frame.
    pub fn from_frame(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?;
        let op = d.uint()?;
        let frame = match (op, n) {
            (OP_SKDM, 3) => Self::Skdm {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise channel_id length"))?,
                sealed: d.bytes()?.to_vec(),
            },
            _ => return Err(Error::MalformedBundle("pairwise frame op")),
        };
        d.finish()?;
        Ok(frame)
    }
}

/// Seal `skdm` into `session` and write it as one frame for `channel_id`.
pub async fn send_skdm(
    send: &mut SendStream,
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    skdm: &Skdm,
) -> Result<()> {
    let sealed = skdm.seal_into(session)?.to_wire();
    let frame = PairwiseFrame::Skdm {
        channel_id: *channel_id,
        sealed,
    };
    write_frame(send, &frame.to_frame()).await
}

/// Open a `pairwise` stream on `conn`, deliver one SKDM, and half-close. The
/// stream's lifetime is the delivery: nothing is expected back.
pub async fn deliver_skdm(
    conn: &VoxConnection,
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    skdm: &Skdm,
) -> Result<()> {
    let (mut send, _recv) = open_typed(conn, StreamKind::Pairwise).await?;
    send_skdm(&mut send, channel_id, session, skdm).await?;
    let _ = send.finish();
    Ok(())
}

/// Read the next frame from an already-accepted, already-authorized `pairwise`
/// stream, returning which channel it is for and the still-sealed bytes.
///
/// Opening it needs the session for `(channel, peer)`, which only the actor knows,
/// so the two steps are separate: this reads, [`open_skdm`] decrypts. `Ok(None)` on
/// a clean half-close with no further frames.
pub async fn recv_pairwise(
    recv: &mut RecvStream,
) -> Result<Option<(crate::hash::Digest32, Vec<u8>)>> {
    let Some(bytes) = read_frame(recv, MAX_PAIRWISE_FRAME).await? else {
        return Ok(None);
    };
    let PairwiseFrame::Skdm { channel_id, sealed } = PairwiseFrame::from_frame(&bytes)?;
    Ok(Some((channel_id, sealed)))
}

/// Open sealed bytes from [`recv_pairwise`] into an SKDM (still unverified — the
/// channel verifies it against the author's admitted key).
pub fn open_skdm(session: &mut Session, sealed: &[u8], now_secs: u64) -> Result<Skdm> {
    let message = Message::from_wire(sealed)?;
    Skdm::open_from(session, &message, now_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::state::{ReceiverChain, SenderChain};
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::identity::keyagreement::X25519IdentityKey;
    use crate::nat::multiaddr::{EndpointList, Multiaddr};
    use crate::node::net::{accept_authorized, ConnectionManager, PeerPolicy};
    use crate::node::prekeys::{OneTimeUse, PrekeyRing};
    use crate::node::store::Store;
    use crate::pairwise::{OtpReuseTracker, ResponderPrekeys};
    use crate::suite::SuiteFloor;
    use crate::transport::quic::{Admission, VoxEndpoint};
    use crate::transport::streams::StreamKind;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(15);
    const T0: u64 = 1_700_000_000;
    const CHANNEL: crate::hash::Digest32 = [0xD4; 32];
    const EPOCH: u64 = 1;

    #[test]
    fn pairwise_frames_round_trip_and_refuse_malformed() {
        let f = PairwiseFrame::Skdm {
            channel_id: [0xA1; 32],
            sealed: vec![1, 2, 3, 4],
        };
        assert_eq!(PairwiseFrame::from_frame(&f.to_frame()).unwrap(), f);
        // Unknown op and wrong arity are refused.
        let mut e = Encoder::new();
        e.array(3).uint(9).bytes(&[]).bytes(&[]);
        assert!(matches!(
            PairwiseFrame::from_frame(&e.finish()),
            Err(Error::MalformedBundle("pairwise frame op"))
        ));
        let mut e = Encoder::new();
        e.array(2).uint(OP_SKDM).bytes(&[]);
        assert!(PairwiseFrame::from_frame(&e.finish()).is_err());
        assert!(PairwiseFrame::from_frame(&[]).is_err());
    }
    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn manager(s: &SoftwareRootSigner) -> Arc<ConnectionManager> {
        let ep = Arc::new(VoxEndpoint::bind(s, "127.0.0.1:0".parse().unwrap()).unwrap());
        Arc::new(ConnectionManager::new(ep, Arc::new(|| T0)))
    }

    fn endpoints_for(addr: SocketAddr) -> EndpointList {
        let SocketAddr::V4(v4) = addr else {
            unreachable!("loopback is v4")
        };
        EndpointList::new(vec![Multiaddr::Ip4(v4)]).unwrap()
    }

    /// A sender key crosses the network sealed in a pairwise session, and the
    /// receiving side can then decrypt that author's broadcasts.
    #[test]
    fn an_skdm_crosses_a_pairwise_stream_and_unlocks_the_authors_messages() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        rt.block_on(async move {
            let alice_s = signer(1, 2);
            let bob_s = signer(3, 4);
            let alice = manager(&alice_s);
            let bob = manager(&bob_s);
            let alice_id = alice.local_id();
            let alice_eps = endpoints_for(alice.endpoint().local_addr().unwrap());
            let alice_fp = alice_s.fingerprint();

            // Alice is the PQXDH responder: her ring supplies the bundle Bob uses.
            let store = Store::open(&tmp.path().join("alice.redb")).unwrap();
            let mut ring = PrekeyRing::generate(&alice_s, &[0x5C; 32], T0).unwrap();
            let bundle = ring.bundle(&alice_s.public_key()).unwrap();

            // Bob initiates a session against that bundle; Alice accepts it.
            let bob_ik = X25519IdentityKey::generate().unwrap();
            let (init, mut bob_session) = crate::pairwise::session::Session::initiate(
                &bob_ik,
                &bundle,
                &CHANNEL,
                EPOCH,
                crate::suite::VOX_SUITE_1.id,
                SuiteFloor::DAY_ONE,
            )
            .unwrap();
            let mut reuse = OtpReuseTracker::new();
            if let Some(id) = init.one_time_prekey_id {
                assert_eq!(ring.use_one_time(id, T0), OneTimeUse::Fresh);
                crate::node::prekeys::save(&store, &alice_s, &ring).unwrap();
            }
            let mut alice_session = {
                let prekeys = ResponderPrekeys {
                    identity_dh_key: ring.identity_dh(),
                    signed_prekey: ring.signed_prekey_for(init.signed_prekey_id).unwrap(),
                    one_time_prekey: init
                        .one_time_prekey_id
                        .and_then(|id| ring.consumed_one_time(id)),
                };
                crate::pairwise::session::Session::accept(
                    &init,
                    &prekeys,
                    &CHANNEL,
                    EPOCH,
                    &mut reuse,
                    SuiteFloor::DAY_ONE,
                )
                .unwrap()
            };

            // Alice's sender chain and the SKDM releasing it at her current position.
            let mut chain = SenderChain::new(&CHANNEL, EPOCH, &alice_fp, 0, T0).unwrap();
            let (iteration, key) = chain.current_position();
            let skdm = chain.skdm_for(&alice_s, iteration, key).unwrap();

            // Bob is a member, so the policy admits a pairwise stream from him.
            let mut policy = PeerPolicy::new();
            policy.add_members([bob.local_id()]);

            let server = {
                let alice = Arc::clone(&alice);
                tokio::spawn(async move {
                    let conn = alice
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let (kind, _send, mut recv) = accept_authorized(&conn, &policy).await.unwrap();
                    assert_eq!(kind, StreamKind::Pairwise);
                    let got = match recv_pairwise(&mut recv).await {
                        Ok(Some((cid, sealed))) => {
                            assert_eq!(cid, CHANNEL, "the frame names its channel");
                            open_skdm(&mut alice_session, &sealed, T0).map(Some)
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    };
                    (got, conn)
                })
            };

            // Alice would normally deliver to Bob; here Bob dials and delivers his
            // side's stream, so the SKDM travels Bob → Alice sealed in the session.
            let conn = tokio::time::timeout(TIMEOUT, bob.connect(alice_id, &alice_eps))
                .await
                .unwrap()
                .unwrap();
            deliver_skdm(&conn, &CHANNEL, &mut bob_session, &skdm)
                .await
                .unwrap();

            let (got, _conn) = tokio::time::timeout(TIMEOUT, server)
                .await
                .unwrap()
                .unwrap();
            let received = got.unwrap().expect("an SKDM frame");
            assert_eq!(received.to_wire(), skdm.to_wire(), "unchanged in transit");

            // The received key really is the author's: it decrypts her broadcasts.
            let mut receiver =
                ReceiverChain::from_skdm(&received, &alice_s.public_key(), &CHANNEL, EPOCH)
                    .unwrap();
            let msg = chain.encrypt(b"over the wire").unwrap();
            assert_eq!(receiver.decrypt(&msg).unwrap(), b"over the wire");
            // And it is bound to this channel/epoch: another channel's SKDM is not
            // interchangeable.
            assert!(
                ReceiverChain::from_skdm(&received, &alice_s.public_key(), &[0xEE; 32], EPOCH)
                    .is_err()
            );

            alice.close_all();
            bob.close_all();
        });
    }
}
