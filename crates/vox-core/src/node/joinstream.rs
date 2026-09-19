//! The ADR-005 authenticated join over a typed QUIC stream (ADR-016 §"Join over
//! the network").
//!
//! The join *cryptography* is `crate::join` and is used here **unchanged**: this
//! module is only the wire exchange ADR-016 specifies, in order, on one bi-stream
//! typed [`StreamKind::Join`] with the [`crate::transport::framing`] length prefix:
//!
//! | # | direction | frame | drives |
//! |---|---|---|---|
//! | 1 | responder → joiner | `CHALLENGE` — signed [`ResponderNonce`], the `sid`, the responder's composite key and its prekey bundle | — |
//! | 2 | joiner → responder | `SOLVE` — [`PowToken`] + CPace share | [`join_initiate`] |
//! | 3 | responder → joiner | `SHARE` — CPace share | [`join_accept`] (PoW verified **before** any CPace work) |
//! | 4 | joiner → responder | `PROOF` — sealed identity PoP | [`JoinInitiator::complete_cpace`] |
//! | 5 | responder → joiner | `PROOF` — sealed identity PoP | [`JoinResponder::complete_cpace`], [`JoinProofPending::verify_peer_sealed`] |
//! | 6 | joiner → responder | `INIT` — PQXDH [`InitialMessage`] | [`JoinInitiatorBootstrap::bootstrap`] |
//! | 7 | responder → joiner | `ACCEPTED` / `REJECTED` | [`JoinResponderBootstrap::bootstrap`] |
//!
//! ## The transport identities are the join's expected identities
//! Both ends take the peer fingerprint they verify the PoP against from the
//! **authenticated QUIC connection**: the responder uses
//! [`VoxConnection::peer_id`], and the joiner requires the challenge's composite
//! key to hash to the peer it pinned when it dialled. So the identity the ADR-005
//! PoP binds is the identity the ADR-011 handshake proved — a third party cannot
//! relay someone else's join, and the two layers cannot disagree about who is on
//! the other end.
//!
//! ## What a rejection may say
//! [`JoinReject`] is deliberately coarse. `PowInvalid` and `Malformed` are
//! structural and useful (the joiner should re-solve or give up); everything after
//! them collapses to a single `Refused`.
//!
//! The **joiner proves first** (frame 4 before frame 5): the party seeking entry
//! commits its identity proof before the member reveals its own. A consequence is
//! that with a wrong passphrase the *responder* is the first to detect it — the
//! sealed PoP will not open under its differing CPace key — so the joiner learns of
//! the failure from `REJECTED` rather than locally. That is why the reason is one
//! opaque value: it says "this attempt failed", which the joiner would learn from
//! the absence of a session anyway, and never distinguishes a wrong passphrase from
//! an identity mismatch or a policy refusal. Reversing the order would let the
//! joiner fail locally, at the cost of making the member prove itself to an
//! unauthenticated peer first; the defensive order is kept.
//!
//! ## One-shot one-time prekeys are made durable here
//! Before completing the handshake the responder consumes the targeted one-time
//! prekey and **persists the ring immediately** (`prekeys::save`), so a crash
//! between accepting and saving cannot re-offer it. A concurrent duplicate use is
//! served from the ring's retained set and the session is flagged
//! `is_last_resort_grade` — the reconciliation ADR-004 requires between the ring's
//! persistent record and the per-process [`OtpReuseTracker`]: the tracker is seeded
//! from the ring's verdict, so a restart cannot silently lose the downgrade.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::keyagreement::{PrekeyBundlePublic, X25519IdentityKey};
use crate::join::cpace::{fresh_sid, CPACE_SHARE_LEN};
use crate::join::pop::JoinPeerIdentity;
use crate::join::pow::{Difficulty, PowToken, ResponderNonce};
use crate::join::session::{join_accept, join_initiate, JoinContext};
use crate::node::prekeys::{self, OneTimeUse, PrekeyRing};
use crate::node::store::Store;
use crate::pairwise::session::Session;
use crate::pairwise::{InitialMessage, OtpReuseTracker, ResponderPrekeys};
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

use quinn::{RecvStream, SendStream};

/// The largest join frame either side will read. The biggest is `CHALLENGE`
/// (a prekey bundle is ~15 KiB, measured 2026-09-20); an Equihash (200,9) solution
/// is ~1.4 KiB and a sealed PoP ~3.5 KiB.
pub const MAX_JOIN_FRAME: usize = 64 * 1024;

/// Bound on the `sid` a peer may propose (the local one is 16 bytes).
const MAX_SID: usize = 64;

const OP_CHALLENGE: u64 = 1;
const OP_SOLVE: u64 = 2;
const OP_SHARE: u64 = 3;
const OP_PROOF: u64 = 4;
const OP_INIT: u64 = 5;
const OP_ACCEPTED: u64 = 6;
const OP_REJECTED: u64 = 7;

/// Why a responder refused a join (see the module docs: deliberately coarse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum JoinReject {
    /// The proof-of-work token did not verify against the issued challenge.
    PowInvalid = 1,
    /// A frame was structurally malformed, out of order, or over-long.
    Malformed = 2,
    /// Refused after the work gate: wrong passphrase, identity mismatch, an
    /// unresolvable prekey, or a policy refusal. One value, so it is no oracle.
    Refused = 3,
}

impl JoinReject {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PowInvalid),
            2 => Some(Self::Malformed),
            3 => Some(Self::Refused),
            _ => None,
        }
    }

    /// The reason as the static string [`Error::JoinRefused`] carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PowInvalid => "responder refused: proof-of-work invalid",
            Self::Malformed => "responder refused: malformed frame",
            Self::Refused => "responder refused",
        }
    }
}

/// One frame of the join exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinFrame {
    /// The responder's signed challenge, run `sid`, identity key and bundle.
    Challenge {
        /// The responder's composite public key (must hash to the dialled peer).
        responder_pub: Box<[u8; COMPOSITE_PUB_LEN]>,
        /// The responder's signature over the challenge.
        challenge_sig: Box<[u8; COMPOSITE_SIG_LEN]>,
        /// The channel this challenge binds.
        channel_id: Digest32,
        /// The epoch it binds.
        epoch: u64,
        /// Difficulty in leading zero bits.
        difficulty_bits: u8,
        /// The challenge nonce.
        nonce: Digest32,
        /// The CPace run identifier both sides use.
        sid: Vec<u8>,
        /// The responder's current prekey bundle (canonical bytes).
        bundle: Vec<u8>,
    },
    /// The joiner's PoW solution and CPace share.
    Solve {
        /// Equihash nonce.
        equihash_nonce: Vec<u8>,
        /// Equihash solution.
        solution: Vec<u8>,
        /// The joiner's CPace share.
        share: [u8; CPACE_SHARE_LEN],
    },
    /// The responder's CPace share.
    Share {
        /// The share.
        share: [u8; CPACE_SHARE_LEN],
    },
    /// A sealed identity proof-of-possession.
    Proof {
        /// The sealed proof.
        sealed: Vec<u8>,
    },
    /// The joiner's PQXDH initial message (framed bytes).
    Init {
        /// `InitialMessage::to_wire` bytes.
        message: Vec<u8>,
    },
    /// The join succeeded.
    Accepted,
    /// The join was refused.
    Rejected(JoinReject),
}

impl JoinFrame {
    /// Canonical frame bytes.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Challenge {
                responder_pub,
                challenge_sig,
                channel_id,
                epoch,
                difficulty_bits,
                nonce,
                sid,
                bundle,
            } => {
                e.array(9)
                    .uint(OP_CHALLENGE)
                    .bytes(responder_pub.as_ref())
                    .bytes(challenge_sig.as_ref())
                    .bytes(channel_id)
                    .uint(*epoch)
                    .uint(u64::from(*difficulty_bits))
                    .bytes(nonce)
                    .bytes(sid)
                    .bytes(bundle);
            }
            Self::Solve {
                equihash_nonce,
                solution,
                share,
            } => {
                e.array(4)
                    .uint(OP_SOLVE)
                    .bytes(equihash_nonce)
                    .bytes(solution)
                    .bytes(share);
            }
            Self::Share { share } => {
                e.array(2).uint(OP_SHARE).bytes(share);
            }
            Self::Proof { sealed } => {
                e.array(2).uint(OP_PROOF).bytes(sealed);
            }
            Self::Init { message } => {
                e.array(2).uint(OP_INIT).bytes(message);
            }
            Self::Accepted => {
                e.array(1).uint(OP_ACCEPTED);
            }
            Self::Rejected(r) => {
                e.array(2).uint(OP_REJECTED).uint(u64::from(*r as u8));
            }
        }
        e.finish()
    }

    /// Parse a join frame.
    pub fn from_frame(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?;
        let op = d.uint()?;
        let frame = match (op, n) {
            (OP_CHALLENGE, 9) => {
                let responder_pub = take_fixed::<COMPOSITE_PUB_LEN>(&mut d, "challenge key")?;
                let challenge_sig = take_fixed::<COMPOSITE_SIG_LEN>(&mut d, "challenge sig")?;
                let channel_id = take_fixed::<32>(&mut d, "challenge channel_id")?;
                let epoch = d.uint()?;
                let difficulty_bits = u8::try_from(d.uint()?)
                    .map_err(|_| Error::MalformedJoin("challenge difficulty range"))?;
                let nonce = take_fixed::<32>(&mut d, "challenge nonce")?;
                let sid = d.bytes()?.to_vec();
                if sid.is_empty() || sid.len() > MAX_SID {
                    return Err(Error::MalformedJoin("challenge sid length"));
                }
                let bundle = d.bytes()?.to_vec();
                Self::Challenge {
                    responder_pub: Box::new(*responder_pub),
                    challenge_sig: Box::new(*challenge_sig),
                    channel_id: *channel_id,
                    epoch,
                    difficulty_bits,
                    nonce: *nonce,
                    sid,
                    bundle,
                }
            }
            (OP_SOLVE, 4) => Self::Solve {
                equihash_nonce: d.bytes()?.to_vec(),
                solution: d.bytes()?.to_vec(),
                share: *take_fixed::<CPACE_SHARE_LEN>(&mut d, "solve share")?,
            },
            (OP_SHARE, 2) => Self::Share {
                share: *take_fixed::<CPACE_SHARE_LEN>(&mut d, "share length")?,
            },
            (OP_PROOF, 2) => Self::Proof {
                sealed: d.bytes()?.to_vec(),
            },
            (OP_INIT, 2) => Self::Init {
                message: d.bytes()?.to_vec(),
            },
            (OP_ACCEPTED, 1) => Self::Accepted,
            (OP_REJECTED, 2) => {
                let v = u8::try_from(d.uint()?)
                    .map_err(|_| Error::MalformedJoin("reject reason range"))?;
                Self::Rejected(JoinReject::from_u8(v).ok_or(Error::MalformedJoin("reject reason"))?)
            }
            _ => return Err(Error::MalformedJoin("join frame op")),
        };
        d.finish()?;
        Ok(frame)
    }
}

fn take_fixed<const N: usize>(d: &mut Decoder<'_>, ctx: &'static str) -> Result<Box<[u8; N]>> {
    let b: [u8; N] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedJoin(ctx))?;
    Ok(Box::new(b))
}

async fn send_frame(send: &mut SendStream, frame: &JoinFrame) -> Result<()> {
    write_frame(send, &frame.to_frame()).await
}

async fn recv_frame(recv: &mut RecvStream) -> Result<JoinFrame> {
    let bytes = read_frame(recv, MAX_JOIN_FRAME)
        .await?
        .ok_or(Error::MalformedJoin("join stream closed early"))?;
    JoinFrame::from_frame(&bytes)
}

/// A completed join: the pairwise session, the peer identity the PoP proved, and
/// whether the session is last-resort-grade (ADR-004 one-time-prekey reuse).
pub struct JoinOutcome {
    /// The established ADR-004 pairwise session.
    pub session: Session,
    /// The peer identity the ADR-005 proof-of-possession bound.
    pub peer: JoinPeerIdentity,
    /// `true` when the one-time prekey had already been consumed (the session's
    /// forward-secrecy bonus is downgraded, never its confidentiality).
    pub last_resort_grade: bool,
}

impl std::fmt::Debug for JoinOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinOutcome")
            .field("peer", &crate::hash::Hex(&self.peer.fingerprint))
            .field("last_resort_grade", &self.last_resort_grade)
            .finish_non_exhaustive()
    }
}

/// Run the **joiner** side over `conn` (which must already be authenticated as the
/// responder the joiner pinned). Opens the `join` stream itself.
///
/// `ctx` binds channelID, epoch, suite and the ADR-003 floor; `passphrase` is the
/// channel passphrase collected out of band (never from the link, ADR-016).
pub async fn run_initiator(
    conn: &VoxConnection,
    ctx: JoinContext,
    passphrase: &[u8],
    root: &(dyn RootSigner + Send + Sync),
    ik: &X25519IdentityKey,
) -> Result<JoinOutcome> {
    let responder_fp = conn.peer_id();
    let (mut send, mut recv) = open_typed(conn, StreamKind::Join).await?;

    // 1. CHALLENGE. The responder's key must be the identity the QUIC handshake
    //    already proved, and its bundle must be its own.
    let JoinFrame::Challenge {
        responder_pub,
        challenge_sig,
        channel_id,
        epoch,
        difficulty_bits,
        nonce,
        sid,
        bundle,
    } = recv_frame(&mut recv).await?
    else {
        return Err(Error::MalformedJoin("expected challenge"));
    };
    let responder_pub = CompositePublicKey::from_bytes(&responder_pub)?;
    if responder_pub.fingerprint() != responder_fp {
        return Err(Error::MalformedJoin(
            "challenge key is not the dialled peer",
        ));
    }
    if channel_id != ctx.channel_id || epoch != ctx.epoch {
        return Err(Error::MalformedJoin(
            "challenge binds another channel/epoch",
        ));
    }
    let bundle = PrekeyBundlePublic::decode_canonical(&bundle)?;
    if bundle.root_pub != responder_pub.to_bytes() {
        return Err(Error::MalformedJoin(
            "challenge bundle is not the responder's",
        ));
    }
    let challenge = ResponderNonce {
        channel_id,
        epoch,
        difficulty: Difficulty::bits(difficulty_bits),
        nonce,
    };
    let challenge_sig = CompositeSignature::from_bytes(&challenge_sig)?;

    // 2. SOLVE — `join_initiate` verifies the signature, the binding and the
    //    difficulty cap before grinding, then solves and starts CPace.
    let (initiator, token, share) = join_initiate(
        ctx,
        passphrase,
        &sid,
        &challenge,
        &responder_pub,
        &challenge_sig,
        root,
        ik,
    )?;
    send_frame(
        &mut send,
        &JoinFrame::Solve {
            equihash_nonce: token.equihash_nonce.clone(),
            solution: token.solution.clone(),
            share,
        },
    )
    .await?;

    // 3. SHARE.
    let peer_share = match recv_frame(&mut recv).await? {
        JoinFrame::Share { share } => share,
        JoinFrame::Rejected(r) => return Err(Error::JoinRefused(r.as_str())),
        _ => return Err(Error::MalformedJoin("expected share")),
    };
    let (pending, bootstrap) = initiator.complete_cpace(&peer_share)?;

    // 4/5. PROOF both ways. A wrong passphrase fails here, locally.
    send_frame(
        &mut send,
        &JoinFrame::Proof {
            sealed: pending.own_proof_sealed()?,
        },
    )
    .await?;
    let sealed_peer = match recv_frame(&mut recv).await? {
        JoinFrame::Proof { sealed } => sealed,
        JoinFrame::Rejected(r) => return Err(Error::JoinRefused(r.as_str())),
        _ => return Err(Error::MalformedJoin("expected proof")),
    };
    let peer = pending.verify_peer_sealed(&sealed_peer, &responder_fp)?;

    // 6. INIT — PQXDH against the responder's verified bundle.
    let (session, init_msg) = bootstrap.bootstrap(&bundle)?;
    send_frame(
        &mut send,
        &JoinFrame::Init {
            message: init_msg.to_wire(),
        },
    )
    .await?;

    // 7. ACCEPTED.
    match recv_frame(&mut recv).await? {
        JoinFrame::Accepted => {}
        JoinFrame::Rejected(r) => return Err(Error::JoinRefused(r.as_str())),
        _ => return Err(Error::MalformedJoin("expected accepted")),
    }
    let _ = send.finish();
    Ok(JoinOutcome {
        session,
        peer,
        last_resort_grade: false,
    })
}

/// The responder's side inputs that are not on the wire.
pub struct ResponderConfig<'a> {
    /// The channel/epoch/suite/floor binding (must match the joiner's).
    pub ctx: JoinContext,
    /// The channel passphrase.
    pub passphrase: &'a [u8],
    /// The responder's identity signer. `Send + Sync` because the node serves each
    /// connection on its own spawned task.
    pub root: &'a (dyn RootSigner + Send + Sync),
    /// Base difficulty before load adaptation (ADR-005 invite/open default).
    pub base_difficulty: Difficulty,
    /// Joins currently in flight, for `Difficulty::adapted_for_load`.
    pub pending_joins: u32,
    /// Wall clock (for the prekey-ring consume record).
    pub now_secs: u64,
}

/// Run the **responder** side on an already-accepted, already-authorized `join`
/// stream (the manager authorized the kind; `peer_fp` is the connection's
/// authenticated identity).
///
/// The ring is borrowed mutably and **persisted here** the moment a one-time prekey
/// is consumed, so the one-shot rule survives a crash (see the module docs).
pub async fn run_responder(
    mut send: SendStream,
    mut recv: RecvStream,
    peer_fp: Digest32,
    cfg: &ResponderConfig<'_>,
    store: &Store,
    ring: &mut PrekeyRing,
) -> Result<JoinOutcome> {
    let result = responder_exchange(&mut send, &mut recv, peer_fp, cfg, store, ring).await;
    match &result {
        Ok(_) => {
            send_frame(&mut send, &JoinFrame::Accepted).await?;
            let _ = send.finish();
        }
        Err(e) => {
            // Coarse by design (see the module docs).
            let reason = match e {
                Error::JoinPowInvalid => JoinReject::PowInvalid,
                Error::MalformedJoin(_) | Error::Cbor(_) => JoinReject::Malformed,
                _ => JoinReject::Refused,
            };
            let _ = send_frame(&mut send, &JoinFrame::Rejected(reason)).await;
            let _ = send.finish();
        }
    }
    result
}

async fn responder_exchange(
    send: &mut SendStream,
    recv: &mut RecvStream,
    peer_fp: Digest32,
    cfg: &ResponderConfig<'_>,
    store: &Store,
    ring: &mut PrekeyRing,
) -> Result<JoinOutcome> {
    // 1. CHALLENGE — difficulty adapts to the responder's live join load and is
    //    capped by `adapted_for_load` at `Difficulty::MAX`.
    let difficulty = cfg.base_difficulty.adapted_for_load(cfg.pending_joins);
    let challenge = ResponderNonce::generate(&cfg.ctx.channel_id, cfg.ctx.epoch, difficulty)?;
    let challenge_sig = challenge.sign(cfg.root)?;
    let sid = fresh_sid()?;
    let root_pub = cfg.root.public_key();
    let bundle = ring.bundle(&root_pub)?;
    send_frame(
        send,
        &JoinFrame::Challenge {
            responder_pub: Box::new(root_pub.to_bytes()),
            challenge_sig: Box::new(challenge_sig.to_bytes()),
            channel_id: challenge.channel_id,
            epoch: challenge.epoch,
            difficulty_bits: challenge.difficulty.leading_zero_bits,
            nonce: challenge.nonce,
            sid: sid.to_vec(),
            bundle: bundle.encode_canonical(),
        },
    )
    .await?;

    // 2. SOLVE — `join_accept` verifies the PoW before any CPace work.
    let JoinFrame::Solve {
        equihash_nonce,
        solution,
        share: joiner_share,
    } = recv_frame(recv).await?
    else {
        return Err(Error::MalformedJoin("expected solve"));
    };
    let token = PowToken {
        equihash_nonce,
        solution,
    };
    let (responder, own_share) =
        join_accept(cfg.ctx, cfg.passphrase, &sid, &challenge, &token, cfg.root)?;

    // 3. SHARE, then CPace completes and this side's proof is built.
    send_frame(send, &JoinFrame::Share { share: own_share }).await?;
    let (pending, bootstrap) = responder.complete_cpace(&joiner_share)?;

    // 4/5. PROOF: verify the joiner against the identity the transport proved.
    let JoinFrame::Proof { sealed } = recv_frame(recv).await? else {
        return Err(Error::MalformedJoin("expected proof"));
    };
    let peer = pending.verify_peer_sealed(&sealed, &peer_fp)?;
    send_frame(
        send,
        &JoinFrame::Proof {
            sealed: pending.own_proof_sealed()?,
        },
    )
    .await?;

    // 6. INIT — resolve our own prekeys for the message, consuming the one-time
    //    prekey durably before the session is completed.
    let JoinFrame::Init { message } = recv_frame(recv).await? else {
        return Err(Error::MalformedJoin("expected init"));
    };
    let init = InitialMessage::from_wire(&message)?;
    let mut reuse = OtpReuseTracker::new();
    let mut last_resort_grade = false;
    if let Some(id) = init.one_time_prekey_id {
        match ring.use_one_time(id, cfg.now_secs) {
            OneTimeUse::Fresh => {}
            OneTimeUse::Reused => {
                // Seed the per-process tracker from the ring's persistent record so
                // `Session::accept` flags the downgrade even after a restart
                // (ADR-004 reconciliation).
                reuse.observe(id);
                last_resort_grade = true;
            }
            OneTimeUse::Unknown => {
                return Err(Error::MalformedJoin(
                    "init names an unknown one-time prekey",
                ))
            }
        }
        // Persist the consume before the handshake completes: a crash here must not
        // leave the prekey re-offerable.
        prekeys::save(store, cfg.root, ring)?;
    }
    let signed_prekey = ring
        .signed_prekey_for(init.signed_prekey_id)
        .ok_or(Error::MalformedJoin("init names an unknown signed prekey"))?;
    let one_time_prekey = init
        .one_time_prekey_id
        .and_then(|id| ring.consumed_one_time(id));
    let prekeys = ResponderPrekeys {
        identity_dh_key: ring.identity_dh(),
        signed_prekey,
        one_time_prekey,
    };
    let session = bootstrap.bootstrap(&init, &prekeys, &mut reuse)?;
    debug_assert_eq!(session.is_last_resort_grade(), last_resort_grade);
    Ok(JoinOutcome {
        session,
        peer,
        last_resort_grade,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::join::pow::PowParams;
    use crate::nat::multiaddr::{EndpointList, Multiaddr};
    use crate::node::net::{accept_authorized, ConnectionManager, PeerPolicy};
    use crate::suite::SuiteFloor;
    use crate::transport::quic::{Admission, VoxEndpoint};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(30);
    const T0: u64 = 1_700_000_000;
    const CHANNEL: Digest32 = [0xC5; 32];
    const EPOCH: u64 = 2;
    const PASS: &[u8] = b"correct horse battery staple";

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    /// Reduced PoW params so the fast tests do not grind (200,9); the ignored
    /// `production_pow` test below runs the real ones.
    fn ctx(pow: PowParams) -> JoinContext {
        JoinContext {
            channel_id: CHANNEL,
            epoch: EPOCH,
            suite_id: crate::suite::VOX_SUITE_1.id,
            floor: SuiteFloor::DAY_ONE,
            pow_params: pow,
        }
    }

    fn small_pow() -> PowParams {
        PowParams::new(48, 5).unwrap()
    }

    fn store(tmp: &tempfile::TempDir, name: &str) -> Store {
        Store::open(&tmp.path().join(name)).unwrap()
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

    #[test]
    fn join_frames_round_trip_and_refuse_malformed() {
        let frames = [
            JoinFrame::Challenge {
                responder_pub: Box::new([7u8; COMPOSITE_PUB_LEN]),
                challenge_sig: Box::new([8u8; COMPOSITE_SIG_LEN]),
                channel_id: CHANNEL,
                epoch: EPOCH,
                difficulty_bits: 2,
                nonce: [9u8; 32],
                sid: vec![1, 2, 3],
                bundle: vec![4, 5, 6],
            },
            JoinFrame::Solve {
                equihash_nonce: vec![1],
                solution: vec![2, 3],
                share: [4u8; CPACE_SHARE_LEN],
            },
            JoinFrame::Share {
                share: [5u8; CPACE_SHARE_LEN],
            },
            JoinFrame::Proof {
                sealed: vec![6; 40],
            },
            JoinFrame::Init {
                message: vec![7; 40],
            },
            JoinFrame::Accepted,
            JoinFrame::Rejected(JoinReject::PowInvalid),
            JoinFrame::Rejected(JoinReject::Malformed),
            JoinFrame::Rejected(JoinReject::Refused),
        ];
        for f in &frames {
            assert_eq!(&JoinFrame::from_frame(&f.to_frame()).unwrap(), f);
        }
        // Unknown op, wrong arity, unknown reject reason, empty/oversized sid.
        let mut e = Encoder::new();
        e.array(2).uint(99).bytes(&[]);
        assert!(matches!(
            JoinFrame::from_frame(&e.finish()),
            Err(Error::MalformedJoin("join frame op"))
        ));
        let mut e = Encoder::new();
        e.array(2).uint(OP_REJECTED).uint(42);
        assert!(matches!(
            JoinFrame::from_frame(&e.finish()),
            Err(Error::MalformedJoin("reject reason"))
        ));
        let mut e = Encoder::new();
        e.array(1).uint(OP_SHARE);
        assert!(JoinFrame::from_frame(&e.finish()).is_err());
        let sid_case = |sid: Vec<u8>| {
            let mut e = Encoder::new();
            e.array(9)
                .uint(OP_CHALLENGE)
                .bytes(&[7u8; COMPOSITE_PUB_LEN])
                .bytes(&[8u8; COMPOSITE_SIG_LEN])
                .bytes(&CHANNEL)
                .uint(EPOCH)
                .uint(2)
                .bytes(&[9u8; 32])
                .bytes(&sid)
                .bytes(&[]);
            JoinFrame::from_frame(&e.finish())
        };
        assert!(matches!(
            sid_case(vec![]),
            Err(Error::MalformedJoin("challenge sid length"))
        ));
        assert!(matches!(
            sid_case(vec![0; MAX_SID + 1]),
            Err(Error::MalformedJoin("challenge sid length"))
        ));
        // A truncated fixed-width field is refused, not silently padded.
        let mut e = Encoder::new();
        e.array(2).uint(OP_SHARE).bytes(&[1u8; 31]);
        assert!(matches!(
            JoinFrame::from_frame(&e.finish()),
            Err(Error::MalformedJoin("share length"))
        ));
    }

    /// Drive a full join over loopback QUIC and return both outcomes.
    #[allow(clippy::type_complexity)]
    fn run_join(
        pow: PowParams,
        joiner_pass: &'static [u8],
        responder_pass: &'static [u8],
    ) -> (Result<JoinOutcome>, Result<JoinOutcome>) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        rt.block_on(async move {
            let responder_s = signer(1, 2);
            let joiner_s = signer(3, 4);
            let responder = manager(&responder_s);
            let joiner = manager(&joiner_s);
            let responder_id = responder.local_id();
            let joiner_id = joiner.local_id();
            let responder_eps = endpoints_for(responder.endpoint().local_addr().unwrap());

            // The responder expects this joiner: the pending-joiner class lets it
            // open the join stream and nothing else.
            let mut policy = PeerPolicy::new();
            policy.expect_joiner(joiner_id);

            let st = store(&tmp, "responder.redb");
            let mut ring = PrekeyRing::generate(&responder_s, T0).unwrap();

            let server = {
                let responder = Arc::clone(&responder);
                let ctx = ctx(pow);
                tokio::spawn(async move {
                    let conn = responder
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let (kind, send, recv) = accept_authorized(&conn, &policy).await.unwrap();
                    assert_eq!(kind, StreamKind::Join);
                    let cfg = ResponderConfig {
                        ctx,
                        passphrase: responder_pass,
                        root: &responder_s,
                        base_difficulty: Difficulty::ZERO,
                        pending_joins: 0,
                        now_secs: T0,
                    };
                    let out = run_responder(send, recv, conn.peer_id(), &cfg, &st, &mut ring).await;
                    (out, conn)
                })
            };

            let conn = tokio::time::timeout(TIMEOUT, joiner.connect(responder_id, &responder_eps))
                .await
                .unwrap()
                .unwrap();
            let ik = X25519IdentityKey::generate().unwrap();
            let joiner_out = tokio::time::timeout(
                TIMEOUT,
                run_initiator(&conn, ctx(pow), joiner_pass, &joiner_s, &ik),
            )
            .await
            .unwrap();
            let (responder_out, _conn) = tokio::time::timeout(TIMEOUT, server)
                .await
                .unwrap()
                .unwrap();
            responder.close_all();
            joiner.close_all();
            (joiner_out, responder_out)
        })
    }

    #[test]
    fn a_full_join_over_loopback_yields_two_agreeing_sessions() {
        let (joiner, responder) = run_join(small_pow(), PASS, PASS);
        let mut joiner = joiner.expect("joiner side");
        let mut responder = responder.expect("responder side");

        // Each side's PoP bound the *other's* identity, and the transport already
        // proved it — so the join cannot be relayed by a third party.
        assert_ne!(joiner.peer.fingerprint, responder.peer.fingerprint);
        assert!(!joiner.last_resort_grade && !responder.last_resort_grade);

        // The two sessions agree: the joiner's first message decrypts, and the
        // responder's reply decrypts back (the ADR-004 ratchet is live).
        let msg = joiner.session.encrypt(b"hello from the joiner").unwrap();
        assert_eq!(
            responder.session.decrypt(&msg, T0).unwrap(),
            b"hello from the joiner"
        );
        let reply = responder.session.encrypt(b"welcome").unwrap();
        assert_eq!(joiner.session.decrypt(&reply, T0).unwrap(), b"welcome");
        assert!(!responder.session.is_last_resort_grade());
    }

    #[test]
    fn a_wrong_passphrase_is_refused_with_one_opaque_reason() {
        let (joiner, responder) = run_join(small_pow(), b"wrong passphrase", PASS);
        // The joiner proves first, so the responder detects the mismatch (the sealed
        // PoP will not open under its differing CPace key) and answers with the
        // single opaque refusal — never a "bad passphrase" code that would confirm
        // a guess, and the same value a policy refusal produces.
        assert!(matches!(
            joiner,
            Err(Error::JoinRefused("responder refused"))
        ));
        // The responder's own error is the PoP failure, and it is never leaked.
        let err = responder.expect_err("a wrong passphrase cannot join");
        assert!(
            !matches!(err, Error::JoinRefused(_)),
            "the responder failed on its own check: {err:?}"
        );
        assert_ne!(
            JoinReject::Refused.as_str(),
            JoinReject::PowInvalid.as_str(),
            "structural reasons stay distinguishable; semantic ones do not"
        );
    }

    #[test]
    #[ignore = "production (200,9) Equihash: ~1.2 s in release, minutes unoptimized; CI runs it in release"]
    fn a_full_join_at_production_pow_parameters() {
        let (joiner, responder) = run_join(PowParams::DEFAULT, PASS, PASS);
        let mut joiner = joiner.expect("joiner side");
        let mut responder = responder.expect("responder side");
        let msg = joiner.session.encrypt(b"real params").unwrap();
        assert_eq!(responder.session.decrypt(&msg, T0).unwrap(), b"real params");
    }
}
