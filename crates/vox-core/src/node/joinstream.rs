//! The ADR-005 authenticated join over a typed QUIC stream (ADR-016 §"Join over
//! the network").
//!
//! The join *cryptography* is `crate::join` and is used here **unchanged**: this
//! module is only the wire exchange ADR-016 specifies, in order, on one bi-stream
//! typed [`StreamKind::Join`] with the [`crate::transport::framing`] length prefix:
//!
//! | # | direction | frame | drives |
//! |---|---|---|---|
//! | 0 | joiner → responder | `WANT` — which `(channelID, epoch)` this join is for | — |
//! | 1 | responder → joiner | `CHALLENGE` — signed [`ResponderNonce`], the `sid`, the responder's composite key and its prekey bundle | — |
//! | 2 | joiner → responder | `SOLVE` — [`PowToken`] + CPace share | [`join_check_challenge`], [`join_start`] |
//! | 3 | responder → joiner | `SHARE` — CPace share | [`join_accept`] (PoW verified **before** any CPace work) |
//! | 4 | joiner → responder | `PROOF` — sealed identity PoP | [`JoinInitiator::complete_cpace`](crate::join::session::JoinInitiator::complete_cpace) |
//! | 5 | responder → joiner | `PROOF` — sealed identity PoP | [`JoinResponder::complete_cpace`](crate::join::session::JoinResponder::complete_cpace), [`JoinProofPending::verify_peer_sealed`](crate::join::session::JoinProofPending::verify_peer_sealed) |
//! | 6 | joiner → responder | `INIT` — PQXDH [`InitialMessage`] | [`JoinInitiatorBootstrap::bootstrap`](crate::join::session::JoinInitiatorBootstrap::bootstrap) |
//! | 7 | responder → joiner | `ACCEPTED` / `REJECTED` | [`JoinResponderBootstrap::bootstrap`](crate::join::session::JoinResponderBootstrap::bootstrap) |
//!
//! ## Why the joiner speaks first
//! ADR-016's frame list starts with the responder's challenge, which silently assumes
//! the responder already knows which channel is being joined. It does not: a
//! connection is **per peer**, not per channel (ADR-016 §"Connections"), and a member
//! may hold many channels with the same peer. So the joiner opens with `WANT`, naming
//! the `(channelID, epoch)`; the responder answers a challenge only for a channel it
//! actually holds open and can answer for, and otherwise refuses. The channelID is
//! not a secret — it is on the board and in the invite link — and the frame is inside
//! the authenticated QUIC stream either way.
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
use crate::join::pow::solve_token_until;
use crate::join::pow::{Difficulty, PowToken, ResponderNonce};
use crate::join::session::{join_accept, join_check_challenge, join_start, JoinContext};
use crate::nat::record::JoinWitness;
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

const OP_WANT: u64 = 0;
const OP_CHALLENGE: u64 = 1;
const OP_SOLVE: u64 = 2;
const OP_SHARE: u64 = 3;
const OP_PROOF: u64 = 4;
const OP_INIT: u64 = 5;
const OP_ACCEPTED: u64 = 6;
/// `8` — the joiner's ratchet message that opens the responder's sending direction.
const OP_OPEN: u64 = 8;
const OP_REJECTED: u64 = 7;
const OP_FULL: u64 = 9;
const OP_BUSY: u64 = 10;
const OP_UNANSWERED: u64 = 11;

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
    /// Every one of the responder's join slots was held, so it did not start the exchange
    /// (V210-92). Sent before the challenge, so before anything about the passphrase is known: it
    /// says only that this member is busy, and nothing about the joiner.
    Busy = 4,
    /// The exchange succeeded — the passphrase was accepted — and the responder then could not
    /// admit the joiner (V210-128): locked or closing mid-join, its store refused the write, or a
    /// key conflict. A full room has its own frame, [`JoinFrame::Full`].
    NotAdmitted = 5,
}

impl JoinReject {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PowInvalid),
            2 => Some(Self::Malformed),
            3 => Some(Self::Refused),
            4 => Some(Self::Busy),
            5 => Some(Self::NotAdmitted),
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
            Self::Busy => "responder refused: busy answering other joins",
            Self::NotAdmitted => "responder refused: it could not admit this identity",
        }
    }
}

/// One frame of the join exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinFrame {
    /// The joiner names the channel and epoch it wants to join.
    Want {
        /// The channelID from the invite link.
        channel_id: Digest32,
        /// The epoch it expects (the board's current one).
        epoch: u64,
    },
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
    /// The join succeeded, and the responder's **witness** to it (M17.6).
    ///
    /// The responder is the only party that saw the joiner's ADR-005 proof, so it is
    /// the only one that can honestly attest to it. The joiner keeps this and
    /// publishes it with every bundle record it ever puts on a board: it is the
    /// evidence that turns "here is my key" into "this key joined".
    Accepted {
        /// `JoinWitness::body_bytes` — the witness, signed by the responder.
        witness: Vec<u8>,
    },
    /// The join was refused.
    Rejected(JoinReject),
    /// The join was refused because the room is full: the exchange succeeded, and the responder
    /// could not admit the joiner, as the room already holds `members` (V210, the silent join).
    /// Sent where `Accepted` would have been. Its own frame, not a [`JoinReject`], because it
    /// carries the count.
    Full {
        /// How many members the room holds.
        members: u64,
        /// The room's cap, as the refusing member enforces it.
        cap: u64,
    },
    /// Refused because the room's last place is held for another join (V210-128).
    Busy,
    /// Refused because an online member did not answer in time (V210-128).
    Unanswered {
        /// The member, as a short id.
        member: String,
    },
    /// **Step 8, joiner → responder:** one ratchet message with an empty plaintext,
    /// whose only job is to open the responder's sending direction (M17.6).
    ///
    /// A PQXDH responder begins with no chains — `Ratchet::init_responder`: *"with no
    /// chains yet — they are established when the first inbound message triggers a DH
    /// ratchet step"*. Step 6's `InitialMessage` creates the session but delivers no
    /// ratchet message, so without this the responder cannot send at all and its first
    /// `Consent` fails with "no sending chain".
    ///
    /// Joining used to meet that need by releasing the joiner's **sender key**, which
    /// made a consent decision nobody took, to whichever member answered the join. This
    /// meets it with nothing: an empty plaintext grants no key and no reach.
    ///
    /// It rides the **join stream** rather than a later pairwise stream so the responder
    /// has processed it before the join returns. On a separate stream it was a race, and
    /// a `Consent` issued straight after a join would fail or not depending on timing.
    Open {
        /// `Message::to_wire` bytes of a sealed, empty-plaintext ratchet message.
        sealed: Vec<u8>,
    },
}

impl JoinFrame {
    /// Canonical frame bytes.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Want { channel_id, epoch } => {
                e.array(3).uint(OP_WANT).bytes(channel_id).uint(*epoch);
            }
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
            Self::Accepted { witness } => {
                e.array(2).uint(OP_ACCEPTED).bytes(witness);
            }
            Self::Open { sealed } => {
                e.array(2).uint(OP_OPEN).bytes(sealed);
            }
            Self::Rejected(r) => {
                e.array(2).uint(OP_REJECTED).uint(u64::from(*r as u8));
            }
            Self::Busy => {
                e.array(1).uint(OP_BUSY);
            }
            Self::Unanswered { member } => {
                e.array(2).uint(OP_UNANSWERED).bytes(member.as_bytes());
            }
            Self::Full { members, cap } => {
                e.array(3).uint(OP_FULL).uint(*members).uint(*cap);
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
            (OP_WANT, 3) => Self::Want {
                channel_id: *take_fixed::<32>(&mut d, "want channel_id")?,
                epoch: d.uint()?,
            },
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
            (OP_ACCEPTED, 2) => Self::Accepted {
                witness: d.bytes()?.to_vec(),
            },
            (OP_OPEN, 2) => Self::Open {
                sealed: d.bytes()?.to_vec(),
            },
            (OP_REJECTED, 2) => {
                let v = u8::try_from(d.uint()?)
                    .map_err(|_| Error::MalformedJoin("reject reason range"))?;
                Self::Rejected(JoinReject::from_u8(v).ok_or(Error::MalformedJoin("reject reason"))?)
            }
            (OP_BUSY, 1) => Self::Busy,
            (OP_UNANSWERED, 2) => {
                let raw = d.bytes()?;
                if raw.len() > 64 {
                    return Err(Error::MalformedJoin("unanswered member"));
                }
                Self::Unanswered {
                    member: String::from_utf8_lossy(raw).into_owned(),
                }
            }
            (OP_FULL, 3) => Self::Full {
                members: d.uint()?,
                cap: d.uint()?,
            },
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

/// What a joiner reports for a member's refusal: [`JoinReject::Busy`] — every slot held, or this
/// join ended for one from elsewhere (V210-92) — is the member being busy and says nothing about
/// the joiner; every other reason is the coarse refusal.
fn rejected(r: JoinReject) -> Error {
    match r {
        JoinReject::Busy => Error::JoinResponderBusy,
        JoinReject::NotAdmitted => Error::JoinNotAdmitted,
        r => Error::JoinRefused(r.as_str()),
    }
}

async fn recv_frame(recv: &mut RecvStream) -> Result<JoinFrame> {
    let bytes = read_frame(recv, MAX_JOIN_FRAME)
        .await?
        .ok_or(Error::MalformedJoin("join stream closed early"))?;
    JoinFrame::from_frame(&bytes)
}

/// **How long the rest of a join may take once the joiner's proof of work has verified**
/// (V210-92): the remaining frames are a few signatures, key agreements and round trips each way,
/// well under 2s even on a Raspberry-Pi-class device, so 20s is ten times that and all margin. It
/// is tight on purpose: a hold that has done its work cannot be ended for a newcomer, so this is
/// the only thing that frees its slot, and at the per-frame bound's 30s each it would never fire.
///
/// A hold that has done its work is never the one ended for a newcomer (`node::joinslots`), so
/// how long it may last is what this sets. Each frame is already bounded by
/// [`FRAME_PATIENCE`](crate::transport::framing::FRAME_PATIENCE); this bounds the rest of the
/// exchange **as a whole**, so a stranger that paid sixteen solves cannot then keep every slot by
/// sending each remaining frame just inside the per-frame bound.
pub const ADMISSION_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

/// How long one expected Equihash solve may take on a slow joiner.
///
/// Measured on a developer machine run 2–3.5× over its cores: 0.9–2.0s a nonce, 1–3 nonces at the
/// base difficulty. A Raspberry-Pi-class device is an order slower on this memory-hard (200,9)
/// solve, so this is sized for that rather than for the machine that measured it.
///
/// **Two orders slower, not one (V210-87).** At 30s the patience at the base difficulty was 120s,
/// and a joiner slower than that was turned away every time, told only that no member could be
/// reached: the responder's own report was `peer sent no frame in time`, on the `Solve`. Measured
/// through the real binaries on one busy machine (load 30–110, nine joins at once) with the
/// unoptimized build standing in for a slow device: one join's solve took 22–118s when it got in,
/// and three of nine were refused after grinding 151–194s. That is a device 20–100× slower than the
/// one that measured the release build, which a small board under load is. Waiting longer costs
/// the responder nothing a stranger could not already take: holding a join slot never required
/// solving (see [`solve_patience`]).
const SOLVE_BUDGET_PER_EXPECTED_SOLVE: std::time::Duration = std::time::Duration::from_secs(120);

/// Test-only: make this joiner's grind last at least this many milliseconds, as it does on a
/// slower device. **For proofs; nothing in a real deployment sets it.** A proof cannot otherwise
/// stage a joiner slower than the responder's patience with the release build, whose solve takes a
/// second or two. Unset, empty or unparsable is no floor. Not compiled in without the `test-knobs`
/// feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_SOLVE_AT_LEAST_ENV: &str = "VOX_TEST_SOLVE_AT_LEAST_MS";

/// Test-only: once this joiner has sent its solution, wait this many milliseconds before reading
/// the member's answer — a join that has done its work and then goes quiet, which the member's
/// [`ADMISSION_PATIENCE`] exists for (V210-92). It says so on stderr when it starts waiting, so a
/// proof can tell the work was done. **For proofs; nothing in a real deployment sets it.** Unset,
/// empty or unparsable is no wait. Not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_STALL_AFTER_SOLVE_ENV: &str = "VOX_TEST_STALL_AFTER_SOLVE_MS";

/// Test-only: once this joiner's proof of work is in, wait this many milliseconds before **each**
/// frame it still owes the member (its proof, then its init) — a join that has done its work and
/// then sends every remaining frame just inside the per-frame bound, which only the member's
/// [`ADMISSION_PATIENCE`] limits as a whole (V210-92). It says so on stderr when it starts. **For
/// proofs; nothing in a real deployment sets it.** Unset, empty or unparsable is no wait. Not
/// compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_DRIP_AFTER_SOLVE_ENV: &str = "VOX_TEST_DRIP_AFTER_SOLVE_MS";

/// The test-only wait of `TEST_DRIP_AFTER_SOLVE_ENV`, before one frame the joiner owes.
#[cfg(feature = "test-knobs")]
fn test_drip() -> Option<std::time::Duration> {
    std::env::var(TEST_DRIP_AFTER_SOLVE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
}

/// Without the `test-knobs` feature there is no wait, and nothing reads the environment.
#[cfg(not(feature = "test-knobs"))]
const fn test_drip() -> Option<std::time::Duration> {
    None
}

/// Tells a joiner's grind to give up when the join that started it is dropped — finished, failed,
/// or aborted by a lock (V210-94). See the `SOLVE` step of [`run_initiator`].
struct StopGrind(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for StopGrind {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// How close to the responder's patience a grind may finish and still count as in time. The
/// responder started its clock when it sent the challenge, a one-way trip before this side started
/// its own, so a grind that ended just inside the patience here may have ended just outside it
/// there.
const SOLVE_PATIENCE_SLACK: std::time::Duration = std::time::Duration::from_secs(5);

/// How far past the expected number of solves an honest joiner may run: the nonce search is
/// geometric, and this covers its tail.
const SOLVE_TAIL: u32 = 4;

/// How long the responder waits for the joiner's `Solve`, derived from the difficulty it demanded.
///
/// **Not the general frame bound.** The `Solve` was read with the same 30s as every other frame,
/// while the time to produce it depends on the joiner's hardware and on the difficulty — which
/// adapts upward under load, exactly when the responder is busiest. Measured through the real
/// binaries: 1 join in 16 failed at ~37s with the responder reporting `peer sent no frame in time`
/// while the joiner was still grinding. A stranger gains nothing from the longer wait: holding a
/// join slot never required solving, so the slot cap and refuse-not-queue are the defence against
/// that, as they were at 30s.
fn solve_patience(difficulty: crate::join::pow::Difficulty) -> std::time::Duration {
    // `expected_solves` is ≥ 1 and bounded by the difficulty cap, so this cannot overflow in
    // practice; saturate anyway rather than trust that.
    let solves = difficulty.expected_solves().ceil().min(f64::from(u32::MAX)) as u32;
    SOLVE_BUDGET_PER_EXPECTED_SOLVE
        .saturating_mul(solves.max(1))
        .saturating_mul(SOLVE_TAIL)
}

/// A completed join: the pairwise session, the peer identity the PoP proved, and
/// whether the session is last-resort-grade (ADR-004 one-time-prekey reuse).
pub struct JoinOutcome {
    /// The established ADR-004 pairwise session.
    pub session: Session,
    /// The peer identity the ADR-005 proof-of-possession bound.
    pub peer: JoinPeerIdentity,
    /// The witness to this join (M17.6). On the **joiner** side this is the
    /// responder's attestation, kept and republished with every bundle record. On the
    /// **responder** side it is the one this node just signed.
    pub witness: JoinWitness,
    /// `true` when the one-time prekey had already been consumed (the session's
    /// forward-secrecy bonus is downgraded, never its confidentiality).
    pub last_resort_grade: bool,
    /// How long **this side** spent solving the proof of work: the joiner's own CPU, on its own
    /// machine, and random in length by design (ADR-005). Zero on the responder. Said apart from
    /// the rest of the exchange, so a slow join shows whether it waited on the responder or on
    /// its own grind (V210-62).
    pub solved_in: std::time::Duration,
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

    // 0. WANT — the responder holds many channels; say which one.
    send_frame(
        &mut send,
        &JoinFrame::Want {
            channel_id: ctx.channel_id,
            epoch: ctx.epoch,
        },
    )
    .await?;

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
    } = (match recv_frame(&mut recv).await? {
        // A member whose every join slot was held (V210-92): not a verdict on this joiner, and
        // said as such, not as the refusal a wrong passphrase gets.
        JoinFrame::Rejected(JoinReject::Busy) => return Err(Error::JoinResponderBusy),
        frame => frame,
    })
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

    // 2. SOLVE — the challenge is checked first: the responder's signature, the binding to this
    //    channel and epoch, and the cap, before any work.
    //
    //    **Ground on a thread that holds nothing secret** (V210-94). The solve is Equihash —
    //    seconds of CPU, far more in a debug build — and only the challenge goes into it. It used
    //    to run under `block_in_place` inside this task, with the room passphrase and the identity
    //    signer held across it; no abort reaches a thread busy in `block_in_place`, so a lock
    //    aborting this join waited out the whole grind before it could say it was done, and the
    //    secrets lived that long. Now this task only *awaits* the grind: an abort drops it — and
    //    everything it holds — at once, and the dropped `StopGrind` tells the thread to give up at
    //    its next nonce. The CPace start that needs the passphrase runs after, here, briefly.
    //    (On a current-thread runtime there is no other thread: it grinds inline, as before.)
    join_check_challenge(&ctx, &challenge, &responder_pub, &challenge_sig)?;
    let grinding = std::time::Instant::now();
    #[cfg(feature = "test-knobs")]
    let floor = std::env::var(TEST_SOLVE_AT_LEAST_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(std::time::Duration::ZERO, std::time::Duration::from_millis);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _stop_on_drop = StopGrind(std::sync::Arc::clone(&stop));
    let grind = {
        let (params, challenge, stop) = (
            ctx.pow_params,
            challenge.clone(),
            std::sync::Arc::clone(&stop),
        );
        move || {
            let token = solve_token_until(params, &challenge, 1 << 24, &stop)?;
            // The test-only floor on a joiner's grind (V210-87), stopped like the grind.
            #[cfg(feature = "test-knobs")]
            while grinding.elapsed() < floor && !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(50).min(floor));
            }
            Ok::<_, Error>(token)
        }
    };
    let token = if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        tokio::task::spawn_blocking(grind)
            .await
            .map_err(|_| Error::JoinPowInvalid)??
    } else {
        grind()?
    };
    let (initiator, share) = join_start(ctx, passphrase, &sid, root, ik)?;
    let solved_in = grinding.elapsed();
    // **A grind past the responder's patience is this device's, and said so (V210-87).** The
    // responder has stopped waiting by then and its refusal arrived here as a stream that failed,
    // which the join reported as "no member could be reached" — about a member that had answered
    // and waited. Both sides derive the patience from the same signed difficulty, so this side can
    // tell, and say how long it took against how long it was given.
    let patience = solve_patience(challenge.difficulty);
    let too_slow = || Error::JoinSolveTooSlow {
        solved_secs: solved_in.as_secs(),
        patience_secs: patience.as_secs(),
    };
    let late = solved_in + SOLVE_PATIENCE_SLACK >= patience;
    if let Err(e) = send_frame(
        &mut send,
        &JoinFrame::Solve {
            equihash_nonce: token.equihash_nonce.clone(),
            solution: token.solution.clone(),
            share,
        },
    )
    .await
    {
        // A member that ended this join while it solved (V210-92) said why before it stopped
        // reading, so the write can fail with the reason already waiting: read it, briefly. Only
        // `Busy` is told apart here. Any other refusal, from a member that stopped waiting for a
        // grind past its patience, is that grind's, and is said as such (V210-87).
        let said =
            tokio::time::timeout(std::time::Duration::from_secs(5), recv_frame(&mut recv)).await;
        return Err(match said {
            Ok(Ok(JoinFrame::Rejected(JoinReject::Busy))) => Error::JoinResponderBusy,
            _ if late => too_slow(),
            Ok(Ok(JoinFrame::Rejected(r))) => rejected(r),
            _ => e,
        });
    }
    #[cfg(feature = "test-knobs")]
    if let Some(stall) = std::env::var(TEST_STALL_AFTER_SOLVE_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        eprintln!("vox: test: solved, now silent for {stall}ms ({TEST_STALL_AFTER_SOLVE_ENV})");
        tokio::time::sleep(std::time::Duration::from_millis(stall)).await;
    }
    #[cfg(feature = "test-knobs")]
    if let Some(drip) = test_drip() {
        eprintln!(
            "vox: test: solved, now {drip:?} before each frame ({TEST_DRIP_AFTER_SOLVE_ENV})"
        );
    }

    // 3. SHARE.
    let peer_share = match recv_frame(&mut recv).await {
        Ok(JoinFrame::Share { share }) => share,
        // Busy is the member's slots, never this joiner's pace (V210-92).
        Ok(JoinFrame::Rejected(JoinReject::Busy)) => return Err(Error::JoinResponderBusy),
        Ok(JoinFrame::Rejected(_)) | Err(_) if late => return Err(too_slow()),
        Ok(JoinFrame::Rejected(r)) => return Err(rejected(r)),
        Err(e) => return Err(e),
        Ok(_) => return Err(Error::MalformedJoin("expected share")),
    };
    let (pending, bootstrap) = initiator.complete_cpace(&peer_share)?;

    // 4/5. PROOF both ways. A wrong passphrase fails here, locally.
    if let Some(drip) = test_drip() {
        tokio::time::sleep(drip).await;
    }
    send_frame(
        &mut send,
        &JoinFrame::Proof {
            sealed: pending.own_proof_sealed()?,
        },
    )
    .await?;
    let sealed_peer = match recv_frame(&mut recv).await? {
        JoinFrame::Proof { sealed } => sealed,
        JoinFrame::Rejected(r) => return Err(rejected(r)),
        _ => return Err(Error::MalformedJoin("expected proof")),
    };
    let peer = pending.verify_peer_sealed(&sealed_peer, &responder_fp)?;

    // 6. INIT — PQXDH against the responder's verified bundle.
    if let Some(drip) = test_drip() {
        tokio::time::sleep(drip).await;
    }
    let (session, init_msg) = bootstrap.bootstrap(&bundle)?;
    send_frame(
        &mut send,
        &JoinFrame::Init {
            message: init_msg.to_wire(),
        },
    )
    .await?;

    // 7. ACCEPTED, carrying the responder's witness to this join (M17.6).
    let witness = match recv_frame(&mut recv).await? {
        JoinFrame::Accepted { witness } => JoinWitness::from_body(&witness)?,
        JoinFrame::Rejected(r) => return Err(rejected(r)),
        JoinFrame::Full { members, cap } => return Err(Error::RoomFull { members, cap }),
        JoinFrame::Busy => return Err(Error::RoomBusy),
        JoinFrame::Unanswered { member } => return Err(Error::AdmissionUnanswered { member }),
        _ => return Err(Error::MalformedJoin("expected accepted")),
    };
    // Checked here, against the identity the handshake pinned, so a responder cannot
    // hand back a witness for some other key or some other room and have it kept.
    witness.verify(
        &responder_pub,
        &ctx.channel_id,
        ctx.epoch,
        &root.fingerprint(),
    )?;

    // 8. OPEN — one ratchet message, empty plaintext, so the responder can send at all.
    //    On this stream rather than a later one, so it is processed before the join
    //    returns (see `JoinFrame::Open`).
    let mut session = session;
    let sealed = session.encrypt(&[])?.to_wire();
    send_frame(&mut send, &JoinFrame::Open { sealed }).await?;
    let _ = send.finish();
    Ok(JoinOutcome {
        session,
        peer,
        witness,
        last_resort_grade: false,
        solved_in,
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
    /// Set once the joiner's proof of work verifies, so its join slot is never the one ended for
    /// a newcomer (V210-92, `node::joinslots`).
    pub worked: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// Read the joiner's opening `WANT` frame, so the caller can select the channel
/// before it builds the [`ResponderConfig`] (see the module docs for why the joiner
/// speaks first).
pub async fn read_join_request(recv: &mut RecvStream) -> Result<(Digest32, u64)> {
    match recv_frame(recv).await? {
        JoinFrame::Want { channel_id, epoch } => Ok((channel_id, epoch)),
        _ => Err(Error::MalformedJoin("expected want")),
    }
}

/// Refuse a join on a stream whose `WANT` named a channel this node cannot answer
/// for (it does not hold it, or it is app-locked so the passphrase is gone). The
/// reason is the same opaque `Refused` every post-work refusal uses.
pub async fn refuse_join(send: SendStream) {
    refuse_join_as(send, JoinReject::Refused).await;
}

/// Refuse a join with `reason`, as [`refuse_join`] does. Only [`JoinReject::Busy`] is said apart,
/// and only before the exchange starts, where it depends on nothing the joiner sent.
pub async fn refuse_join_as(mut send: SendStream, reason: JoinReject) {
    let _ = send_frame(&mut send, &JoinFrame::Rejected(reason)).await;
    let _ = send.finish();
}

/// Run the **responder** side on an already-accepted, already-authorized `join`
/// stream (the manager authorized the kind; `peer_fp` is the connection's
/// authenticated identity).
///
/// The ring is **shared, not borrowed mutably**, and is **persisted here** the moment a
/// one-time prekey is consumed, so the one-shot rule survives a crash (see the module docs).
///
/// # Why the ring is behind a lock
/// This exchange waits on the joiner three times and verifies its proof of work, so it must
/// not run on the node's actor and must not hold anything the rest of the node needs while it
/// waits. The ring is needed at exactly two points — the bundle that goes out in the
/// `Challenge`, and the prekey consume after the *last* frame arrives — with every wait in
/// between. Taking the lock twice, briefly, is what lets concurrent joins overlap instead of
/// queueing behind whichever joiner is slowest; a `&mut` borrow across the whole exchange
/// would serialize them and reproduce the stall one layer down.
///
/// # `admit_before_accepting`
/// Called with the joiner's proven identity **after the exchange succeeds and before the
/// acceptance frame goes out**, and awaited. That ordering is the whole reason it exists. An
/// `Err` is an admission that did not happen: the joiner is refused instead of accepted —
/// [`JoinFrame::Full`] for a room already full, [`JoinReject::NotAdmitted`] otherwise, never the
/// refusal a wrong passphrase gets — and the exchange returns that error.
///
/// The joiner treats `Accepted` as "I am in", and the very next thing it does is publish its
/// records to this node's board. Those records are refused unless this node has already admitted
/// it as an author, and nothing retries them. While the exchange ran on the actor that ordering was
/// free — the admission happened in the same actor turn the exchange ended, before the joiner could
/// possibly have returned. Moving the exchange into a slot broke it: the admission became an event
/// the actor reached *later*, the joiner published into the gap, and the newcomer never reached any
/// board. Measured, real binaries: a third person joining went 6 of 10 to **0 of 10** (ADR-018
/// §"The admission window").
///
/// So the caller uses this to apply the admission on the actor and wait for it. The wait happens
/// here, on the slot's task, which is what keeps the actor free — the property the slot was
/// introduced for.
#[allow(clippy::too_many_arguments)] // each argument is a distinct required input
pub async fn run_responder<F, Fut>(
    mut send: SendStream,
    mut recv: RecvStream,
    peer_fp: Digest32,
    cfg: &ResponderConfig<'_>,
    store: &Store,
    ring: &tokio::sync::Mutex<PrekeyRing>,
    ended: Option<tokio::sync::oneshot::Receiver<()>>,
    admit_before_accepting: F,
) -> Result<JoinOutcome>
where
    F: FnOnce(crate::identity::composite::CompositePublicKey) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let exchange = responder_exchange(&mut send, &mut recv, peer_fp, cfg, store, ring);
    // **Ended for a newcomer, and told so** (V210-92). The slot this exchange holds can be given
    // to a joiner from a lighter source; the exchange stops where it is and the joiner hears the
    // member is busy, not the refusal a wrong passphrase gets. A sender dropped without a word is
    // not an ending: that branch is then off and the exchange runs on.
    let mut result = match ended {
        Some(ended) => tokio::select! {
            r = exchange => r,
            Ok(()) = ended => Err(Error::JoinEndedForNewcomer),
        },
        None => exchange.await,
    };
    match &mut result {
        Ok(outcome) => {
            // **Admitted before it is told it is in.** See `admit_before_accepting`. And told it
            // is in only if it was: an admission that failed was dropped here, so a joiner the
            // room could not take (it was full) heard `Accepted`, exited 0, and was a member of
            // nothing.
            if let Err(e) = admit_before_accepting(outcome.peer.identity.clone()).await {
                let refusal = match &e {
                    Error::RoomFull { members, cap } => JoinFrame::Full {
                        members: *members,
                        cap: *cap,
                    },
                    Error::RoomBusy => JoinFrame::Busy,
                    Error::AdmissionUnanswered { member } => JoinFrame::Unanswered {
                        member: member.clone(),
                    },
                    // The passphrase was accepted: never the refusal that reads as a wrong one.
                    _ => JoinFrame::Rejected(JoinReject::NotAdmitted),
                };
                let _ = send_frame(&mut send, &refusal).await;
                let _ = send.finish();
                return Err(e);
            }
            // The witness `responder_exchange` minted beside the verification that
            // justifies it. The joiner keeps it: it is what makes that key admissible
            // to anyone else (M17.6).
            send_frame(
                &mut send,
                &JoinFrame::Accepted {
                    witness: outcome.witness.body_bytes(),
                },
            )
            .await?;
            // Step 8: the joiner's ratchet message, read **before returning**, so the
            // session handed to the caller can already send. Without it this node holds
            // a session it can receive on and never speak on, and its first `Consent`
            // fails with "no sending chain" (see `JoinFrame::Open`).
            // A joiner that says nothing here leaves this node unable to answer it.
            // That is the joiner's loss and not a reason to refuse a join that is
            // already complete and already witnessed, so anything else is tolerated:
            // the session still receives, and a later `Hello`/`Open` on a pairwise
            // stream can open the sending direction.
            if let Ok(Ok(JoinFrame::Open { sealed })) =
                tokio::time::timeout(ADMISSION_PATIENCE, recv_frame(&mut recv)).await
            {
                let message = crate::pairwise::message::Message::from_wire(&sealed)?;
                // An empty plaintext is the whole payload; what matters is that
                // decrypting it steps the ratchet and yields a sending chain.
                let _ = outcome.session.decrypt(&message, cfg.now_secs)?;
            }
            let _ = send.finish();
        }
        Err(e) => {
            // Coarse by design (see the module docs).
            let reason = match e {
                Error::JoinPowInvalid => JoinReject::PowInvalid,
                Error::MalformedJoin(_) | Error::Cbor(_) => JoinReject::Malformed,
                Error::JoinEndedForNewcomer => JoinReject::Busy,
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
    ring: &tokio::sync::Mutex<PrekeyRing>,
) -> Result<JoinOutcome> {
    // 1. CHALLENGE — difficulty adapts to the responder's live join load and is
    //    capped by `adapted_for_load` at `Difficulty::MAX`.
    let difficulty = cfg.base_difficulty.adapted_for_load(cfg.pending_joins);
    let challenge = ResponderNonce::generate(&cfg.ctx.channel_id, cfg.ctx.epoch, difficulty)?;
    let challenge_sig = challenge.sign(cfg.root)?;
    let sid = fresh_sid()?;
    let root_pub = cfg.root.public_key();
    // Held only for the bundle, and dropped before the first frame goes out: everything
    // below this line waits on the joiner.
    let bundle = { ring.lock().await.bundle(&root_pub)? };
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
    let solve = crate::transport::framing::read_frame_within(
        recv,
        MAX_JOIN_FRAME,
        solve_patience(challenge.difficulty),
    )
    .await?
    .ok_or(Error::MalformedJoin("join stream closed early"))?;
    let JoinFrame::Solve {
        equihash_nonce,
        solution,
        share: joiner_share,
    } = JoinFrame::from_frame(&solve)?
    else {
        return Err(Error::MalformedJoin("expected solve"));
    };
    let token = PowToken {
        equihash_nonce,
        solution,
    };
    let (responder, own_share) =
        join_accept(cfg.ctx, cfg.passphrase, &sid, &challenge, &token, cfg.root)?;
    // The work is done and verified: from here this join's slot is not given to a newcomer, and
    // the rest of the exchange must finish within `ADMISSION_PATIENCE`.
    if let Some(worked) = &cfg.worked {
        worked.store(true, std::sync::atomic::Ordering::Release);
    }
    tokio::time::timeout(
        ADMISSION_PATIENCE,
        responder_after_work(
            send,
            recv,
            peer_fp,
            cfg,
            store,
            ring,
            responder,
            own_share,
            joiner_share,
        ),
    )
    .await
    .map_err(|_| Error::MalformedJoin("the joiner went quiet after its proof of work"))?
}

/// The exchange after the joiner's proof of work has verified: steps 3–7, bounded by the caller.
#[allow(clippy::too_many_arguments)] // the state of one exchange, handed on whole
async fn responder_after_work(
    send: &mut SendStream,
    recv: &mut RecvStream,
    peer_fp: Digest32,
    cfg: &ResponderConfig<'_>,
    store: &Store,
    ring: &tokio::sync::Mutex<PrekeyRing>,
    responder: crate::join::session::JoinResponder<'_>,
    own_share: [u8; CPACE_SHARE_LEN],
    joiner_share: [u8; CPACE_SHARE_LEN],
) -> Result<JoinOutcome> {
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
    // The last frame has arrived, so the ring is taken again here — for the consume, the
    // durable save and the session bootstrap that depends on both. No wait happens under
    // this guard, which is what keeps one joiner from delaying another's prekeys.
    let (session, last_resort_grade) = {
        let mut ring = ring.lock().await;
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
            prekeys::save(store, cfg.root, &ring)?;
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
        (session, last_resort_grade)
    };
    debug_assert_eq!(session.is_last_resort_grade(), last_resort_grade);
    // This node verified the joiner's ADR-005 proof of possession above, so it is the
    // only party that can honestly attest to this join. The witness is minted here,
    // beside the verification that justifies it, and `run_responder` sends it with the
    // acceptance (M17.6).
    let witness = JoinWitness::build(
        cfg.root,
        &cfg.ctx.channel_id,
        cfg.ctx.epoch,
        &peer.fingerprint,
        cfg.now_secs,
    )?;
    Ok(JoinOutcome {
        session,
        peer,
        witness,
        last_resort_grade,
        solved_in: std::time::Duration::ZERO,
    })
}
