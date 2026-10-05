//! **A room never exceeds its member cap: every online member agrees before a newcomer is
//! admitted** (V030-30, #366; the decider, 2026-10-02).
//!
//! Each member used to check the cap against its own view, so members answering joins at the same
//! moment could each give the last place away. Now the member answering a join (the *asker*)
//! agrees the place with every other member it holds a connection to, before it admits the joiner:
//!
//! 1. **Reserve.** It counts its authors and every place promised and not yet settled, its own
//!    promises and those it gave others. At the cap it refuses the join as full; otherwise it holds
//!    a place for the joiner.
//! 2. **Ask.** It asks every member it holds a connection to, all at once, on a
//!    [`StreamKind::Seat`] stream: "may this newcomer take a place?" Each member counts the same way
//!    and answers [`Answer::Yes`], promising the place, or [`Answer::Full`], or [`Answer::Taken`]
//!    when the last place is promised to another newcomer.
//! 3. **Commit or abort.** Every member said yes: the asker admits the joiner and tells it it is
//!    in. Any other answer, or none within [`SEAT_ANSWER_WITHIN`]: the asker sends [`Abort`] to
//!    every member that promised, frees its own place, and refuses the joiner, saying why.
//!
//! A promise is kept until the newcomer is an author on the promising member (it arrives from a
//! board, with the asker's witness), an [`Abort`] frees it, or [`PROMISE_TTL`] passes. A stream that
//! ends with no abort keeps the promise: a commit that never arrived must not free a place early.
//!
//! **Online is what the asker observes**: a member it holds a connection to that is heard from. One
//! that is not connected is not asked, and one whose connection carries nothing back for
//! [`SILENT_IS_GONE`] (its process crashed or is stopped, its connection not yet known closed) is
//! offline; neither blocks the join. Each learns of the newcomer from a board when it returns, and
//! admits it past the cap only after a split let both sides fill the room, which it says
//! (`ChannelState::admit_from_board`). Anchors that are not members are never asked. Only a
//! member of the room may open this stream (`PeerPolicy::allows`), and only a member of the room
//! asked about is answered.

use std::time::Duration;

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::{read_frame_within, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

/// **How long the asker waits for every member's answer** (#366), all asked at once. A member
/// answers from its own state, without waiting on anything, in about a round trip; 5 s is that
/// with ample margin on a slow link, and fits inside the 20 s the rest of a join may take
/// (`joinstream::ADMISSION_PATIENCE`), so a member that does not answer fails the join with time
/// left to say why.
pub const SEAT_ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// **How long a member keeps a place it promised** (#366) with no word of the newcomer and no
/// abort. Long enough for the newcomer's records to reach this member from a board after the
/// asker admitted it, so a place taken is never counted free in between; short enough that an
/// asker that crashed between asking and committing holds a place for two minutes, not for good.
pub const PROMISE_TTL: Duration = Duration::from_secs(120);

/// **For proofs only.** When set, this node reads each member's seat question and never answers
/// it, holding the stream open, as a member online whose node is stuck would: the asker hears the
/// connection and gets no answer. Nothing a person runs sets it; unset, nothing changes. Not
/// compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
pub const TEST_SEAT_SILENT_ENV: &str = "VOX_TEST_SEAT_SILENT";

const MAX_FRAME: usize = 256;

const OP_ASK: u64 = 1;
const OP_ANSWER: u64 = 2;
const OP_ABORT: u64 = 3;

/// The asker's question: "may `joiner` take a place in `channel_id`?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ask {
    /// The room.
    pub channel_id: Digest32,
    /// Its epoch.
    pub epoch: u64,
    /// The newcomer's fingerprint.
    pub joiner: Digest32,
}

/// A member's answer to an [`Ask`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// There is a place, and it is promised to the newcomer.
    Yes,
    /// The room is at its cap: `members` authors.
    Full {
        /// How many members the answering member holds for the room.
        members: u64,
    },
    /// The last place is promised to another newcomer.
    Taken,
    /// It does not hold the room at that epoch, or does not count the asker a member.
    NotHeld,
}

/// "The place promised to `joiner` is not taken after all."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abort {
    /// The room.
    pub channel_id: Digest32,
    /// The newcomer whose place is freed.
    pub joiner: Digest32,
}

impl Ask {
    fn to_frame(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(OP_ASK)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.joiner);
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        if d.array()? != 4 || d.uint()? != OP_ASK {
            return Err(Error::MalformedBundle("seat ask"));
        }
        let channel_id = digest(&mut d)?;
        let epoch = d.uint()?;
        let joiner = digest(&mut d)?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            joiner,
        })
    }
}

impl Answer {
    fn to_frame(self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Answer::Yes => {
                e.array(2).uint(OP_ANSWER).uint(0);
            }
            Answer::Full { members } => {
                e.array(3).uint(OP_ANSWER).uint(1).uint(members);
            }
            Answer::Taken => {
                e.array(2).uint(OP_ANSWER).uint(2);
            }
            Answer::NotHeld => {
                e.array(2).uint(OP_ANSWER).uint(3);
            }
        }
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array()?;
        if d.uint()? != OP_ANSWER {
            return Err(Error::MalformedBundle("seat answer"));
        }
        let a = match (d.uint()?, n) {
            (0, 2) => Answer::Yes,
            (1, 3) => Answer::Full { members: d.uint()? },
            (2, 2) => Answer::Taken,
            (3, 2) => Answer::NotHeld,
            _ => return Err(Error::MalformedBundle("seat answer")),
        };
        d.finish()?;
        Ok(a)
    }
}

impl Abort {
    fn to_frame(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(OP_ABORT)
            .bytes(&self.channel_id)
            .bytes(&self.joiner);
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        if d.array()? != 3 || d.uint()? != OP_ABORT {
            return Err(Error::MalformedBundle("seat abort"));
        }
        let channel_id = digest(&mut d)?;
        let joiner = digest(&mut d)?;
        d.finish()?;
        Ok(Self { channel_id, joiner })
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("seat digest"))
}

/// How long a connection may carry nothing back, a probe's acknowledgement included, before the
/// member behind it counts as **offline**: its process is not there (it crashed, or is stopped). A
/// live member acknowledges a probe within a round trip. The Agree stream's bound, for the same
/// question (`agreestream::SILENT_IS_GONE`).
pub const SILENT_IS_GONE: Duration = crate::node::agreestream::SILENT_IS_GONE;

/// What asking one member came to.
#[derive(Debug)]
pub enum Asked {
    /// It answered, and this is the stream to abort its promise on.
    Answered(Answer, SendStream),
    /// Nothing came back on the connection for [`SILENT_IS_GONE`], not even a probe's
    /// acknowledgement: the member is offline, so it is not counted and does not block the join
    /// (the decider, 2026-10-02: an offline member learns of the newcomer when it returns).
    Gone,
    /// The connection is heard from, and no answer came within [`SEAT_ANSWER_WITHIN`]: a member
    /// online that did not agree.
    Unanswered,
}

/// **The asker's side**: ask `ask` of the member on `conn`, bounded as a whole by
/// [`SEAT_ANSWER_WITHIN`] (opening the stream included: on a connection whose peer is gone,
/// opening one waits on flow control for as long as the connection lives). While it waits the
/// connection is probed, so a member whose process is not there, with its connection not yet
/// known closed, is found [`Asked::Gone`] after [`SILENT_IS_GONE`].
pub async fn ask(conn: &VoxConnection, ask: Ask) -> Asked {
    let heard = || conn.quinn().stats().udp_rx.datagrams;
    let start = heard();
    let asked = async {
        let (mut send, mut recv) = open_typed(conn, StreamKind::Seat).await?;
        write_frame(&mut send, &ask.to_frame()).await?;
        let frame = read_frame_within(&mut recv, MAX_FRAME, SEAT_ANSWER_WITHIN)
            .await?
            .ok_or(Error::Unreachable(
                "seat: the member closed the stream unanswered",
            ))?;
        Ok::<_, Error>((Answer::from_frame(&frame)?, send))
    };
    tokio::pin!(asked);
    let t0 = tokio::time::Instant::now();
    let deadline = t0 + SEAT_ANSWER_WITHIN;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            answered = &mut asked => {
                return match answered {
                    Ok((answer, send)) => Asked::Answered(answer, send),
                    Err(_) if conn.quinn().close_reason().is_some() || heard() == start => {
                        Asked::Gone
                    }
                    Err(_) => Asked::Unanswered,
                };
            }
            _ = tick.tick() => {
                let _ = crate::node::net::probe(conn);
                if heard() == start && t0.elapsed() >= SILENT_IS_GONE {
                    return Asked::Gone;
                }
                if tokio::time::Instant::now() >= deadline {
                    return if heard() == start { Asked::Gone } else { Asked::Unanswered };
                }
            }
        }
    }
}

/// **The asker's side, on an abort**: free the place `send`'s member promised, and close.
pub async fn abort(mut send: SendStream, abort: Abort) {
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        write_frame(&mut send, &abort.to_frame()),
    )
    .await;
    let _ = send.finish();
}

/// **The asker's side, on a commit**: close the stream with no abort, so the promise stands until
/// the newcomer reaches the member.
pub fn commit(mut send: SendStream) {
    let _ = send.finish();
}

/// **A member's side, before the actor looks**: read the asker's question.
///
/// # Errors
/// No well-formed question within [`SEAT_ANSWER_WITHIN`].
pub async fn read_ask(recv: &mut RecvStream) -> Result<Ask> {
    let frame = read_frame_within(recv, MAX_FRAME, SEAT_ANSWER_WITHIN)
        .await?
        .ok_or(Error::MalformedBundle(
            "seat: stream closed before the question",
        ))?;
    Ask::from_frame(&frame)
}

/// **A member's side**: send the answer, then wait (at most [`PROMISE_TTL`]) for an abort of the
/// place it promised. `Some` is an abort for that room and newcomer; `None` is anything else: the
/// stream closed with no abort (a commit), a malformed frame, or the bound.
pub async fn answer_and_wait(
    mut send: SendStream,
    mut recv: RecvStream,
    answer: Answer,
    asked: Ask,
) -> Option<Abort> {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        write_frame(&mut send, &answer.to_frame()),
    )
    .await;
    let _ = send.finish();
    if answer != Answer::Yes {
        return None;
    }
    let frame = read_frame_within(&mut recv, MAX_FRAME, PROMISE_TTL)
        .await
        .ok()??;
    let abort = Abort::from_frame(&frame).ok()?;
    (abort.channel_id == asked.channel_id && abort.joiner == asked.joiner).then_some(abort)
}
