//! **A claim answers "you hold it" only once every online member agrees** (V210-168, the
//! decider 2026-10-02; the same rule as the room cap).
//!
//! A claim is a post, and who holds what is whatever each member's own log folds to. Two claims
//! posted at once each fold to "mine" on their own node until the other arrives, so both were
//! told "you hold it" and the loser learned otherwise only later. Agreement closes that window:
//! after the claim is posted, the claimant's node asks every other member it can reach, all at
//! once, on an [`StreamKind::Agree`] stream:
//!
//! - the member waits (at most [`HOLD_PATIENCE`]) until its own log holds the claim, pulling it
//!   from the claimant if it has not arrived;
//! - then it answers with the entry hashes of the posts it holds of the asked `type`s
//!   ([`Answer::Holds`]), or that it never got the claim ([`Answer::NotReceived`]).
//!
//! The claimant's node pulls whatever a member holds that it does not (bounded by
//! [`FETCH_PATIENCE`]), and reports, member by member, what that member's log has that its own
//! lacks and the reverse ([`Agreement`]). The client folds each member's set and says "you hold
//! it" only when every one of them, and its own, folds to this claimant.
//!
//! **Why exactly one of two crossing claims wins.** Each claimant's node is a member the other
//! asks, and it answers only once it holds the asker's claim. Its own claim is then either
//! already in its log, so in the set it answers with and folded by the asker, or posted later,
//! and a node stamps every post later than every post it holds
//! (`ChannelState::stamp_after_held`), so that claim sorts after the asker's whatever the two
//! clocks say. Either way the set each claimant folds puts the same claim first: the winner is
//! told it holds it, and the other that it lost, and to whom, at once. The order rests on the
//! stamps, not on the clocks agreeing.
//!
//! **Online is what the asker observes**, as for the room cap: a member it holds a connection to
//! or reaches within [`REACH_PATIENCE`]. One it cannot reach, or that does not answer within
//! [`ASK_PATIENCE`], is reported as such, and the client does not claim success.
//!
//! The node knows no `type`'s meaning (see [`crate::node::api::StructuredIndex`]): it moves entry
//! hashes, and the client folds them. Only members may open this stream (`PeerPolicy::allows`),
//! and only a member of the room asked about is answered.

use std::time::Duration;

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::{read_frame_within, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

/// How long the asker waits for every member's answer, all asked at once.
pub const ASK_PATIENCE: Duration = Duration::from_secs(10);

/// How long a member waits for the claim to reach its log before it answers that it never got
/// it. Inside [`ASK_PATIENCE`], so the answer arrives before the asker gives up.
pub const HOLD_PATIENCE: Duration = Duration::from_secs(8);

/// How long the asker tries to reach a member it holds no connection to before counting it
/// unreachable. A member online reaches in about a round trip, directly or through a relay.
pub const REACH_PATIENCE: Duration = Duration::from_secs(2);

/// How long a connection may carry nothing back, probes included, before the member behind it
/// counts as unreachable. A live peer acknowledges a probe within a round trip.
pub const SILENT_IS_GONE: Duration = Duration::from_secs(3);

/// How long the asker's node waits to pull what members hold that it does not.
pub const FETCH_PATIENCE: Duration = Duration::from_secs(5);

/// The most entry hashes one answer carries. Past this a member answers [`Answer::TooMany`].
pub const MAX_LISTED: usize = 65_536;

/// The most `type`s one question names, and the longest one.
pub const MAX_TYPES: usize = 16;
const MAX_TYPE_LEN: usize = 64;

const MAX_ASK_FRAME: usize = 2 * 1024;
const MAX_ANSWER_FRAME: usize = MAX_LISTED * 34 + 64;

const OP_ASK: u64 = 1;
const OP_ANSWER: u64 = 2;

/// The asker's question: "here is my post `entry` in `channel_id`; which posts of these `types`
/// do you hold, once you hold it?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// The room.
    pub channel_id: Digest32,
    /// Its epoch.
    pub epoch: u64,
    /// The asker's post the answer must include.
    pub entry: Digest32,
    /// The `type`s whose posts are listed.
    pub types: Vec<String>,
}

/// A member's answer to an [`Ask`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// It holds the asked entry, and these are the posts of the asked types it holds.
    Holds(Vec<Digest32>),
    /// It does not hold the asked entry after [`HOLD_PATIENCE`]: its log has not taken it.
    NotReceived,
    /// It cannot answer for that room: it does not hold it, or the asker is not a member of it.
    NotHeld,
    /// It holds more than [`MAX_LISTED`] such posts.
    TooMany,
}

impl Ask {
    fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(OP_ASK)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.entry)
            .array(self.types.len());
        for t in &self.types {
            e.text(t);
        }
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        if d.array()? != 5 || d.uint()? != OP_ASK {
            return Err(Error::MalformedBundle("agree ask"));
        }
        let channel_id = digest(&mut d)?;
        let epoch = d.uint()?;
        let entry = digest(&mut d)?;
        let n = d.array()?;
        if n > MAX_TYPES {
            return Err(Error::MalformedBundle("agree ask: too many types"));
        }
        let mut types = Vec::with_capacity(n);
        for _ in 0..n {
            let t = d.text()?;
            if t.len() > MAX_TYPE_LEN {
                return Err(Error::MalformedBundle("agree ask: type too long"));
            }
            types.push(t.to_owned());
        }
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            entry,
            types,
        })
    }
}

impl Answer {
    fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Answer::Holds(list) => {
                e.array(3).uint(OP_ANSWER).uint(0).array(list.len());
                for h in list {
                    e.bytes(h);
                }
            }
            Answer::NotReceived => {
                e.array(2).uint(OP_ANSWER).uint(1);
            }
            Answer::NotHeld => {
                e.array(2).uint(OP_ANSWER).uint(2);
            }
            Answer::TooMany => {
                e.array(2).uint(OP_ANSWER).uint(3);
            }
        }
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array()?;
        if d.uint()? != OP_ANSWER {
            return Err(Error::MalformedBundle("agree answer"));
        }
        let a = match (d.uint()?, n) {
            (0, 3) => {
                let m = d.array()?;
                if m > MAX_LISTED {
                    return Err(Error::MalformedBundle("agree answer: too many entries"));
                }
                let mut list = Vec::with_capacity(m);
                for _ in 0..m {
                    list.push(digest(&mut d)?);
                }
                Answer::Holds(list)
            }
            (1, 2) => Answer::NotReceived,
            (2, 2) => Answer::NotHeld,
            (3, 2) => Answer::TooMany,
            _ => return Err(Error::MalformedBundle("agree answer")),
        };
        d.finish()?;
        Ok(a)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("agree digest"))
}

/// What asking one member came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asking {
    /// It answered.
    Answered(Answer),
    /// Nothing came back on the connection, not even an acknowledgement of a probe: its process
    /// is not there.
    Gone,
    /// The connection is heard from, and no answer came within the bound.
    Unanswered,
}

/// **The asker's side**: ask `ask` of the member on `conn`, and wait at most `patience`.
///
/// While it waits the connection is probed, so a member whose process died with its connection
/// not yet known closed is reported gone after [`SILENT_IS_GONE`], not after the whole bound.
pub async fn ask(conn: &VoxConnection, ask: &Ask, patience: Duration) -> Asking {
    let heard = || conn.quinn().stats().udp_rx.datagrams;
    let start = heard();
    // Bounded as a whole, opening the stream included: on a connection whose peer died without a
    // word, opening a stream waits on flow control for as long as the connection lives.
    let asked = async {
        let (mut send, mut recv) = open_typed(conn, StreamKind::Agree).await?;
        write_frame(&mut send, &ask.to_frame()).await?;
        let frame = read_frame_within(&mut recv, MAX_ANSWER_FRAME, patience)
            .await?
            .ok_or(Error::Unreachable(
                "agree: the member closed the stream unanswered",
            ))?;
        let _ = send.finish();
        Answer::from_frame(&frame)
    };
    tokio::pin!(asked);
    let t0 = tokio::time::Instant::now();
    let deadline = t0 + patience;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            answered = &mut asked => {
                return match answered {
                    Ok(a) => Asking::Answered(a),
                    Err(_) if conn.quinn().close_reason().is_some() || heard() == start => {
                        Asking::Gone
                    }
                    Err(_) => Asking::Unanswered,
                };
            }
            _ = tick.tick() => {
                let _ = crate::node::net::probe(conn);
                if heard() == start && t0.elapsed() >= SILENT_IS_GONE {
                    return Asking::Gone;
                }
                if tokio::time::Instant::now() >= deadline {
                    return if heard() == start { Asking::Gone } else { Asking::Unanswered };
                }
            }
        }
    }
}

/// **A member's side, before the actor looks**: read the asker's question.
///
/// # Errors
/// No well-formed question within [`ASK_PATIENCE`].
pub async fn read_ask(recv: &mut RecvStream) -> Result<Ask> {
    let frame = read_frame_within(recv, MAX_ASK_FRAME, ASK_PATIENCE)
        .await?
        .ok_or(Error::MalformedBundle(
            "agree: stream closed before the question",
        ))?;
    Ask::from_frame(&frame)
}

/// **A member's side**: send the answer and close the stream.
pub async fn answer(mut send: SendStream, answer: &Answer) {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        write_frame(&mut send, &answer.to_frame()),
    )
    .await;
    let _ = send.finish();
}

/// Where one member stands on the asker's post, as the asker's node reports it to its client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agreement {
    /// It holds the post. Its set of posts of the asked types is the asker's own set (as counted
    /// in [`Report::mine`]) less `absent`, plus `unseen`, which the asker's node holds none of
    /// even after pulling them.
    Holds {
        /// Posts the asker's node holds and this member does not.
        absent: Vec<Digest32>,
        /// Posts this member holds and the asker's node does not.
        unseen: Vec<Digest32>,
    },
    /// Reached, and its log has not taken the post.
    NotReceived,
    /// Reached, and it does not hold the room, or does not count the asker a member.
    NotHeld,
    /// Its set differs from the asker's by more than one answer can carry.
    TooDifferent,
    /// Not reached within [`REACH_PATIENCE`], or its process is not there.
    Unreachable,
    /// Reached, and it gave no answer within [`ASK_PATIENCE`].
    Unanswered,
}

/// What an agreement round found, for the client.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// How many posts of the asked types the asker's node held when it compared: the client
    /// reads them and checks it read exactly that many, or asks again.
    pub mine: u64,
    /// Every other member of the room, and where it stands.
    pub members: Vec<(Digest32, Agreement)>,
}

/// The most hashes one [`Agreement::Holds`] carries in each list, so a [`Report`] fits an IPC
/// frame whatever the room's size.
pub const MAX_DIFF: usize = 1024;

/// Compare one member's set with this node's own.
#[must_use]
pub fn compare(mine: &[Digest32], theirs: &[Digest32]) -> Agreement {
    let a: std::collections::BTreeSet<&Digest32> = mine.iter().collect();
    let b: std::collections::BTreeSet<&Digest32> = theirs.iter().collect();
    let absent: Vec<Digest32> = a.difference(&b).map(|h| **h).collect();
    let unseen: Vec<Digest32> = b.difference(&a).map(|h| **h).collect();
    if absent.len() > MAX_DIFF || unseen.len() > MAX_DIFF {
        return Agreement::TooDifferent;
    }
    Agreement::Holds { absent, unseen }
}

/// Encode a [`Report`] into `e` (the IPC frame body uses it).
pub fn encode_report(e: &mut Encoder, r: &Report) {
    e.array(2).uint(r.mine).array(r.members.len());
    for (m, a) in &r.members {
        e.array(2).bytes(m);
        match a {
            Agreement::Holds { absent, unseen } => {
                e.array(3).uint(0).array(absent.len());
                for h in absent {
                    e.bytes(h);
                }
                e.array(unseen.len());
                for h in unseen {
                    e.bytes(h);
                }
            }
            Agreement::NotReceived => {
                e.array(1).uint(1);
            }
            Agreement::NotHeld => {
                e.array(1).uint(2);
            }
            Agreement::TooDifferent => {
                e.array(1).uint(3);
            }
            Agreement::Unreachable => {
                e.array(1).uint(4);
            }
            Agreement::Unanswered => {
                e.array(1).uint(5);
            }
        }
    }
}

/// The most members one [`Report`] names: a room's member cap, with room to spare.
pub const MAX_REPORTED: usize = 1024;

/// Decode a [`Report`] written by [`encode_report`].
///
/// # Errors
/// A malformed or oversized report.
pub fn decode_report(d: &mut Decoder<'_>) -> Result<Report> {
    let bad = |what| Error::MalformedIpc(what);
    if d.array()? != 2 {
        return Err(bad("agreement report"));
    }
    let mine = d.uint()?;
    let n = d.array()?;
    if n > MAX_REPORTED {
        return Err(bad("agreement report: too many members"));
    }
    let list = |d: &mut Decoder<'_>| -> Result<Vec<Digest32>> {
        let k = d.array()?;
        if k > MAX_DIFF {
            return Err(bad("agreement report: list too long"));
        }
        (0..k)
            .map(|_| {
                d.bytes()?
                    .try_into()
                    .map_err(|_| bad("agreement report: digest"))
            })
            .collect()
    };
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(bad("agreement report: member"));
        }
        let m: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| bad("agreement report: digest"))?;
        let k = d.array()?;
        let a = match (d.uint()?, k) {
            (0, 3) => {
                let absent = list(d)?;
                let unseen = list(d)?;
                Agreement::Holds { absent, unseen }
            }
            (1, 1) => Agreement::NotReceived,
            (2, 1) => Agreement::NotHeld,
            (3, 1) => Agreement::TooDifferent,
            (4, 1) => Agreement::Unreachable,
            (5, 1) => Agreement::Unanswered,
            _ => return Err(bad("agreement report: verdict")),
        };
        members.push((m, a));
    }
    Ok(Report { mine, members })
}
