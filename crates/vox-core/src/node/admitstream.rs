//! **A room's cap is strict: every online member agrees before a newcomer is admitted**
//! (V210-128, the decider 2026-10-02).
//!
//! The member answering a join (the *asker*) checks its own view, reserves a place for the
//! newcomer, and then asks every member it is connected to at that moment — directly or through
//! a relay, which only carries the bytes — on an [`StreamKind::Admit`] stream. Each member
//! answers at once from its own state and never waits on anyone:
//!
//! - [`Verdict::Yes`] — it has room (admitted + reserved + 1 ≤ cap), and reserves a place too;
//! - [`Verdict::Full`] — it already holds the cap in admitted members;
//! - [`Verdict::Busy`] — it is at the cap only because of places reserved for other joins.
//!
//! With every answer a yes, the asker admits the newcomer and sends [`Decision::Commit`];
//! otherwise [`Decision::Abort`], and every reservation for the newcomer is dropped. A member
//! that is connected and does not answer within [`ASK_PATIENCE`] fails the join: skipping it
//! could let it admit somebody else at the same moment. A member the asker holds no connection
//! to is offline and blocks nothing.
//!
//! **Why the cap holds.** Every admission has a yes from every online member, and every yes is a
//! reservation a member counts against its own free places. Two joins racing for one last place
//! through two members are each reserved by their own asker before it asks, so each asker answers
//! the other `Busy`: at most one gets in, and when both lose, each newcomer is told to try again.
//! Nobody holds a reservation while waiting on another member's answer except the asker for its
//! own newcomer, so there is no wait cycle.
//!
//! **Where it does not hold:** a network split. Members that cannot reach each other agree only
//! among themselves; see [`crate::node::channel::ADMIT_LEARNED_PAST_CAP`] for what a member
//! learned past the cap after the split heals is then.
//!
//! Nothing here goes through an anchor's authority: an anchor is never a member, and only
//! members may open this stream (`PeerPolicy::allows`).

use std::time::Duration;

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::{read_frame_within, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

/// How long the asker waits for every online member's answer, all asked at once. Well inside
/// the joiner's own patience for its acceptance (`FRAME_PATIENCE`, 30 s), so a slow agreement is
/// never read as an unreachable member.
pub const ASK_PATIENCE: Duration = Duration::from_secs(10);

/// How long a member waits, after it answered yes, for the asker's decision before it drops the
/// reservation on its own. Past [`ASK_PATIENCE`], so an asker that is still collecting answers
/// is not abandoned.
pub const DECISION_PATIENCE: Duration = Duration::from_secs(20);

/// How long a committed reservation counts against the cap before the newcomer's own board
/// record must have arrived. A fallback only: the record normally lands within seconds, and is
/// what admits the newcomer here, which ends the reservation.
pub const COMMITTED_FALLBACK: Duration = Duration::from_secs(600);

const MAX_ADMIT_FRAME: usize = 256;

const OP_ASK: u64 = 1;
const OP_VERDICT: u64 = 2;
const OP_DECISION: u64 = 3;

/// An asker's question: may `newcomer` take a place in `channel_id`?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// The room.
    pub channel_id: Digest32,
    /// Its epoch.
    pub epoch: u64,
    /// The newcomer's fingerprint.
    pub newcomer: Digest32,
}

/// A member's answer to an [`Ask`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// There is room, and a place is reserved here.
    Yes,
    /// The room holds `members`, its cap `cap`, in admitted members.
    Full {
        /// Admitted members, as this member counts them.
        members: u64,
        /// The cap it enforces.
        cap: u64,
    },
    /// The last place is reserved for another join.
    Busy,
    /// This member cannot answer for that room: it does not hold it, or the asker is not a member.
    NotHeld,
}

/// The asker's decision, sent to every member that answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The newcomer is admitted: keep counting it until its own record arrives.
    Commit,
    /// It is not: drop the reservation.
    Abort,
}

impl Ask {
    fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(OP_ASK)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.newcomer);
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        if d.array()? != 4 || d.uint()? != OP_ASK {
            return Err(Error::MalformedBundle("admit ask"));
        }
        let channel_id = digest(&mut d)?;
        let epoch = d.uint()?;
        let newcomer = digest(&mut d)?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            newcomer,
        })
    }
}

impl Verdict {
    fn to_frame(self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Verdict::Yes => e.array(2).uint(OP_VERDICT).uint(0),
            Verdict::Full { members, cap } => {
                e.array(4).uint(OP_VERDICT).uint(1).uint(members).uint(cap)
            }
            Verdict::Busy => e.array(2).uint(OP_VERDICT).uint(2),
            Verdict::NotHeld => e.array(2).uint(OP_VERDICT).uint(3),
        };
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.array()?;
        if d.uint()? != OP_VERDICT {
            return Err(Error::MalformedBundle("admit verdict"));
        }
        let v = match (d.uint()?, n) {
            (0, 2) => Verdict::Yes,
            (1, 4) => Verdict::Full {
                members: d.uint()?,
                cap: d.uint()?,
            },
            (2, 2) => Verdict::Busy,
            (3, 2) => Verdict::NotHeld,
            _ => return Err(Error::MalformedBundle("admit verdict")),
        };
        d.finish()?;
        Ok(v)
    }
}

impl Decision {
    fn to_frame(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2)
            .uint(OP_DECISION)
            .uint(u64::from(self == Decision::Commit));
        e.finish()
    }

    fn from_frame(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        if d.array()? != 2 || d.uint()? != OP_DECISION {
            return Err(Error::MalformedBundle("admit decision"));
        }
        let commit = d.uint()? == 1;
        d.finish()?;
        Ok(if commit {
            Decision::Commit
        } else {
            Decision::Abort
        })
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("admit digest"))
}

/// One member asked: the stream stays open for the decision.
pub struct Asked {
    /// The member.
    pub member: Digest32,
    send: SendStream,
}

impl Asked {
    /// Tell the member the decision, and close the stream. Best effort: a member that does not
    /// hear it drops its reservation at [`DECISION_PATIENCE`], or counts the newcomer until its
    /// record arrives.
    pub async fn decide(mut self, decision: Decision) {
        // Bounded: a member that stopped reading must not hold the asker past its own decision.
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            write_frame(&mut self.send, &decision.to_frame()),
        )
        .await;
        let _ = self.send.finish();
    }
}

/// What asking one member came to.
pub enum Asking {
    /// It answered.
    Answered(Asked, Verdict),
    /// Its process is not there: nothing at all came back on the connection, not even an
    /// acknowledgement of a probe, for [`SILENT_IS_OFFLINE`]. Offline; it blocks nothing.
    Offline,
    /// Its process is there — the connection is heard from — and it gave no answer within the
    /// bound. It fails the join: skipped, it could admit somebody else at the same moment.
    Unanswered,
}

/// How long the asker tries to reach a member it holds no connection to before counting it
/// offline. A member online reaches in about a round trip, directly or through a relay.
pub const REACH_PATIENCE: Duration = Duration::from_secs(2);

/// How long a connection may carry nothing back, probes included, before the member behind it
/// counts as offline for a join's agreement. A live peer acknowledges a probe within a round
/// trip; a process that died, or is frozen, acknowledges nothing.
pub const SILENT_IS_OFFLINE: Duration = Duration::from_secs(3);

/// **The asker's side**: ask `member`, on `conn`, whether `ask.newcomer` may take a place, and
/// wait at most `patience` for the answer. The stream is kept for the decision.
///
/// While it waits, the connection is probed: an answer is awaited from a member that is there,
/// and a member that is not — dead, or frozen, with a connection not yet known closed — is
/// offline after [`SILENT_IS_OFFLINE`] rather than holding the join for the whole bound.
pub async fn ask(conn: &VoxConnection, member: Digest32, ask: &Ask, patience: Duration) -> Asking {
    let heard = || conn.quinn().stats().udp_rx.datagrams;
    let start = heard();
    // **Bounded as a whole**, opening the stream included: on a connection whose peer died
    // without a word, opening a stream waits on flow control for as long as the connection
    // lives.
    let asked = async {
        let (mut send, mut recv) = open_typed(conn, StreamKind::Admit).await?;
        write_frame(&mut send, &ask.to_frame()).await?;
        let frame = read_frame_within(&mut recv, MAX_ADMIT_FRAME, patience)
            .await?
            .ok_or(Error::Unreachable(
                "admit: the member closed the stream unanswered",
            ))?;
        let verdict = Verdict::from_frame(&frame)?;
        Ok::<_, Error>((Asked { member, send }, verdict))
    };
    tokio::pin!(asked);
    let t0 = tokio::time::Instant::now();
    let deadline = t0 + patience;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            answered = &mut asked => {
                return match answered {
                    Ok((a, v)) => Asking::Answered(a, v),
                    // The connection closed under it: the member is gone.
                    Err(_) if conn.quinn().close_reason().is_some() => Asking::Offline,
                    Err(_) if heard() == start => Asking::Offline,
                    Err(_) => Asking::Unanswered,
                };
            }
            _ = tick.tick() => {
                let _ = crate::node::net::probe(conn);
                if heard() == start && t0.elapsed() >= SILENT_IS_OFFLINE {
                    return Asking::Offline;
                }
                if tokio::time::Instant::now() >= deadline {
                    return if heard() == start { Asking::Offline } else { Asking::Unanswered };
                }
            }
        }
    }
}

/// **A member's side, before the actor decides**: read the asker's question.
///
/// # Errors
/// No well-formed question within [`ASK_PATIENCE`].
pub async fn read_ask(recv: &mut RecvStream) -> Result<Ask> {
    let frame = read_frame_within(recv, MAX_ADMIT_FRAME, ASK_PATIENCE)
        .await?
        .ok_or(Error::MalformedBundle(
            "admit: stream closed before the question",
        ))?;
    Ask::from_frame(&frame)
}

/// **A member's side, after the actor decided**: send the verdict, and, after a yes, wait for the
/// asker's decision. A closed stream, a malformed frame or no decision within
/// [`DECISION_PATIENCE`] is an abort: nothing was committed that this member heard of.
pub async fn answer(mut send: SendStream, mut recv: RecvStream, verdict: Verdict) -> Decision {
    if write_frame(&mut send, &verdict.to_frame()).await.is_err() || verdict != Verdict::Yes {
        let _ = send.finish();
        return Decision::Abort;
    }
    let decision = match read_frame_within(&mut recv, MAX_ADMIT_FRAME, DECISION_PATIENCE).await {
        Ok(Some(frame)) => Decision::from_frame(&frame).unwrap_or(Decision::Abort),
        _ => Decision::Abort,
    };
    let _ = send.finish();
    decision
}

/// Places held for joins in one room, as one member counts them (see the module docs).
#[derive(Debug, Default)]
pub struct Reservations {
    held: std::collections::HashMap<Digest32, Held>,
}

#[derive(Debug, Clone, Copy)]
struct Held {
    committed: bool,
    until: std::time::Instant,
}

impl Reservations {
    /// Forget what has run out, and what `is_author` says is now admitted (its place is counted
    /// as a member from now on).
    pub fn prune(&mut self, is_author: impl Fn(&Digest32) -> bool) {
        let now = std::time::Instant::now();
        self.held.retain(|n, h| h.until > now && !is_author(n));
    }

    /// How many places are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Whether a place is held for `newcomer`.
    #[must_use]
    pub fn holds(&self, newcomer: &Digest32) -> bool {
        self.held.contains_key(newcomer)
    }

    /// Hold a place for `newcomer` until a decision (or [`DECISION_PATIENCE`] and
    /// [`ASK_PATIENCE`]).
    pub fn hold(&mut self, newcomer: Digest32) {
        self.held.insert(
            newcomer,
            Held {
                committed: false,
                until: std::time::Instant::now() + ASK_PATIENCE + DECISION_PATIENCE,
            },
        );
    }

    /// Apply a decision for `newcomer`.
    pub fn decide(&mut self, newcomer: &Digest32, decision: Decision) {
        match decision {
            Decision::Abort => {
                self.held.remove(newcomer);
            }
            Decision::Commit => {
                if let Some(h) = self.held.get_mut(newcomer) {
                    h.committed = true;
                    h.until = std::time::Instant::now() + COMMITTED_FALLBACK;
                }
            }
        }
    }

    /// The verdict for one more place, `admitted` members in, the cap `cap`; holds a place on a
    /// yes. A newcomer already held for is a yes again (a repeated ask), not a second place. A
    /// committed place counts as a member: the room is full, not busy, when only those fill it.
    pub fn judge(&mut self, newcomer: Digest32, admitted: usize, cap: usize) -> Verdict {
        if let Some(h) = self.held.get_mut(&newcomer) {
            // Asked again while held: still a yes, and the wait starts over (a slow asker's own
            // place must not run out while it is still asking).
            if !h.committed {
                h.until = std::time::Instant::now() + ASK_PATIENCE + DECISION_PATIENCE;
            }
            return Verdict::Yes;
        }
        let committed = self.held.values().filter(|h| h.committed).count();
        let members = admitted + committed;
        if members >= cap {
            return Verdict::Full {
                members: members as u64,
                cap: cap as u64,
            };
        }
        if admitted + self.len() >= cap {
            return Verdict::Busy;
        }
        self.hold(newcomer);
        Verdict::Yes
    }
}
