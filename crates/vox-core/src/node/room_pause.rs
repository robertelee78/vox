//! ADR-033 pause/resume foundation: bounded current roster, saved receiver state and explicit
//! per-target outcomes. Consumers perform one user action by streaming all continuation pages.

use crate::hash::Digest32;
use crate::node::ipc::{Frame, IpcClient, NodeSocket, Request};
use vox_agentcomms::drive::{Action, PauseReport, PauseSelection, PauseState};

/// One captured actor and saved room. Members are the existing bounded current roster, not
/// every author or Session in retained history. New members require a new user selection.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Selected local actor.
    pub actor: Digest32,
    /// Exact room.
    pub room: Digest32,
    /// Existing driver-local saved room instance.
    pub instance: [u8; 16],
    /// All current members at selection, including this node.
    pub members: Vec<Digest32>,
}

/// A target which was not confirmed changed. An unknown outcome must never be called refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The authenticated receiver refused it; its state was not changed by this request.
    Refused(String),
    /// No pause request was sent.
    NotSent(String),
    /// The request may have committed; an acknowledgment was not received or understood.
    Unknown(String),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(s) | Self::NotSent(s) | Self::Unknown(s) => f.write_str(s),
        }
    }
}

/// Capture the current roster and room instance without reading Session history.
///
/// # Errors
/// The selected node/room is unavailable, changed during capture, or cannot supply its roster.
pub async fn capture(at: &NodeSocket, room: Digest32) -> Result<Selection, String> {
    let mut client = IpcClient::open_at(at).await.map_err(|e| e.to_string())?;
    let actor = client.me().ok_or("the selected node is locked")?;
    let instance = head(&mut client, room).await?;
    let members = match client
        .request(&Request::Roster { channel_id: room })
        .await
        .map_err(|e| e.to_string())?
    {
        Frame::Members { members } => members,
        Frame::Error { reason } => return Err(reason),
        _ => return Err("unexpected room roster answer".into()),
    };
    if members.len() > crate::node::channel::AUTHORS_HARD_LIMIT
        || head(&mut client, room).await? != instance
    {
        return Err("the room selection changed; refresh and retry".into());
    }
    Ok(Selection {
        actor,
        room,
        instance,
        members,
    })
}
async fn head(client: &mut IpcClient, room: Digest32) -> Result<[u8; 16], String> {
    match client
        .request(&Request::ArrivalHead { channel_id: room })
        .await
        .map_err(|e| e.to_string())?
    {
        Frame::ArrivalHead { head } => Ok(head.instance),
        Frame::Error { reason } => Err(reason),
        _ => Err("unexpected room instance answer".into()),
    }
}

/// Change one target and deliver one bounded page of Esc interrupts. Continue `report.next`
/// transparently with the same `report.selection`; resume/status never have a continuation.
///
/// # Errors
/// A per-target refusal, unsent request, or unknown outcome, kept distinct.
pub async fn change(
    at: &NodeSocket,
    selected: &Selection,
    peer: Digest32,
    paused: bool,
    continuation: Option<(String, PauseSelection)>,
) -> Result<PauseReport, Failure> {
    if !selected.members.contains(&peer) {
        return Err(Failure::NotSent(
            "the target was not in the selected room roster".into(),
        ));
    }
    let (after, expected) = match continuation {
        Some((after, expected)) => (Some(after), Some(expected)),
        None => (None, None),
    };
    request(
        at,
        selected.room,
        peer,
        Some(paused),
        after,
        expected,
        Some((selected.actor, selected.instance)),
    )
    .await
}

/// Read the receiver's durable current state. This is a metadata read, not a drive operation;
/// the authenticated app gate determines which trusted room members may ask it.
///
/// # Errors
/// The current receiver cannot be queried; callers must retain known state as stale, not resume.
pub async fn status(
    at: &NodeSocket,
    room: Digest32,
    peer: Digest32,
) -> Result<PauseState, Failure> {
    Ok(request(at, room, peer, None, None, None, None)
        .await?
        .selection
        .state)
}

async fn request(
    at: &NodeSocket,
    room: Digest32,
    peer: Digest32,
    paused: Option<bool>,
    after: Option<String>,
    expected: Option<PauseSelection>,
    selected: Option<(Digest32, [u8; 16])>,
) -> Result<PauseReport, Failure> {
    let request = vox_agentcomms::drive::Request {
        v: 1,
        session: String::new(),
        action: Action::RoomPause {
            paused,
            after: after.clone(),
            expected,
        },
    };
    let answer = crate::node::drive_input::send_checked(at, room, peer, &request, selected)
        .await
        .map_err(|e| match e {
            crate::node::drive_input::Unsent::Unreachable(s) => Failure::NotSent(s),
            crate::node::drive_input::Unsent::NoAnswer(s) => Failure::Unknown(s),
        })?;
    if answer.said.len() > 4096 {
        return Err(Failure::Unknown(
            "the receiver's reason exceeds the room-pause answer bound; its state is not confirmed"
                .into(),
        ));
    }
    if answer.code.as_deref() == Some(vox_agentcomms::drive::PAUSE_UNKNOWN) {
        return Err(Failure::Unknown(answer.said));
    }
    if !answer.ok {
        return Err(Failure::Refused(
            answer.said_to(&crate::node::link::b32_encode(&peer)),
        ));
    }
    let report = answer.pause.ok_or_else(|| {
        Failure::Unknown("the receiver did not acknowledge a saved room pause state".into())
    })?;
    if report.interrupts.len() > vox_agentcomms::drive::PAUSE_PAGE
        || report.interrupts.iter().any(|i| {
            i.session.len() > crate::node::content::MAX_SESSION_ID_LEN || i.said.len() > 4096
        })
        || report
            .interrupt_error
            .as_ref()
            .is_some_and(|e| e.len() > 4096)
        || report
            .next
            .as_ref()
            .is_some_and(|next| next.len() > crate::node::content::MAX_SESSION_ID_LEN)
        || report
            .next
            .as_ref()
            .is_some_and(|next| after.as_ref().is_some_and(|after| next <= after))
        || paused.is_some_and(|wanted| report.selection.state.paused != wanted)
        || expected.is_some_and(|expected| report.selection != expected)
        || (paused != Some(true) && (report.next.is_some() || !report.interrupts.is_empty()))
    {
        return Err(Failure::Unknown(
            "the receiver's pause acknowledgment is inconsistent; refresh its current state".into(),
        ));
    }
    Ok(report)
}
