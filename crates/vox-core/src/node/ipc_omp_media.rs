//! Connection-scoped, exact-activity OMP image paging.

use super::{Frame, Request};
use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::channel::session_projection::{ActivityQuery, ActivityReply, Query, Reply};
use crate::node::drive::SessionFilter;
use crate::node::shares::media::{self, Descriptor};
use std::sync::{Arc, LazyLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

static CACHED: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8)));

#[derive(Clone, PartialEq, Eq)]
struct Selection {
    room: Digest32,
    node: Digest32,
    session: String,
    opening: Digest32,
    entry: Digest32,
    instance: [u8; 16],
}

#[derive(PartialEq, Eq)]
struct Offer {
    tag: String,
    descriptor: Descriptor,
    generation: u64,
}

struct Held {
    selection: Selection,
    offer: Offer,
    bytes: Vec<u8>,
    offset: usize,
    cursor: String,
    /// The owner's room-removal generation this transfer was admitted under (own: unused).
    authority: u64,
    /// This node's own cheap room/instance/lock check, rechecked before every later page.
    current: Arc<dyn Fn() -> bool + Send + Sync>,
    _slot: OwnedSemaphorePermit,
}

#[derive(Default)]
pub(super) struct Cache(Option<Held>);

fn token() -> Result<String, String> {
    use std::fmt::Write as _;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|e| e.to_string())?;
    let mut result = String::with_capacity(32);
    for b in random {
        let _ = write!(result, "{b:02x}");
    }
    Ok(result)
}

async fn authorized(handle: &NodeHandle, selection: &Selection) -> Result<Offer, String> {
    let Reply::Page { rows, revision, .. } = super::session_projection(
        handle,
        selection.room,
        Query::Exact {
            node: selection.node,
            id: selection.session.clone(),
        },
    )
    .await?
    else {
        return Err("unexpected Session selection".into());
    };
    if revision.provisional() || revision.refreshing().contains(&selection.node) {
        return Err("the Session authority is refreshing".into());
    }
    let Some(session) = rows.first() else {
        return Err("the Session is unavailable".into());
    };
    let me = handle
        .view()
        .identity
        .as_ref()
        .map(|identity| identity.fingerprint);
    if rows.len() != 1
        || session.opening != selection.opening
        || !session.open
        || (me != Some(selection.node) && !session.can_drive)
    {
        return Err("the exact Session is no longer authorized".into());
    }
    let ActivityReply::Selected(plan) = handle
        .session_activity(
            selection.room,
            ActivityQuery::Select {
                which: SessionFilter::Entries {
                    node: selection.node,
                    session_id: selection.session.clone(),
                    entries: vec![selection.entry],
                    instance: selection.instance,
                },
                before: None,
                max_rows: 1,
                max_bytes: super::rows_budget(),
                revision: None,
            },
        )
        .await?
    else {
        return Err("unexpected Session activity selection".into());
    };
    if plan.provisional() || plan.refreshing().contains(&selection.node) || plan.origins.len() != 1
    {
        return Err("the image activity is unavailable".into());
    }
    let arrival = plan.origins[0];
    let ActivityReply::Row(row) = handle
        .session_activity(selection.room, ActivityQuery::Row { plan, arrival })
        .await?
    else {
        return Err("unexpected Session activity".into());
    };
    if row.entry_hash != selection.entry
        || row.author != selection.node
        || row.session_id != selection.session
    {
        return Err("the image does not belong to this Session".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(&row.body).map_err(|_| "invalid media activity")?;
    if value.get("kind").and_then(serde_json::Value::as_str) != Some("omp-media") {
        return Err("the selected activity is not OMP media".into());
    }
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("media activity has no {name}"))
    };
    let offer = Offer {
        tag: field("tag")?,
        descriptor: Descriptor {
            id: field("media_id")?,
            mime: field("mime")?,
            size: value
                .get("size")
                .and_then(serde_json::Value::as_u64)
                .ok_or("media activity has no size")?,
            sha256: field("sha256")?,
        },
        generation: value
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or("media activity has no generation")?,
    };
    offer.descriptor.validate()?;
    Ok(offer)
}

impl Cache {
    pub(super) async fn page(
        &mut self,
        handle: &NodeHandle,
        request: &Request,
    ) -> Result<Frame, String> {
        let Request::OmpMedia {
            channel_id,
            node,
            session_id,
            opening,
            entry,
            instance,
            cursor,
        } = request
        else {
            return Err("not a media request".into());
        };
        if session_id.is_empty()
            || session_id.len() > crate::node::content::MAX_SESSION_ID_LEN
            || cursor.as_ref().is_some_and(|cursor| cursor.len() != 32)
        {
            self.0 = None;
            return Err("invalid Session media selection".into());
        }
        let selection = Selection {
            room: *channel_id,
            node: *node,
            session: session_id.clone(),
            opening: *opening,
            entry: *entry,
            instance: *instance,
        };
        if let Some(cursor) = cursor {
            // A later page of an admitted transfer: this node's cheap room check, then the
            // owner's pinned-generation check. Neither re-reads activity, record or bytes.
            let Some(held) = self.0.as_ref().filter(|held| {
                held.selection == selection && held.cursor == *cursor && (held.current)()
            }) else {
                self.0 = None;
                return Err("the media cursor is stale".into());
            };
            if let Err(error) = media::probe(
                handle,
                selection.room,
                selection.node,
                &held.offer.tag,
                &held.offer.descriptor,
                held.authority,
            )
            .await
            {
                self.0 = None;
                return Err(error);
            }
        } else {
            self.0 = None;
            let offer = authorized(handle, &selection).await?;
            let slot = CACHED
                .clone()
                .try_acquire_owned()
                .map_err(|_| "too many retained media transfers".to_owned())?;
            let check_handle = handle.clone();
            let check = selection.clone();
            let current: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
                let view = check_handle.view();
                !view.locked
                    && !view.locking
                    && view.identity.is_some()
                    && view.open_channels.iter().any(|room| {
                        room.channel_id == check.room
                            && room.history_instance == check.instance
                            && room.members.contains(&check.node)
                    })
            });
            if !current() {
                return Err("the media room is no longer current".into());
            }
            let own = handle
                .view()
                .identity
                .as_ref()
                .map(|identity| identity.fingerprint)
                == Some(selection.node);
            let (bytes, authority) = if own {
                let bytes = media::fetch_local(
                    selection.room,
                    selection.node,
                    &offer.tag,
                    &offer.descriptor,
                )
                .await?;
                (bytes, 0)
            } else {
                media::fetch(
                    handle,
                    selection.room,
                    selection.node,
                    &offer.tag,
                    &offer.descriptor,
                    selection.entry,
                    Arc::clone(&current),
                )
                .await?
            };
            if authorized(handle, &selection).await? != offer {
                return Err("media activity changed".into());
            }
            self.0 = Some(Held {
                selection: selection.clone(),
                offer,
                bytes,
                offset: 0,
                cursor: token()?,
                authority,
                current,
                _slot: slot,
            });
        }
        let held = self.0.as_mut().ok_or("media transfer is unavailable")?;
        let end = held
            .offset
            .saturating_add(super::frame_limit().saturating_sub(512).min(64 * 1024))
            .min(held.bytes.len());
        let bytes = held.bytes[held.offset..end].to_vec();
        held.offset = end;
        if end == held.bytes.len() {
            self.0 = None;
            Ok(Frame::OmpMedia {
                bytes,
                cursor: None,
            })
        } else {
            held.cursor = token()?;
            Ok(Frame::OmpMedia {
                bytes,
                cursor: Some(held.cursor.clone()),
            })
        }
    }
}
