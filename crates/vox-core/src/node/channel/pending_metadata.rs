//! Compact known-member component persistence for the original join continuation.
use super::*;
use crate::atrest::sek::WeakSek;

pub(crate) struct Prepared {
    room: Digest32,
    epoch: u64,
    owner: Arc<()>,
    sek: WeakSek,
    members: Option<BTreeSet<Digest32>>,
    add: Vec<Digest32>,
}
pub(crate) struct Completed {
    pending: Prepared,
    result: Result<()>,
    poison: bool,
}

impl ChannelState {
    /// These two metadata components cannot change saved history. Reserve the ordinary owner
    /// without reading/pinning unrelated history or introducing a new failure into best effort.
    pub(crate) fn reserve_pending_metadata(&mut self, owner: Arc<()>) -> Result<()> {
        if self.post_pending() {
            return Err(Error::Profile(
                "room publication is busy; retry this operation",
            ));
        }
        self.pending_text = Some(owner);
        Ok(())
    }

    pub(crate) fn metadata_write_owned(&self, room: Digest32, epoch: u64, owner: &Arc<()>) -> bool {
        self.channel_id == room
            && self.epoch == epoch
            && self
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn prepare_pending_known_members(
        &mut self,
        _store: &Arc<Store>,
        owner: Arc<()>,
        mut members: Vec<Digest32>,
    ) -> Result<Prepared> {
        self.reserve_pending_metadata(Arc::clone(&owner))?;
        members.retain(|member| !self.is_author(member) && !self.known_members.contains(member));
        let known = (!members.is_empty()).then(|| self.known_members.clone());
        Ok(Prepared {
            room: self.channel_id,
            epoch: self.epoch,
            owner,
            sek: self.sek.reader(),
            members: known,
            add: members,
        })
    }
}
impl Prepared {
    pub(crate) fn run(mut self, store: &Store) -> Completed {
        let add = std::mem::take(&mut self.add);
        let Some(members) = self.members.as_mut() else {
            return Completed {
                pending: self,
                result: Ok(()),
                poison: false,
            };
        };
        let mut poison = false;
        let result = self.sek.with(|sek| {
            for member in add {
                if !members.insert(member) {
                    continue;
                }
                let segment = seal_segment(
                    sek,
                    SegmentKind::KeyMaterial,
                    SEG_KNOWN_MEMBERS,
                    &known_members_bytes(members),
                )?;
                if let Err(error) = store.put_segment_derived(
                    &self.room,
                    SegmentKind::KeyMaterial,
                    SEG_KNOWN_MEMBERS,
                    &segment,
                ) {
                    poison = true;
                    return Err(error);
                }
            }
            Ok(())
        });
        Completed {
            pending: self,
            result,
            poison,
        }
    }
}
impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        None
    }
    pub(crate) fn finish(self, channel: &mut ChannelState) -> Result<()> {
        if self.can_install(channel, &self.pending.owner) {
            // note_member inserted before attempting its derived write. Preserve that exact
            // failure projection, including poisoning, rather than pretending it never happened.
            if let Some(members) = self.pending.members {
                channel.known_members = members;
            }
            if self.poison {
                if let Err(error) = &self.result {
                    channel.poisoned = true;
                    channel.save_error = Some(error.to_string());
                }
            }
            channel.release_pending_text(&self.pending.owner, false);
        }
        self.result
    }
    pub(crate) fn into_result(self) -> Result<()> {
        self.result
    }
}
