//! Computer removals reuse each room's existing governance continuation and member-removal command.
use super::*;

impl Node {
    pub(super) async fn resume_computer_room_removals(&mut self, room: Digest32) {
        let Some(computer) = self.computer.clone() else {
            return;
        };
        if !computer.has_pending_room_removals() {
            return;
        }
        let Some(profile) = &self.profile else {
            return;
        };
        let me = profile.fingerprint();
        let store = profile.store_handle();
        let rooms = match store.channels() {
            Ok(rooms) => rooms,
            Err(_) => {
                self.retry_computer_room_removal(room);
                return;
            }
        };
        let captured = computer.clone();
        if !matches!(
            tokio::task::spawn_blocking(move || captured.capture_removal_rooms(me, &rooms)).await,
            Ok(Ok(()))
        ) {
            self.retry_computer_room_removal(room);
            return;
        }
        let Some(instance) = self.channels.get(&room).cloned() else {
            return;
        };
        let rows = match computer.room_removals(me, room) {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!("vox: computer room removals could not be read: {error}");
                self.retry_computer_room_removal(room);
                return;
            }
        };
        for (event, index, row) in rows {
            #[cfg(feature = "test-knobs")]
            if hold_removal_for_proof(&row.room, false) {
                self.retry_computer_room_removal(room);
                continue;
            }
            let done = {
                let channel = instance.lock().await;
                if !channel.trust_reconciled(self.trust_generation) {
                    self.retry_computer_room_removal(room);
                    return;
                }
                match channel.is_member_removed(&store, &row.member) {
                    Ok(true) => true,
                    Ok(false) => !channel.is_member(&row.member),
                    Err(_) => {
                        self.retry_computer_room_removal(room);
                        return;
                    }
                }
            };
            if done {
                #[cfg(feature = "test-knobs")]
                if let Ok(path) = std::env::var("VOX_TEST_HOLD_COMPUTER_EVICTION") {
                    let _ = std::fs::write(
                        std::path::Path::new(&path).with_extension("observed"),
                        crate::node::link::b32_encode(&room),
                    );
                }
                #[cfg(feature = "test-knobs")]
                if hold_removal_for_proof(&row.room, true) {
                    self.retry_computer_room_removal(room);
                    continue;
                }
                #[cfg(feature = "test-knobs")]
                if crate::node::computer::fx28_mutant("do-not-record-already-gone") {
                    continue;
                }
                let computer = computer.clone();
                match tokio::task::spawn_blocking(move || {
                    computer.finish_room_removal(event, index, None)
                })
                .await
                {
                    Ok(Ok(())) => {}
                    result => {
                        eprintln!(
                            "vox: computer room removal completion was not saved: {result:?}"
                        );
                        self.retry_computer_room_removal(room);
                    }
                }
                continue;
            }
            let authority = {
                let channel = instance.lock().await;
                match channel.validate_member_removal(&store, &me, &row.member, self.now_ms()) {
                    Ok(()) => None,
                    Err(Error::Profile("room policy authority required"
                        | "this admin delegation has an expiry and cannot remove members; ask the room creator"
                        | "the room creator cannot be removed")) => {
                        Some(channel.genesis().creator_pubkey().fingerprint())
                    }
                    Err(_) => {
                        self.retry_computer_room_removal(room);
                        continue;
                    }
                }
            };
            if let Some(creator) = authority {
                if row.command_node != creator {
                    let computer = computer.clone();
                    if !matches!(
                        tokio::task::spawn_blocking(move || {
                            computer.finish_room_removal(event, index, Some(creator))
                        })
                        .await,
                        Ok(Ok(()))
                    ) {
                        self.retry_computer_room_removal(room);
                    }
                }
                continue;
            }
            if self.pending_posts.contains_key(&room) {
                self.retry_computer_room_removal(room);
                continue;
            }
            // The existing one-second governance deadline also covers a rejected send or
            // reply. Success is reconciled from the committed roster, not a task's verdict.
            self.retry_computer_room_removal(room);
            if let Some(sender) = self.command_sender.upgrade() {
                let (reply, received) = oneshot::channel();
                if sender
                    .try_send((
                        NodeCommand::RemoveRoomMember {
                            channel_id: room,
                            member: row.member,
                        },
                        reply,
                    ))
                    .is_ok()
                {
                    tokio::spawn(async move {
                        let _ = received.await;
                    });
                }
            }
            break;
        }
    }
    pub(super) fn retry_computer_room_removal(&mut self, room: Digest32) {
        let retry = self
            .now_ms()
            .0
            .saturating_add(ROOM_RETRY.as_millis() as u64);
        let next = self
            .governance_work
            .deadlines
            .get(&room)
            .map_or(retry, |at| (*at).min(retry));
        self.governance_work.set_deadline(room, Some(next));
    }
}

#[cfg(feature = "test-knobs")]
fn hold_removal_for_proof(room: &Digest32, after: bool) -> bool {
    let Ok(path) = std::env::var("VOX_TEST_HOLD_COMPUTER_EVICTION") else {
        return false;
    };
    let path = std::path::Path::new(&path);
    let expected = format!(
        "{}\t{}",
        crate::node::link::b32_encode(room),
        if after { "after" } else { "before" }
    );
    if std::fs::read_to_string(path).ok().as_deref() != Some(expected.as_str()) {
        return false;
    }
    let _ = std::fs::write(path.with_extension("engaged"), expected);
    true
}
impl Node {
    pub(super) fn capture_room_offer_boundary(
        &self,
        channel: &ChannelState,
        store: &crate::node::store::Store,
    ) -> crate::error::Result<bool> {
        let Some(computer) = &self.computer else {
            return Ok(true);
        };
        let room = channel.channel_id();
        let me = channel.me();
        if !computer.offer_boundaries_owed(me, &[room]) {
            return Ok(true);
        }
        computer.capture_offer_boundaries(
            me,
            &store.channels()?,
            &[(room, channel.offer_bases(store)?)],
        )
    }
    pub(super) async fn capture_open_computer_offer_boundaries(
        &mut self,
    ) -> crate::error::Result<()> {
        let (Some(profile), Some(computer)) = (&self.profile, &self.computer) else {
            return Ok(());
        };
        let me = profile.fingerprint();
        let store = profile.store_handle();
        let known = store.channels()?;
        if !computer.offer_boundaries_owed(me, &known) {
            return Ok(());
        }
        let mut captured = Vec::new();
        for (room, instance) in &self.channels {
            let channel = instance.lock().await;
            captured.push((*room, channel.offer_bases(&store)?));
        }
        if !computer.capture_offer_boundaries(me, &known, &captured)? {
            return Err(Error::Profile(
                "computer offer boundaries wait for its current save; retry this operation",
            ));
        }
        Ok(())
    }
}
