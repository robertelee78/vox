//! Explicit old-format contiguous recovery through the same node-wide archive operation.
use super::*;
use crate::node::channel::{legacy_provisional::LegacyProvisionalOwner, LegacySync};

pub(super) struct LegacyDispatch {
    pub room: Digest32,
    pub instance: [u8; 16],
    pub peer: Digest32,
    pub request: RequestId,
    pub generation: Digest32,
    pub bounds: Bounds,
    pub plan: demand::LegacyPlan,
    pub staging: Staging,
    pub fence: Arc<Fence>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_legacy(
    room: &ChannelState,
    store: &Store,
    node: Digest32,
    instance: [u8; 16],
    action: Action,
    context: Arc<Context>,
    job: &Job,
    peers: Vec<Digest32>,
    mut answer: Prepared,
    saved: Option<&demand::State>,
    fence: Arc<Fence>,
) -> Result<Prepared, String> {
    let binding = Binding {
        room: room.channel_id(),
        instance,
        epoch: room.epoch(),
        audience: [0; 32],
        grant: answer.generation,
    };
    let (plan, bounds, active) = if let Action::Resume { request } = action {
        let Some(state) = saved else {
            answer.status.phase = Phase::Unavailable;
            answer.status.detail = "No legacy history request is saved to resume.".into();
            return Ok(answer);
        };
        if state.request != request {
            answer.status.phase = Phase::Unavailable;
            answer.status.detail =
                "The requested resume does not match the saved legacy history request.".into();
            return Ok(answer);
        }
        let plan = state
            .legacy
            .ok_or("The saved request is not legacy history.")?;
        let active = demand::resume(&context, request, binding, job).map_err(|e| e.to_string())?;
        (plan, state.bounds, active)
    } else {
        if saved.is_some_and(|state| {
            !matches!(
                state.progress(None),
                demand::Progress::Complete | demand::Progress::Cancelled
            ) || state.reclaiming()
        }) {
            answer.status.detail =
                "A saved history request exists. Resume or cancel it explicitly.".into();
            return Ok(answer);
        }
        let required = room
            .legacy_required_page(store, None, 1)
            .map_err(|e| e.to_string())?;
        let Some(required) = required.first() else {
            answer.status=status(room.channel_id(),instance,Phase::Cached,
                "No authenticated legacy prefix gap is currently known. Cached history remains available.");
            return Ok(answer);
        };
        let base = room
            .legacy_accepted_head(store, &required.author)
            .map_err(|e| e.to_string())?;
        let plan = demand::LegacyPlan {
            author: required.author,
            from: base.saturating_add(1),
            through: required.through,
            expected_base: base,
        };
        let bounds = Bounds {
            head: required.hash,
            lo: plan.from,
            hi: plan.through,
            entries: crate::log::sync::LEGACY_QUANTUM_ENTRIES,
        };
        let request = crate::identity::rng::random_array::<16>().map_err(|e| e.to_string())?;
        let active = demand::start_legacy(&context, request, binding, bounds, plan, job)
            .map_err(|e| e.to_string())?;
        (plan, bounds, active)
    };
    let request = active.request();
    // A publication-only Resume can proceed without a connected donor. The worker checks
    // its sealed cursor first; only a network quantum needs the selected peer online.
    let peer = peers
        .into_iter()
        .find(|peer| room.is_member(peer) && !room.has_left(peer))
        .unwrap_or(plan.author);
    answer.status = status(
        room.channel_id(),
        instance,
        Phase::Pending,
        "One explicit legacy recovery quantum is queued; further recovery requires Resume.",
    );
    answer.status.request = Some(request);
    answer.status.author = Some(plan.author);
    answer.status.head = Some(bounds.head);
    answer.status.remaining = usize::try_from(
        plan.through.saturating_sub(
            room.legacy_accepted_head(store, &plan.author)
                .map_err(|e| e.to_string())?,
        ),
    )
    .unwrap_or(usize::MAX);
    answer.status.headers = bounds.entries;
    answer.status.wire_bytes = crate::log::sync::LEGACY_QUANTUM_BYTES;
    answer.legacy = Some(LegacyDispatch {
        room: room.channel_id(),
        instance,
        peer,
        request,
        generation: answer.generation,
        bounds,
        plan,
        staging: Staging {
            context,
            active: Arc::new(StdMutex::new(active)),
        },
        fence,
    });
    let _ = node;
    Ok(answer)
}

fn lock_room<'a>(
    room: &'a Mutex<ChannelState>,
    fence: &Fence,
    deadline: std::time::Instant,
) -> Result<tokio::sync::MutexGuard<'a, ChannelState>, String> {
    loop {
        if fence.is_retired() || std::time::Instant::now() >= deadline {
            return Err("Legacy recovery paused or cancelled.".into());
        }
        if let Ok(guard) = room.try_lock() {
            if fence.is_retired() {
                return Err("Legacy recovery cancelled.".into());
            }
            return Ok(guard);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

impl Node {
    pub(super) fn start_legacy_history(&mut self, dispatch: LegacyDispatch) {
        let Some(profile) = self.profile.as_ref() else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Node locked; legacy recovery is paused.",
            );
            return;
        };
        let node = profile.fingerprint();
        let store = profile.store_handle();
        let Some(shared) = self.channels.get(&dispatch.room).cloned() else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Room closed; legacy recovery is paused.",
            );
            return;
        };
        let conn = self
            .net
            .as_ref()
            .and_then(|net| net.manager().existing(&dispatch.peer));
        let Some(job) = self.history_budget.try_start(node, Lane::Archive) else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Archive worker is busy; Resume later.",
            );
            return;
        };
        let Some(buffers) = job.reserve(crate::log::sync::LEGACY_BUFFER_ENVELOPE) else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Legacy record buffers are busy; Resume later.",
            );
            return;
        };
        let Some(slot) =
            crate::node::ports::Slots::take(&self.slots, dispatch.peer, Box::new(|| {}))
        else {
            self.history_demand.failed(
                dispatch.request,
                dispatch.generation,
                "Peer transfer slots are busy; Resume later.",
            );
            return;
        };
        let request = dispatch.request;
        let generation = dispatch.generation;
        let owner = LegacyProvisionalOwner {
            request,
            instance: dispatch.instance,
            author: dispatch.plan.author,
        };
        let legacy_owner = Some((dispatch.room, owner));
        let result = Arc::new(StdMutex::new(None));
        let output = result.clone();
        let tx = self.net_tx.clone();
        let now = self.now_ms();
        let handle = tokio::runtime::Handle::current();
        let task = tokio::spawn(async move {
            let progress_tx = tx.clone();
            let answer=tokio::task::spawn_blocking(move || {
                let _slot = slot;
                let buffers=Arc::new(buffers);
                let deadline=std::time::Instant::now()+std::time::Duration::from_secs(90);
                let context=dispatch.staging.context.clone();
                let active=dispatch.staging.active.clone();
                let sync=LegacySync { owner:LegacyProvisionalOwner{request,instance:dispatch.instance,author:dispatch.plan.author},
                    through:dispatch.plan.through,expected_head:dispatch.bounds.head,node,epoch:context_binding_epoch(&active)?,grant:generation };
                let work=(|| ->Result<Status,String> {
                    let local={let mut room=lock_room(&shared,&dispatch.fence,deadline)?;
                        room.prepare_legacy_sync(&store,sync,now).map_err(|e|e.to_string())?};
                    let report=if let Some(out)=local {
                        let mut room=lock_room(&shared,&dispatch.fence,deadline)?;
                        room.finish_legacy_sync(&store,sync).map_err(|e|e.to_string())?;
                        crate::node::channel::SessionReport{out,fail:None}
                    } else {
                        let conn=conn.ok_or("Legacy donor is offline; Resume after it reconnects.")?;
                        let transport=handle.block_on(async {
                            tokio::select! {biased;
                                ()=dispatch.fence.retired()=>Err(crate::error::Error::Profile("Legacy request cancelled")),
                                result=tokio::time::timeout(std::time::Duration::from_secs(20),
                                    crate::node::syncstream::open_sync(&conn,handle.clone(),&dispatch.room,sync.epoch))=>
                                    result.map_err(|_|crate::error::Error::Profile("Legacy donor did not answer"))?,
                            }
                        }).map_err(|e|e.to_string())?;
                        let mut transport=transport.fenced(dispatch.fence.clone()).charged(buffers.clone());
                        let on_stored=||{};
                        ChannelState::sync_over_room_mode(&shared,&store,dispatch.peer,&mut transport,now,
                            &dispatch.fence,&on_stored,Some(sync))
                    };
                    if report.out.applied > 0 || report.out.rendered > 0 || report.out.governance > 0 {
                        let _ = progress_tx.try_send(NetEvent::BoundedRoomAdvanced {
                            channel_id: dispatch.room,
                            rendered: report.out.rendered > 0,
                            governance: report.out.governance > 0,
                        });
                    }
                    if report.out.legacy_invalid {
                        demand::cancel(&context, request, &job).map_err(|e|e.to_string())?;
                        let _ = demand::reclaim(&context, request, &job).map_err(|e|e.to_string())?;
                        { let room=lock_room(&shared,&dispatch.fence,deadline)?;
                          let _ = room.cleanup_legacy_provisional(&store, sync.owner).map_err(|e|e.to_string())?; }
                        let saved=demand::inspect(&context,&job).map_err(|e|e.to_string())?.ok_or("Legacy request disappeared.")?;
                        let mut status=saved_status(saved.state(),Some(dispatch.plan.author),None);
                        status.detail="Legacy recovery cancelled: the selected signed feed reaches an invalid extension. Missing positions were not accepted as history; partial staging is being reclaimed.".into();
                        return Ok(status);
                    }
                    let (base,pending)={let room=lock_room(&shared,&dispatch.fence,deadline)?;
                        let state=room.legacy_provisional_state(&store).map_err(|e|e.to_string())?;
                        let pending=if state.is_some(){room.legacy_publication_progress(&store,sync.owner).map_err(|e|e.to_string())?.is_some()}else{false};
                        (room.legacy_accepted_head(&store,&dispatch.plan.author).map_err(|e|e.to_string())?,pending)};
                    let remaining=usize::try_from(dispatch.plan.through.saturating_sub(base)).map_err(|_|"Legacy interval is too large.")?;
                    let progress=if report.fail.is_some() || report.out.legacy_unavailable {demand::Progress::Unavailable}
                        else if remaining==0&&!pending{demand::Progress::Complete}else{demand::Progress::More};
                    let mut active=active.lock().map_err(|_|"Legacy history state poisoned.")?;
                    demand::checkpoint_legacy(&context,&mut active,&dispatch.plan,remaining,progress,&job).map_err(|e|e.to_string())?;
                    let saved=demand::inspect(&context,&job).map_err(|e|e.to_string())?.ok_or("Legacy request disappeared.")?;
                    let mut status=saved_status(saved.state(),Some(dispatch.plan.author),Some(&active));
                    status.wire_bytes=crate::log::sync::LEGACY_QUANTUM_BYTES;
                    let stopped = if report.out.legacy_unavailable {
                        "Legacy recovery unavailable: a signed feed entry cannot be classified. The required prefix remains unresolved. ".to_owned()
                    } else { report.fail.as_ref().map(|failure| format!("Legacy recovery paused: {failure}. ")).unwrap_or_default() };
                    status.detail=format!("{stopped}Received {} wire bytes; {} positions still need accepted history{}. {}",report.out.wire_received,remaining,if pending{"; signed publication or cleanup remains"}else{""},if progress==demand::Progress::Complete{"The selected interval is complete."}else{"Resume explicitly to continue."});
                    Ok(status)
                })();
                if work.is_err() {
                    // No secret-key work after lock. A locked/retired room's compact reopen
                    // path owns recovery; an unlocked room detaches only volatile staging.
                    if let Ok(mut room)=shared.try_lock() {let _=room.finish_legacy_sync(&store,sync);}
                }
                work
            }).await.unwrap_or_else(|_|Err("Legacy recovery worker stopped; progress remains paused.".into()));
            if let Ok(mut slot) = output.lock() {
                *slot = Some(answer);
            }
            let _ = tx.try_send(NetEvent::HistoryDemandPrepared { token: 0 });
        });
        self.history_demand.private_work = Some(PrivateWork {
            legacy_owner,
            result,
            request,
            generation,
            task,
        });
    }
}

fn context_binding_epoch(active: &Arc<StdMutex<demand::Active>>) -> Result<u64, String> {
    active
        .lock()
        .map(|active| active.binding().epoch)
        .map_err(|_| "Legacy history state poisoned.".into())
}
