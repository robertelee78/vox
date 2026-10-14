//! The tasks an attached node runs beside its actor (ADR-026 L-2): the notifier,
//! and the interrupt path (wake, ping and tend). Each is cancellable, so a node can be detached
//! without stopping the daemon: [`NodeTasks::stop`] ends them before the node's own stop.
//!
//! Manual anchor refresh belongs to the daemon's machine registry, rather than these node tasks.

use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use vox_core::node::actor::NodeHandle;
use vox_core::node::paths::Paths;

/// The tasks of one attached node, and the token that ends them.
pub struct NodeTasks {
    cancel: CancellationToken,
    set: tokio::task::JoinSet<()>,
}

impl NodeTasks {
    /// Start `node`'s tasks on `rt`: the notifier, and the interrupt path.
    #[must_use]
    pub fn start(rt: &Handle, node: &NodeHandle, paths: &Paths) -> Self {
        let cancel = CancellationToken::new();
        let mut set = tokio::task::JoinSet::new();
        let mut spawn = |task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>| {
            let cancel = cancel.clone();
            set.spawn_on(
                async move {
                    tokio::select! {
                        () = cancel.cancelled() => {}
                        () = task => {}
                    }
                },
                rt,
            );
        };
        // Tell the operator when `vox status` would flag something, and when it clears
        // (PRD-001 R37). Off with `notify = off` in the profile's config file.
        spawn(Box::pin(crate::notify::watch(node.clone(), paths.clone())));
        spawn(Box::pin(watch_for_interrupts(node.clone(), paths.clone())));
        Self { cancel, set }
    }

    /// End every task and wait for each to finish. A task ends at its next await once cancelled;
    /// a wake already handed to its own task (`deliver`) runs to its own deadline.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        while self.set.join_next().await.is_some() {}
    }
}

/// **The interrupt path (ADR-020 §6).** The daemon is the only thing that sees
/// every entry as it lands and also knows which local sessions exist, so it is
/// where "addressed and urgent" turns into a wake. The rule is deliberately
/// narrow: a message interrupts only if it names this node *and* is marked
/// urgent. Everything else waits for the next turn, because an interrupt that
/// fires on everything is a queue with worse manners.
///
/// **An event is a wake, never the data** (ADR-020 §6; ADR-021 F15). The node emits
/// `NewEntry` only for its OWN appends. An entry that arrives from another member is
/// announced as `Synced`, and one made readable by a sender key as
/// `SenderKeyReceived` — neither carries the row. This loop used to act on `NewEntry`
/// alone, so an urgent message from an agent on ANOTHER machine — the case the
/// interrupt path exists for — could never interrupt anybody. So every room is swept
/// for rows this loop has not yet judged: on those events, on `Lagged`, and on a
/// two-second tick, so a view that had not yet published a row when its event arrived
/// is caught on the next sweep rather than missed for good.
async fn watch_for_interrupts(node: NodeHandle, paths: Paths) {
    let mut events = node.subscribe();
    // Keep one arrival high-water mark per room, never one hash per message.
    let history = node.history_reader();
    let mut swept = std::collections::HashMap::new();
    let mut opening = std::collections::HashSet::new();
    for d in &node.view().open_channels {
        match history.arrival_head(d.channel_id).await {
            Ok(last) => {
                swept.insert(d.channel_id, last);
            }
            Err(e) => {
                eprintln!("vox daemon: could not establish the room's wake cursor: {e}");
                opening.insert(d.channel_id);
            }
        }
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    // The rooms where an answer to anything landed since the last look: a session there
    // may now be owed a reply's notice (V030-20).
    let mut answered: std::collections::HashSet<vox_core::hash::Digest32> =
        std::collections::HashSet::new();
    let mut tending = Tending {
        starting: true,
        ..Tending::default()
    };
    let deaf = wake_deaf();
    // Each room whose retention this node's own file asks to exceed, as said (V030-32): said
    // once, from the event or from the view, whichever comes first. The view is the record: the
    // event reaches no subscriber started after it (a room opened before this loop subscribed)
    // nor one that fell behind, and the notice is said all the same.
    let mut said_above: std::collections::HashMap<vox_core::hash::Digest32, (u64, u64)> =
        std::collections::HashMap::new();
    say_retention_above_room(&node.view(), &mut said_above, &paths);
    // Counted at once, not at the first tick.
    if !deaf {
        tend(&paths, &history, &node.view(), &answered, &mut tending).await;
    }
    loop {
        let sweep = tokio::select! {
            item = events.next() => match item {
                None => break,
                Some(vox_core::node::actor::EventStreamItem::Lagged(n)) => {
                    eprintln!("vox daemon: node {} fell behind its events by {n}; re-reading every room", paths.profile_dir.file_name().unwrap_or_default().to_string_lossy());
                    true
                }
                Some(vox_core::node::actor::EventStreamItem::Event(ev)) => {
                    // **A daemon is the node nobody is watching, so it has to say
                    // things out loud** — unreachable peers, refused publishes,
                    // stalls — which `vox node` has always reported.
                    match &ev {
                        vox_core::node::api::NodeEvent::RetentionAboveRoom {
                            channel_id,
                            node: asked,
                            room,
                        } => {
                            if said_above.insert(*channel_id, (*asked, *room)) != Some((*asked, *room)) {
                                crate::tunnel_cli::say_failure_for_node(&ev, paths.profile_dir.file_name().and_then(|n| n.to_str()));
                            }
                        }
                        other => crate::tunnel_cli::say_failure_for_node(
                            other, paths.profile_dir.file_name().and_then(|n| n.to_str()),
                        ),
                    }
                    match ev {
                        vox_core::node::api::NodeEvent::NewEntry { channel_id, row } => {
                            // The ordinary path rereads the committed arrival once. The test-only
                            // deaf path still answers local pings, as it did before.
                            if deaf && crate::ping::is_ping(&row.text) {
                                crate::ping::answer(&node, &paths, &node.view(), channel_id, &row);
                            }
                            true
                        }
                        vox_core::node::api::NodeEvent::Synced { .. }
                        | vox_core::node::api::NodeEvent::SenderKeyReceived { .. } => true,
                        _ => false,
                    }
                }
            },
            _ = tick.tick() => true,
        };
        if sweep {
            say_retention_above_room(&node.view(), &mut said_above, &paths);
        }
        if sweep && !deaf {
            let view = node.view();
            swept.retain(|room, _| view.channels.iter().any(|c| c.channel_id == *room));
            opening.retain(|room| view.channels.iter().any(|c| c.channel_id == *room));
            for d in &view.open_channels {
                if opening.contains(&d.channel_id) {
                    match history.arrival_head(d.channel_id).await {
                        Ok(last) => {
                            swept.insert(d.channel_id, last);
                            opening.remove(&d.channel_id);
                        }
                        Err(e) => {
                            eprintln!("vox daemon: could not establish the room's wake cursor: {e}")
                        }
                    }
                    continue;
                }
                let cursor = swept.get(&d.channel_id).copied();
                let page = match history.arrival_page(d.channel_id, cursor, 64).await {
                    Ok(page) => page,
                    Err(e) => {
                        eprintln!("vox daemon: could not read room notices; will retry: {e}");
                        continue;
                    }
                };
                for row in page.rows {
                    if may_wake(&row.text) {
                        if let Err(e) = judge(&paths, &history, &view, &d.channel_id, &row).await {
                            eprintln!("vox daemon: could not judge room notice; will retry: {e}");
                            break;
                        }
                    }
                    if crate::ping::is_ping(&row.text) {
                        crate::ping::answer(&node, &paths, &view, d.channel_id, &row);
                    }
                    if may_answer(&row.text) {
                        answered.insert(d.channel_id);
                    }
                    swept.insert(
                        d.channel_id,
                        vox_core::node::api::HistoryCursor {
                            instance: page.instance,
                            arrival: row.arrival,
                        },
                    );
                }
            }
            tend(&paths, &history, &view, &answered, &mut tending).await;
            answered.clear();
        }
    }
}

/// Say, once each, every room whose retention this node's own file asks to exceed (V030-32).
fn say_retention_above_room(
    view: &vox_core::node::api::NodeView,
    said: &mut std::collections::HashMap<vox_core::hash::Digest32, (u64, u64)>,
    paths: &Paths,
) {
    said.retain(|room, _| {
        view.open_channels
            .iter()
            .any(|d| d.channel_id == *room && d.retention_above_room.is_some())
    });
    for d in &view.open_channels {
        if let Some((asked, room)) = d.retention_above_room {
            if said.insert(d.channel_id, (asked, room)) != Some((asked, room)) {
                crate::tunnel_cli::say_failure_for_node(
                    &vox_core::node::api::NodeEvent::RetentionAboveRoom {
                        channel_id: d.channel_id,
                        node: asked,
                        room,
                    },
                    paths.profile_dir.file_name().and_then(|n| n.to_str()),
                );
            }
        }
    }
}

/// **Test-only: a wake loop that judges and sends nothing** (V030-31, #368), read from
/// `VOX_TEST_WAKE_DEAF=1` in a build with the `test-knobs` feature; no shipped build reads it
/// (V210-105). It stages the one window the startup count guards: an urgent row in the node's
/// store that the wake loop never looked at before the daemon was killed. Rows still land and are
/// stored; only the loop's judging and sending are off, and the daemon says so at start.
fn wake_deaf() -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var("VOX_TEST_WAKE_DEAF").is_ok_and(|v| v.trim() == "1") {
        eprintln!(
            "vox daemon: test-knobs: the wake loop judges and sends nothing (VOX_TEST_WAKE_DEAF)"
        );
        return true;
    }
    false
}

/// How long one wake may take before it is abandoned.
const WAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `text` is an envelope that could interrupt anyone at all: urgent and addressed.
/// Checked before the node's view is copied, so the common message costs no copy.
fn may_wake(text: &str) -> bool {
    vox_agentcomms::envelope::Envelope::parse(text).is_ok_and(|e| e.urgent && !e.to.is_empty())
}

/// Whether `text` is an envelope that answers an earlier one: it may be a reply some session is
/// owed a notice for (V030-20).
fn may_answer(text: &str) -> bool {
    vox_agentcomms::envelope::Envelope::parse(text).is_ok_and(|e| e.re.is_some())
}

/// The interrupt decision for one entry that just landed in `channel_id`: when it addresses
/// this node and is marked urgent (ADR-020 §6), and has hops left (§9), every session registered
/// in this room on this node but the one that posted it, and but one already in its reply chain
/// (V210-121), is owed a notice. [`tend`] sends it. Other rooms cannot interrupt the session.
///
/// `view` is the node's view as the entry is judged: the room's log, for the hop budget and the
/// reply chain.
async fn judge(
    paths: &vox_core::node::paths::Paths,
    history: &vox_core::node::actor::HistoryReader,
    view: &vox_core::node::api::NodeView,
    channel_id: &vox_core::hash::Digest32,
    row: &vox_core::node::api::MessageRow,
) -> Result<(), String> {
    let Ok(envelope) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
        return Ok(());
    };
    if !envelope.urgent || envelope.to.is_empty() {
        return Ok(());
    }
    let room = vox_core::node::link::b32_encode(channel_id);
    // **A message with no hops left interrupts nobody** (ADR-020 §9, V210-79): the budget
    // is the only loop guard that provably ends an urgent reply chain. It still queues.
    let context = reply_context(history, *channel_id, &envelope).await?;
    if context.hops == 0 {
        eprintln!(
            "vox daemon: not interrupting anyone for {}: its hop budget is spent; it waits for \
             the next turn",
            &vox_core::node::link::b32_encode(&row.entry_hash)[..12]
        );
        return Ok(());
    }
    // **A message wakes the agents of the nodes it addresses** (V210-161): `to` names nodes by
    // fingerprint, within each session's saved room (ADR-029 RB-4, RB-5); an entry
    // `<fingerprint>/<session id>` narrows that to one session (ADR-029 TA-3).
    let Some(me) = view.identity.as_ref().map(|i| i.fingerprint) else {
        return Ok(());
    };
    let me_fp = vox_core::node::link::b32_encode(&me);
    for session in crate::wake::registered(paths) {
        if session.room.as_deref() != Some(room.as_str()) {
            continue;
        }
        if !crate::wake::wakes(&envelope, &me_fp, &session.session) {
            continue;
        }
        if row.author == me && envelope.from == session.session {
            continue;
        }
        // **Not a session already in this conversation** (V210-121): a reply chain that comes
        // back to a session that spoke in it is two agents keeping each other awake. The hop
        // budget ends such a chain eventually; this ends it at the first turn back. It queues.
        if context.spoke(&me, &session.session) {
            eprintln!(
                "vox daemon: not interrupting session {} for {}: it already spoke in the reply \
                 chain this answers; it reads it on its next turn",
                session.session,
                &vox_core::node::link::b32_encode(&row.entry_hash)[..12]
            );
            continue;
        }
        // Recorded **before** the notice is sent, so the session's answer with no `--re` replies
        // to this (V210-121) however soon it comes: recorded after, an answer could beat the
        // record. A notice that then fails still put the message before the session's next turn.
        crate::wake::note_woke(paths, &session.session, &room, &row.entry_hash);
        // **Codex is never woken** (V210-169): nothing is owed it in notices; it reads at its next
        // turn, and a poster on this node is told so ([`crate::wake::uninterruptible`]).
        if !crate::wake::wakeable(&session.harness) {
            continue;
        }
        let mut n = crate::wake::notices_in(paths, &session.session, Some(&room));
        if !n.urgent_due {
            n.urgent_due = true;
            if let Err(e) = crate::wake::save_notices(paths, &session.session, &n) {
                eprintln!(
                    "vox daemon: could not record that session {} is owed a notice: {e}",
                    session.session
                );
            }
        }
    }
    Ok(())
}

/// Only the facts needed from at most DEFAULT_HOPS + 1 parents survive a lookup.
/// Parent text is released before the next actor request; a read error never means absent.
struct ReplyContext {
    expires: Option<u64>,
    hops: u32,
    speakers: Vec<(vox_core::hash::Digest32, vox_core::hash::Digest32)>,
    asked: Option<(vox_core::hash::Digest32, vox_core::hash::Digest32)>,
}
impl ReplyContext {
    fn spoke(&self, author: &vox_core::hash::Digest32, session: &str) -> bool {
        self.speakers
            .contains(&(*author, vox_core::hash::sha256(session.as_bytes())))
    }
    fn answers(&self, author: &vox_core::hash::Digest32, session: &str) -> bool {
        self.asked == Some((*author, vox_core::hash::sha256(session.as_bytes())))
    }
}
async fn reply_context(
    history: &vox_core::node::actor::HistoryReader,
    room: vox_core::hash::Digest32,
    envelope: &vox_agentcomms::envelope::Envelope,
) -> Result<ReplyContext, String> {
    let mut context = ReplyContext {
        expires: None,
        hops: envelope.hops,
        speakers: Vec::new(),
        asked: None,
    };
    let mut re = envelope.re.clone();
    for depth in 1..=vox_agentcomms::envelope::DEFAULT_HOPS + 1 {
        let Some(hash) = re
            .as_deref()
            .and_then(|h| vox_core::node::link::b32_decode(h.trim(), "re").ok())
        else {
            break;
        };
        let Some(parent) = history.notice_exact(room, hash).await? else {
            break;
        };
        context.expires = sooner(context.expires, parent.expires);
        let row = parent.row;
        if depth > vox_agentcomms::envelope::DEFAULT_HOPS {
            context.hops = 0;
            break;
        }
        let Ok(parent) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
            break;
        };
        let speaker = (row.author, vox_core::hash::sha256(parent.from.as_bytes()));
        context.speakers.push(speaker);
        if depth == 1 && !parent.from.is_empty() && !parent.to.is_empty() {
            context.asked = Some(speaker);
        }
        context.hops = context.hops.min(parent.hops.saturating_sub(depth));
        re = parent.re;
    }
    Ok(context)
}

fn sooner(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

// Counts stay exact; the announce-only sender display is an explicit bounded sample.
const NOTICE_SENDERS: usize = 8;
#[derive(Default)]
struct NoticeCount {
    n: usize,
    authors: std::collections::BTreeSet<vox_core::hash::Digest32>,
    more_authors: bool,
}
impl NoticeCount {
    fn add(&mut self, author: vox_core::hash::Digest32) -> Result<(), String> {
        self.n = self.n.checked_add(1).ok_or("notice count overflow")?;
        if self.authors.len() < NOTICE_SENDERS {
            self.authors.insert(author);
        } else if !self.authors.contains(&author) {
            self.more_authors = true;
        }
        Ok(())
    }
}
struct NoticeFold {
    registration: crate::wake::Session,
    cursor: Option<vox_core::hash::Digest32>,
    ahead: crate::agent_hook::SavedHashes,
    next: vox_core::node::api::HistoryCursor,
    through: u64,
    revision: vox_core::node::api::NoticeRevision,
    expires: Option<u64>,
    urgent: NoticeCount,
    replies: NoticeCount,
    newest_reply: Option<vox_core::hash::Digest32>,
}
enum FoldProgress {
    Pending,
    Complete,
    Restart,
}
impl NoticeFold {
    async fn start(
        history: &vox_core::node::actor::HistoryReader,
        room: vox_core::hash::Digest32,
        registration: &crate::wake::Session,
        cursor: Option<vox_core::hash::Digest32>,
        ahead: crate::agent_hook::SavedHashes,
    ) -> Result<Self, String> {
        let state = history.notice_state(room).await?;
        let after = match cursor {
            Some(hash) => history
                .exact(room, vec![hash])
                .await?
                .first()
                .filter(|r| !r.owed)
                .map_or(0, |r| r.arrival),
            None => 0,
        };
        Ok(Self {
            registration: registration.clone(),
            cursor,
            ahead,
            next: vox_core::node::api::HistoryCursor {
                instance: state.head.instance,
                arrival: after,
            },
            through: state.head.arrival,
            revision: state.revision,
            expires: None,
            urgent: NoticeCount::default(),
            replies: NoticeCount::default(),
            newest_reply: None,
        })
    }
    fn valid(&self, state: &vox_core::node::api::NoticeState) -> bool {
        self.next.instance == state.head.instance
            && self.revision == state.revision
            && self.expires.is_none_or(|at| state.now_ms < at)
    }
    async fn advance(
        &mut self,
        history: &vox_core::node::actor::HistoryReader,
        room: vox_core::hash::Digest32,
        me: Option<vox_core::hash::Digest32>,
    ) -> Result<FoldProgress, String> {
        let state = history.notice_state(room).await?;
        if !self.valid(&state) {
            return Ok(FoldProgress::Restart);
        }
        self.through = self.through.max(state.head.arrival);
        if self.next.arrival < self.through {
            let page = history.notice_page(room, Some(self.next)).await?;
            if !self.valid(&page.state) {
                return Ok(FoldProgress::Restart);
            }
            let me_fp = me.as_ref().map(vox_core::node::link::b32_encode);
            let mut finished = page.next.is_none();
            for item in page.rows {
                let row = item.row;
                if row.arrival > self.through {
                    finished = true;
                    break;
                }
                self.expires = sooner(self.expires, item.expires);
                if !self
                    .ahead
                    .contains(&row.entry_hash)
                    .map_err(|e| e.to_string())?
                {
                    if let Ok(envelope) = vox_agentcomms::envelope::Envelope::parse(&row.text) {
                        let own = me == Some(row.author)
                            && !envelope.from.is_empty()
                            && envelope.from == self.registration.session;
                        if !own {
                            let context = reply_context(history, room, &envelope).await?;
                            self.expires = sooner(self.expires, context.expires);
                            let urgent = context.hops > 0
                                && me_fp.as_deref().is_some_and(|fp| {
                                    crate::wake::wakes(&envelope, fp, &self.registration.session)
                                })
                                && !me
                                    .is_some_and(|m| context.spoke(&m, &self.registration.session));
                            if urgent {
                                self.urgent.add(row.author)?;
                            } else if context.hops > 0
                                && !crate::wake::NOT_REPLIES.contains(&envelope.kind.as_str())
                                && me.is_some_and(|m| {
                                    context.answers(&m, &self.registration.session)
                                })
                            {
                                self.replies.add(row.author)?;
                                self.newest_reply = Some(row.entry_hash);
                            }
                        }
                    }
                }
                self.next.arrival = row.arrival;
            }
            if let Some(next) = page.next {
                self.next.arrival = next.arrival.min(self.through);
            }
            if finished {
                self.next.arrival = self.through;
            }
        }
        // This is the final actor wait before notices are read and changed. Catch up new
        // arrivals without discarding the counted prefix; a changed prefix/expired input
        // restarts the count and leaves the current obligation untouched.
        let current = history.notice_state(room).await?;
        if !self.valid(&current) {
            return Ok(FoldProgress::Restart);
        }
        self.through = self.through.max(current.head.arrival);
        Ok(if self.next.arrival < self.through {
            FoldProgress::Pending
        } else {
            FoldProgress::Complete
        })
    }
}

/// Send each session the notice it is owed now, if any (ADR-020 §6; V030-15, V030-20).
///
/// A session works in its saved room alone (ADR-029 RB-4, RB-5). Its notices, unread replies and
/// answer-triggered checks are confined to that room. What it is owed is **counted here, just
/// before sending**, from that room and its cursor, so a message its drain already read is never
/// announced. [`crate::wake::tend`] has the rules; notices carry counts and senders, never a message.
async fn tend(
    paths: &vox_core::node::paths::Paths,
    history: &vox_core::node::actor::HistoryReader,
    view: &vox_core::node::api::NodeView,
    answered: &std::collections::HashSet<vox_core::hash::Digest32>,
    t: &mut Tending,
) {
    let (settings, problems) = crate::wake::Settings::load(paths);
    let now = crate::wake::now_millis();
    // **A setting that cannot be read is said, not silently replaced**: when it changes, and
    // again every ten minutes while it stands.
    if problems != t.problems || now.saturating_sub(t.problems_said) >= 600_000 {
        for problem in &problems {
            eprintln!("vox daemon: {problem}; its default is used until it is fixed");
        }
        t.problems_said = if problems.is_empty() { 0 } else { now };
        t.problems = problems;
    }
    let me = view.identity.as_ref().map(|i| i.fingerprint);
    let starting = std::mem::take(&mut t.starting);
    let registrations = crate::wake::registered(paths);
    if starting {
        t.starting_sessions
            .extend(registrations.iter().map(|s| s.session.clone()));
    }
    t.folds
        .retain(|id, _| registrations.iter().any(|s| &s.session == id));
    t.starting_sessions
        .retain(|id| registrations.iter().any(|s| &s.session == id));
    t.said_held
        .retain(|id| registrations.iter().any(|s| &s.session == id));
    for session in registrations {
        if !crate::wake::wakeable(&session.harness) {
            continue;
        }
        let Some(room) = session.room.as_deref() else {
            continue;
        };
        let Some(d) = view
            .open_channels
            .iter()
            .find(|d| vox_core::node::link::b32_encode(&d.channel_id) == room)
        else {
            continue;
        };
        let mut n = crate::wake::notices_in(paths, &session.session, Some(room));
        if !(t.starting_sessions.contains(&session.session)
            || t.folds.contains_key(&session.session)
            || n.active(&settings)
            || answered.contains(&d.channel_id))
        {
            continue;
        }
        // Only the saved room can contribute unread, a cursor, or reply eligibility.
        let ahead = match crate::agent_hook::delivered_ahead(paths, room, &session.session) {
            Ok(ahead) => ahead,
            Err(e) => {
                eprintln!("vox daemon: could not read shown-ahead state; will retry: {e}");
                continue;
            }
        };
        let cursor = ahead.cursor();
        let sent_cursor = format!(
            "{room}={}",
            cursor
                .as_ref()
                .map(vox_core::node::link::b32_encode)
                .unwrap_or_default()
        );
        if t.folds.get(&session.session).is_some_and(|fold| {
            !fold.registration.same(&session) || fold.cursor != cursor || fold.ahead != ahead
        }) {
            t.folds.remove(&session.session);
        }
        if !t.folds.contains_key(&session.session) {
            match NoticeFold::start(history, d.channel_id, &session, cursor, ahead.clone()).await {
                Ok(fold) => {
                    t.folds.insert(session.session.clone(), fold);
                }
                Err(e) => {
                    eprintln!("vox daemon: could not start notice count; will retry: {e}");
                    continue;
                }
            }
        }
        let Some(fold) = t.folds.get_mut(&session.session) else {
            continue;
        };
        match fold.advance(history, d.channel_id, me).await {
            Ok(FoldProgress::Pending) => continue,
            Ok(FoldProgress::Restart) => {
                t.folds.remove(&session.session);
                continue;
            }
            Err(e) => {
                eprintln!("vox daemon: could not count room notices; will retry: {e}");
                continue;
            }
            Ok(FoldProgress::Complete) => {}
        }
        let Some(fold) = t.folds.remove(&session.session) else {
            continue;
        };
        // No cursor, room move or endpoint change that happened during an actor wait may
        // make an old count update a new binding's notices.
        if !crate::wake::registration(paths, &session.session).is_some_and(|now| session.same(&now))
            || !crate::agent_hook::delivered_ahead(paths, room, &session.session)
                .is_ok_and(|now| now == ahead)
        {
            continue;
        }
        let starting = t.starting_sessions.remove(&session.session);
        let urgent = fold.urgent;
        let replies = fold.replies;
        let newest_reply = fold
            .newest_reply
            .as_ref()
            .map(vox_core::node::link::b32_encode);
        n = crate::wake::notices_in(paths, &session.session, Some(room));
        let before = n.clone();
        // **At start every session is counted from its cursors.** This guards one window only: a
        // daemon killed after a row reached its store and before the wake loop looked at it (the
        // next sweep, at most 2 s). Such a row is history to the restarted loop, so nothing new
        // marks it. Rows that land while the daemon is down arrive by sync after it starts and are
        // judged as new without this. The window is staged with the test-only `VOX_TEST_WAKE_DEAF`
        // (remote_interrupt_proof, a wake owed when the daemon died; V030-31, #368).
        if starting && urgent.n != 0 {
            n.urgent_due = true;
        }
        let outcome = crate::wake::tend(
            &mut n,
            Some(sent_cursor),
            urgent.n,
            newest_reply,
            session.idle(now, settings.busy_idle),
            now,
            &settings,
        );
        if n != before {
            if let Err(e) = crate::wake::save_notices(paths, &session.session, &n) {
                eprintln!(
                    "vox daemon: could not record the notices owed to session {}: {e}",
                    session.session
                );
            }
        }
        match outcome {
            crate::wake::Tended::Quiet => {}
            crate::wake::Tended::AlreadyRead => eprintln!(
                "vox daemon: not waking session {}: it already read the urgent message(s) owed \
                 a notice",
                session.session
            ),
            crate::wake::Tended::Held => {
                if t.said_held.insert(session.session.clone()) {
                    eprintln!(
                        "vox daemon: not waking session {} again yet: the notice sent to it is \
                         outstanding until it reads or {}s pass",
                        session.session,
                        settings.wake_hold.as_secs()
                    );
                }
            }
            crate::wake::Tended::Send => {
                t.said_held.remove(&session.session);
                // The reader's own name for each sender, and "you" for another session of this
                // node (V210-162): its own fingerprint read as "not in keyring".
                let me = view.identity.as_ref().map(|i| i.fingerprint);
                let name = |author: &vox_core::hash::Digest32| {
                    crate::ident::author_for(&view.trusted, me.as_ref(), author)
                };
                let room_name = view
                    .channels
                    .iter()
                    .find(|c| c.channel_id == d.channel_id)
                    .and_then(|c| c.name.clone())
                    .unwrap_or_default();
                let owed = crate::agent_hook::Owed {
                    room_label: room[..12.min(room.len())].to_owned(),
                    room_name,
                    urgent_count: urgent.n,
                    reply_count: replies.n,
                    urgent: urgent.authors.iter().map(name).collect(),
                    replies: replies.authors.iter().map(name).collect(),
                    urgent_more: urgent.more_authors,
                    replies_more: replies.more_authors,
                };
                let text = crate::agent_hook::render_wake(&[owed]);
                let hold = u64::try_from(settings.wake_hold.as_millis()).unwrap_or(u64::MAX);
                deliver(paths.clone(), session, text, (before, n, hold));
            }
        }
    }
}

/// What the wake loop remembers between looks (see [`tend`]).
#[derive(Default)]
struct Tending {
    /// The first look since the daemon started: every session is counted from its cursor.
    starting: bool,
    starting_sessions: std::collections::HashSet<String>,
    folds: std::collections::HashMap<String, NoticeFold>,
    /// The sessions already told, on stderr, that their notice is held.
    said_held: std::collections::HashSet<String>,
    /// The settings problems last said, and when.
    problems: Vec<String>,
    problems_said: u64,
}

/// Wake `session` with `text`, on a task of its own.
///
/// **One wedged session must not stall every other wake.** Each is its own task, bounded by a
/// deadline: a session endpoint that accepts and never reads would otherwise hold the wake
/// loop — and so every later interrupt — indefinitely.
///
/// **A notice that does not arrive stays owed** (`undo`: the record before and after it was sent,
/// and the hold): it is tried again once the hold passes or the session's cursor moves.
fn deliver(
    paths: vox_core::node::paths::Paths,
    session: crate::wake::Session,
    text: String,
    undo: (crate::wake::Notices, crate::wake::Notices, u64),
) {
    tokio::spawn(async move {
        let failed = |paths: &vox_core::node::paths::Paths| {
            crate::wake::undelivered(paths, &session.session, &undo.0, &undo.1, undo.2);
        };
        let woke = crate::wake::wake(&paths, &session, &text);
        match tokio::time::timeout(WAKE_DEADLINE, woke).await {
            Ok(Ok(())) => eprintln!("vox daemon: woke session {}", session.session),
            Ok(Err(crate::wake::WakeError::Moved)) => {}
            // A session that has ended is forgotten, so its name's later messages are
            // not tried against it for ever.
            Ok(Err(crate::wake::WakeError::Gone(e))) => {
                let forgot = crate::wake::forget(&paths, &session);
                eprintln!(
                    "vox daemon: session {} is gone ({e}){}",
                    session.session,
                    if forgot {
                        "; forgot its registration"
                    } else {
                        ""
                    }
                );
            }
            // Reported, never fatal: an agent that cannot be interrupted still reads the
            // message on its next turn, which is the whole point of queueing always.
            Ok(Err(e)) => {
                failed(&paths);
                eprintln!(
                    "vox daemon: could not interrupt session {}: {e}; it stays owed, and is \
                     tried again",
                    session.session
                );
            }
            Err(_) => {
                failed(&paths);
                eprintln!(
                    "vox daemon: interrupting session {} took longer than {}s; gave up for now — \
                     it stays owed, and is tried again",
                    session.session,
                    WAKE_DEADLINE.as_secs()
                );
            }
        }
    });
}
