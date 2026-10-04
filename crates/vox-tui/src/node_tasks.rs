//! The tasks an attached node runs beside its actor (ADR-026 L-2): anchor follow, the notifier,
//! and the interrupt path (wake, ping and tend). Each is cancellable, so a node can be detached
//! without stopping the daemon: [`NodeTasks::stop`] ends them before the node's own stop.
//!
//! Moved here from `vox daemon` (`app::run_daemon`) unchanged: what each task does, and every
//! line it prints, is what the single-node daemon did.

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
    /// Start `node`'s tasks on `rt`: anchor follow (re-reading `paths`' anchors file and
    /// `anchor_specs`), the notifier, and the interrupt path.
    #[must_use]
    pub fn start(rt: &Handle, node: &NodeHandle, paths: &Paths, anchor_specs: Vec<String>) -> Self {
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
        spawn(Box::pin(follow_anchors(
            node.clone(),
            paths.clone(),
            anchor_specs,
        )));
        // Tell the operator when `vox status` would flag something, and when it clears
        // (PRD-001 R37). Off with `notify = off` in the profile's config file.
        spawn(Box::pin(crate::notify::watch(node.clone(), paths.clone())));
        spawn(Box::pin(watch_for_interrupts(node.clone(), paths.clone())));
        Self { cancel, set }
    }

    /// End every task and wait for each to finish. A task ends at its next await once cancelled;
    /// a wake already handed to its own task ([`deliver`]) runs to its own deadline.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        while self.set.join_next().await.is_some() {}
    }
}

/// How often a daemon re-reads its anchor configuration and re-resolves it.
///
/// Short enough that a moved anchor is followed within a minute, long enough that it is
/// not a resolver load: the node only acts when something actually changed, because
/// merging an address it already holds is a no-op.
const ANCHOR_REFRESH: std::time::Duration = std::time::Duration::from_secs(30);

/// **Follow the anchor when it moves.**
///
/// An anchor spec may name a host rather than an address, and the reason it may is
/// that a home connection's address changes whenever the ISP decides — the point
/// being that a person should not have to re-issue it to every client. Resolution
/// happened once, when this process read its configuration, so a daemon that runs for
/// days held whatever the name meant at startup and redialled that address for ever.
/// The failure attributes badly: the anchor is up, the name is right, and the client
/// says only that it cannot reach a peer.
///
/// So re-read the configuration and re-resolve every spec on a timer, and hand the
/// node anything new. Re-reading is what makes this provable without a DNS record to
/// move: the same `merge_anchor_spec` runs again, so a name is resolved again whether
/// it was the file or the record that changed.
async fn follow_anchors(node: NodeHandle, paths: Paths, specs: Vec<String>) {
    // What the last read skipped, so a bad line is said when it appears, not every 30 s. The
    // attach said what the file skipped then (host.rs), so that is the first read's.
    let first = paths.clone();
    let mut said: Vec<String> = tokio::task::spawn_blocking(move || {
        let mut set = vox_core::nat::bootstrap::BootstrapSet::new();
        vox_core::node::link::merge_anchors_file(&mut set, &first.anchors_file())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    loop {
        tokio::time::sleep(ANCHOR_REFRESH).await;
        // On a blocking thread: a name is resolved here, and a slow resolver must not
        // hold a runtime worker (V210-75).
        let (paths, specs) = (paths.clone(), specs.clone());
        let Ok((set, skipped)) = tokio::task::spawn_blocking(move || {
            let mut set = vox_core::nat::bootstrap::BootstrapSet::new();
            // A bad line is skipped, not a reason to skip every anchor (V210-75).
            let skipped = vox_core::node::link::merge_anchors_file(&mut set, &paths.anchors_file())
                .unwrap_or_default();
            for spec in &specs {
                let _ = vox_core::node::link::merge_anchor_spec(&mut set, spec);
            }
            (set, skipped)
        })
        .await
        else {
            continue;
        };
        if skipped != said {
            for line in &skipped {
                eprintln!("vox daemon: {line}");
            }
            said = skipped;
        }
        if !set.is_empty() {
            let _ = node
                .apply(vox_core::node::api::NodeCommand::AddAnchors { anchors: set })
                .await;
        }
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
    // Everything already in a room when the daemon starts is history, not news:
    // an interrupt is for what lands while the daemon is running.
    let mut seen: std::collections::HashSet<vox_core::hash::Digest32> = node
        .view()
        .open_channels
        .iter()
        .flat_map(|d| d.timeline.iter().map(|r| r.entry_hash))
        .collect();
    // How far each room's timeline has been swept, and its row there. A timeline grows at
    // its end, so a sweep reads only what was added since the last one (V210-120): it read
    // the whole room on every sync, so each message cost the room's history. A room whose
    // timeline no longer has that row there (it was closed and reopened) is read whole.
    let mut swept: std::collections::HashMap<
        vox_core::hash::Digest32,
        (usize, Option<vox_core::hash::Digest32>),
    > = node
        .view()
        .open_channels
        .iter()
        .map(|d| {
            (
                d.channel_id,
                (d.timeline.len(), d.timeline.last().map(|r| r.entry_hash)),
            )
        })
        .collect();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    // The rooms where an answer to anything landed since the last look: a session there
    // may now be owed a reply's notice (V030-20).
    let mut answered: std::collections::HashSet<vox_core::hash::Digest32> =
        std::collections::HashSet::new();
    let mut tending = Tending {
        starting: true,
        ..Tending::default()
    };
    // Counted at once, not at the first tick.
    tend(&paths, &node.view(), &answered, &mut tending);
    loop {
        let sweep = tokio::select! {
            item = events.next() => match item {
                None => break,
                Some(vox_core::node::actor::EventStreamItem::Lagged(n)) => {
                    eprintln!("vox daemon: fell behind the node's events by {n}; re-reading every room");
                    true
                }
                Some(vox_core::node::actor::EventStreamItem::Event(ev)) => {
                    // **A daemon is the node nobody is watching, so it has to say
                    // things out loud** — unreachable peers, refused publishes,
                    // stalls — which `vox node` has always reported.
                    crate::tunnel_cli::say_if_it_explains_a_failure(&ev);
                    match ev {
                        vox_core::node::api::NodeEvent::NewEntry { channel_id, row } => {
                            // The view — every open room's timeline — is copied only
                            // for a message that could interrupt someone.
                            if seen.insert(row.entry_hash) {
                                // A ping is the daemon's to answer, never a model's
                                // (V030-16).
                                if crate::ping::is_ping(&row.text) {
                                    crate::ping::answer(
                                        &node,
                                        &paths,
                                        &node.view(),
                                        channel_id,
                                        &row,
                                    );
                                }
                                if may_wake(&row.text) {
                                    judge(&paths, &node.view(), &channel_id, &row);
                                }
                                if may_answer(&row.text) {
                                    answered.insert(channel_id);
                                }
                            }
                            // Looked at at once, rather than at the next tick.
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
            let view = node.view();
            // Every unseen row is marked seen; only one that could interrupt
            // someone is copied out to be judged.
            let mut fresh = Vec::new();
            let mut pings = Vec::new();
            for d in &view.open_channels {
                let from = match swept.get(&d.channel_id) {
                    Some(&(n, last))
                        if n > 0 && d.timeline.get(n - 1).map(|r| r.entry_hash) == last =>
                    {
                        n
                    }
                    _ => 0,
                };
                for r in d.timeline.iter_from(from) {
                    if !seen.insert(r.entry_hash) {
                        continue;
                    }
                    if may_wake(&r.text) {
                        fresh.push((d.channel_id, r.clone()));
                    }
                    if crate::ping::is_ping(&r.text) {
                        pings.push((d.channel_id, r.clone()));
                    }
                    if may_answer(&r.text) {
                        answered.insert(d.channel_id);
                    }
                }
                swept.insert(
                    d.channel_id,
                    (d.timeline.len(), d.timeline.last().map(|r| r.entry_hash)),
                );
            }
            for (cid, row) in fresh {
                judge(&paths, &view, &cid, &row);
            }
            for (cid, row) in pings {
                crate::ping::answer(&node, &paths, &view, cid, &row);
            }
            tend(&paths, &view, &answered, &mut tending);
            answered.clear();
        }
    }
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
/// on this node but the one that posted it, and but one already in its reply chain (V210-121), is
/// owed a notice. [`tend`] sends it. Everything else waits for the session's next turn.
///
/// `view` is the node's view as the entry is judged: the room's log, for the hop budget and the
/// reply chain.
fn judge(
    paths: &vox_core::node::paths::Paths,
    view: &vox_core::node::api::NodeView,
    channel_id: &vox_core::hash::Digest32,
    row: &vox_core::node::api::MessageRow,
) {
    let Ok(envelope) = vox_agentcomms::envelope::Envelope::parse(&row.text) else {
        return;
    };
    if !envelope.urgent || envelope.to.is_empty() {
        return;
    }
    let room = vox_core::node::link::b32_encode(channel_id);
    // **A message with no hops left interrupts nobody** (ADR-020 §9, V210-79): the budget
    // is the only loop guard that provably ends an urgent reply chain. It still queues.
    let empty = vox_core::node::api::Timeline::default();
    let timeline = view
        .open_channels
        .iter()
        .find(|d| d.channel_id == *channel_id)
        .map_or(&empty, |d| &d.timeline);
    if crate::wake::hops_left(&envelope, timeline) == 0 {
        eprintln!(
            "vox daemon: not interrupting anyone for {}: its hop budget is spent; it waits for \
             the next turn",
            &vox_core::node::link::b32_encode(&row.entry_hash)[..12]
        );
        return;
    }
    // **A message wakes the agents of the nodes it addresses** (V210-161): `to` names nodes by
    // fingerprint, and every session of this node hears every room it holds.
    let Some(me) = view.identity.as_ref().map(|i| i.fingerprint) else {
        return;
    };
    if !envelope.may_interrupt(&vox_core::node::link::b32_encode(&me)) {
        return;
    }
    for session in crate::wake::registered(paths) {
        if row.author == me && envelope.from == session.session {
            continue;
        }
        // **Not a session already in this conversation** (V210-121): a reply chain that comes
        // back to a session that spoke in it is two agents keeping each other awake. The hop
        // budget ends such a chain eventually; this ends it at the first turn back. It queues.
        if crate::wake::in_chain(&envelope, timeline, &me, &session.session) {
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
        let mut n = crate::wake::notices(paths, &session.session);
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
}

/// Send each session the notice it is owed now, if any (ADR-020 §6; V030-15, V030-20).
///
/// A session hears every room its node holds (V210-163), so it is owed one notice across all of
/// them. It is looked at when it is owed an urgent notice, while a reply to it is unread, and
/// when an answer to anything landed in one of its rooms (`answered`). What it is owed is
/// **counted here, just before sending**, from each room and the session's cursor there, so a
/// message its drain already read is never announced. [`crate::wake::tend`] has the rules; the
/// notice carries counts and senders, never a message.
fn tend(
    paths: &vox_core::node::paths::Paths,
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
    let said_held = &mut t.said_held;
    let me = view.identity.as_ref().map(|i| i.fingerprint);
    let starting = std::mem::take(&mut t.starting);
    let any_answered = view
        .open_channels
        .iter()
        .any(|d| answered.contains(&d.channel_id));
    for session in crate::wake::registered(paths) {
        if !crate::wake::wakeable(&session.harness) {
            continue;
        }
        let mut n = crate::wake::notices(paths, &session.session);
        // Looked at only when something may be owed: every room is read to count it.
        if !(starting || n.active(&settings) || any_answered) {
            continue;
        }
        // Each room's unread, and the session's read position across all of them: the notice
        // is outstanding until any of its cursors moves.
        let mut rooms = Vec::new();
        let mut cursors = Vec::new();
        for d in &view.open_channels {
            let room = vox_core::node::link::b32_encode(&d.channel_id);
            let cursor = crate::agent_hook::load_cursor(paths, &room, &session.session);
            let ahead = crate::agent_hook::delivered_ahead(paths, &room, &session.session);
            cursors.push(format!(
                "{room}={}",
                cursor
                    .as_ref()
                    .map(vox_core::node::link::b32_encode)
                    .unwrap_or_default()
            ));
            let (urgent, replies) = crate::wake::unread(&d.timeline, me, &session, cursor, &ahead);
            if !urgent.is_empty() || !replies.is_empty() {
                rooms.push((d, urgent, replies));
            }
        }
        let urgent: usize = rooms.iter().map(|(_, u, _)| u.len()).sum();
        let newest_reply = rooms
            .iter()
            .flat_map(|(_, _, r)| r.iter())
            .max_by_key(|r| r.arrival)
            .map(|r| vox_core::node::link::b32_encode(&r.entry_hash));
        let before = n.clone();
        // **At start every session is counted from its cursors.** This guards one window only: a
        // daemon killed after a row reached its store and before the wake loop looked at it (the
        // next sweep, at most 2 s). Such a row is history to the restarted loop, so nothing new
        // marks it. Rows that land while the daemon is down arrive by sync after it starts and are
        // judged as new without this. The window cannot be staged through the shipped binary
        // (`vox room post` needs a running node), so this is unproven by mutant: a review-only guard.
        if starting && urgent > 0 {
            n.urgent_due = true;
        }
        let outcome = crate::wake::tend(
            &mut n,
            Some(cursors.join(" ")),
            urgent,
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
                if said_held.insert(session.session.clone()) {
                    eprintln!(
                        "vox daemon: not waking session {} again yet: the notice sent to it is \
                         outstanding until it reads or {}s pass",
                        session.session,
                        settings.wake_hold.as_secs()
                    );
                }
            }
            crate::wake::Tended::Send => {
                said_held.remove(&session.session);
                // The reader's own name for each sender, and "you" for another session of this
                // node (V210-162): its own fingerprint read as "not in keyring".
                let me = view.identity.as_ref().map(|i| i.fingerprint);
                let name = |r: &&vox_core::node::api::MessageRow| {
                    crate::ident::author_for(&view.trusted, me.as_ref(), &r.author)
                };
                let owed: Vec<crate::agent_hook::Owed> = rooms
                    .iter()
                    .map(|(d, urgent, replies)| {
                        let label = vox_core::node::link::b32_encode(&d.channel_id);
                        let room_name = view
                            .channels
                            .iter()
                            .find(|c| c.channel_id == d.channel_id)
                            .and_then(|c| c.local_name.clone())
                            .unwrap_or_default();
                        crate::agent_hook::Owed {
                            room_label: label[..12.min(label.len())].to_owned(),
                            room_name,
                            urgent: urgent.iter().map(name).collect(),
                            replies: replies.iter().map(name).collect(),
                        }
                    })
                    .collect();
                let text = crate::agent_hook::render_wake(&owed);
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
        let woke = crate::wake::wake(&session, &text);
        match tokio::time::timeout(WAKE_DEADLINE, woke).await {
            Ok(Ok(())) => eprintln!("vox daemon: woke session {}", session.session),
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
