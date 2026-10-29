//! Local attention mutations share the room's authority, publication and sealed-store boundary.
use super::*;
use crate::node::attention::{ledger::Ledger, Operation, Recipient, Reply, Wait, PAGE_SIZE};

impl ChannelState {
    pub(crate) fn attention(
        &mut self,
        store: &Store,
        owner: Digest32,
        expected_instance: Option<[u8; 16]>,
        operation: Operation,
        now: u64,
    ) -> std::result::Result<Reply, String> {
        use super::session_projection::{Query as SessionQuery, Reply as SessionReply};
        let saved_page = matches!(operation, Operation::Page(_));
        if !saved_page && self.is_poisoned() {
            return Err(self.save_failure().to_string());
        }
        // Attention is local bookkeeping over Sessions this node already holds: who is
        // addressed, what is resolved. Nothing here releases a key or chooses an audience, so
        // it answers from known state while the fold catches up (ADR-037 R4); only the
        // legacy-recovery gate stays, as on every opened path (R3).
        let page_resource = if saved_page {
            Some(
                self.history_read_resource()
                    .ok_or_else(|| "the saved room is not ready".to_owned())?,
            )
        } else {
            None
        };
        let instance = if let Some(resource) = &page_resource {
            resource
                .with_snapshot(|_, view, _| {
                    if view.legacy_cache_only() {
                        return Err(Error::Profile(
                            super::legacy_provisional::LEGACY_HISTORY_REQUIRED,
                        ));
                    }
                    if expected_instance.is_some_and(|expected| expected != view.history_instance())
                    {
                        return Err(Error::Profile(
                            "the selected room changed; refresh and retry",
                        ));
                    }
                    Ok(view.history_instance())
                })
                .map_err(|error| error.to_string())?
        } else {
            self.require_legacy_current(store)
                .map_err(|error| error.to_string())?;
            self.history_instance(store)
                .map_err(|error| error.to_string())?
        };
        if matches!(operation, Operation::Maintain) {
            return self.maintain_attention(store, owner, instance, now);
        }
        if let Operation::Recipients { after } = operation {
            return match self.session_query(
                store,
                SessionQuery::Page {
                    open_only: true,
                    after,
                    revision: None,
                    limit: 16,
                },
                128 * 1024,
                now,
            )? {
                SessionReply::Page { rows, more, .. } => {
                    let next = more.then(|| rows.last().map(|row| row.opening)).flatten();
                    let recipients = rows
                        .into_iter()
                        .filter(|row| row.node == owner)
                        .map(|row| self.attention_recipient(store, instance, row.id, row.opening))
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    Ok(Reply::Recipients { recipients, next })
                }
                _ => Err("unexpected attention Session page".into()),
            };
        }
        let session = operation.session().to_owned();
        let row = match self.session_query(
            store,
            SessionQuery::Lookup {
                node: owner,
                id: session.clone(),
            },
            1,
            now,
        )? {
            SessionReply::Lookup(Some(row)) if row.open => row,
            _ => return Err("the selected Session is no longer open".into()),
        };
        let recipient = if let Some(resource) = &page_resource {
            resource
                .with_snapshot(|_, view, _| {
                    self.attention_recipient_in(view.snapshot(), instance, session, row.opening)
                })
                .map_err(|error| error.to_string())?
        } else {
            self.attention_recipient(store, instance, session, row.opening)?
        };
        if operation.recipient().is_some_and(|r| *r != recipient)
            || matches!(&operation, Operation::Page(q) if q.opening != recipient.opening)
        {
            return Err("attention selection changed; refresh and retry".into());
        }
        if let Operation::Scan { harness, route, .. } = &operation {
            return self.scan_attention(store, owner, &recipient, harness, *route, now);
        }
        if let (Operation::Page(query), Some(resource)) = (&operation, &page_resource) {
            let mut page = resource
                .with_snapshot(|sek, view, _| {
                    Ledger::snapshot(view.snapshot(), sek, self.channel_id, instance)?
                        .page(&recipient, query.after)
                })
                .map_err(|error| error.to_string())?;
            let paused = self.room_pause().paused;
            let cutoff = self.pause_resume_after();
            for row in &mut page.rows {
                if row.state != crate::node::attention::State::Unavailable
                    && !matches!(
                        resource.query(
                            history::Query::NoticeExact { entry: row.source },
                            64 * 1024,
                            now,
                        )?,
                        history::Reply::NoticeExact(Some(_))
                    )
                {
                    // Display-time expiry needs no writer. Ordinary maintenance seals the
                    // retirement; no action may treat this transient row as an eligible source.
                    row.state = crate::node::attention::State::Unavailable;
                    row.wait = None;
                    row.reason = Some("the source is no longer readable or retained".into());
                    row.at_millis = now;
                }
                if row.state == crate::node::attention::State::Queued
                    && row.wait != Some(Wait::Unknown)
                {
                    if paused {
                        row.wait = Some(Wait::Paused);
                    } else if !row.urgent && row.arrival <= cutoff && row.wait.is_none() {
                        row.wait = Some(Wait::NextTurnAfterResume);
                    }
                }
            }
            return Ok(Reply::Page(page));
        }
        let initial = if matches!(operation, Operation::Resolve { .. }) {
            match self
                .private_attention_after(store, &recipient.opening)
                .map_err(|e| e.to_string())?
            {
                Some(boundary) if boundary.after.instance == instance => boundary.after.arrival,
                Some(_) => return Err("attention opening belongs to a different saved room".into()),
                // A retained opening from before attention support has no saved boundary.
                // Its first registration starts observation now; existing ledgers never reset.
                None => self
                    .last_arrival(store)
                    .map_err(|e| e.to_string())?
                    .unwrap_or(0),
            }
        } else {
            0
        };
        // Recheck source readability in this turn before taking the Batch writer. No retained
        // snapshot, plaintext body or authority projection survives the operation.
        let native_notice = if let Operation::Admit {
            notice_id, route, ..
        } = &operation
        {
            let mut batch = store.batch().map_err(|e| e.to_string())?;
            let ledger = Ledger::open(&mut batch, &self.sek, self.channel_id, instance)
                .map_err(|e| e.to_string())?;
            Some(
                ledger
                    .notice(&recipient, *notice_id, *route)
                    .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let sources = match &operation {
            Operation::Begin { sources, .. } => sources.as_slice(),
            Operation::Admit { .. } => native_notice
                .as_ref()
                .map_or(&[][..], |notice| notice.sources.as_slice()),
            Operation::Prepare { sources, .. }
            | Operation::CancelPrepared { sources, .. }
            | Operation::Received { sources, .. } => sources.as_slice(),
            Operation::Observed(receipt) => receipt.sources.as_slice(),
            _ => &[],
        };
        if sources.len() > PAGE_SIZE
            || (matches!(operation, Operation::Prepare { .. }) && sources.len() > 6)
            || (matches!(operation, Operation::Observed(_))
                && (sources.is_empty() || sources.len() > 6))
        {
            return Err("attention operation exceeds one page".into());
        }
        let existing = if matches!(
            operation,
            Operation::Prepare { .. } | Operation::Received { .. } | Operation::Observed(_)
        ) {
            let mut batch = store.batch().map_err(|e| e.to_string())?;
            let ledger = Ledger::open(&mut batch, &self.sek, self.channel_id, instance)
                .map_err(|e| e.to_string())?;
            sources
                .iter()
                .map(|source| ledger.contains_obligation(&recipient, source))
                .collect::<Result<Vec<_>>>()
                .map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        let mut readable = Vec::new();
        for (index, hash) in sources.iter().enumerate() {
            if let history::Reply::NoticeExact(Some(notice)) = self.saved_history_query(
                store,
                history::Query::NoticeExact { entry: *hash },
                64 * 1024,
                now,
            )? {
                let env = match vox_agentcomms::envelope::Envelope::parse(&notice.row.text) {
                    Ok(env) => env,
                    Err(_) => continue,
                };
                if match &operation {
                    Operation::Prepare { .. } => {
                        existing[index]
                            || self.attention_eligible(
                                store,
                                owner,
                                &recipient,
                                &notice.row,
                                &env,
                                now,
                            )?
                    }
                    Operation::Received { .. } | Operation::Observed(_) => existing[index],
                    Operation::Begin { .. } => true,
                    Operation::Admit { .. } => {
                        self.attention_eligible(store, owner, &recipient, &notice.row, &env, now)?
                    }
                    _ => env.is_ordinary_conversation() || env.urgent,
                } {
                    readable.push((*hash, notice.row.arrival, env.urgent));
                }
            }
        }
        if matches!(operation, Operation::Observed(_)) && readable.len() != sources.len() {
            return Err("attention receipt source is no longer readable or retained".into());
        }
        let paused = self.room_pause().paused;
        let cutoff = self.pause_resume_after();
        let result = (|| -> Result<Reply> {
            let mut batch = store.batch()?;
            batch.ruled();
            let mut ledger = Ledger::open(&mut batch, &self.sek, self.channel_id, instance)?;
            let reply = match operation {
                Operation::Resolve { .. } => {
                    ledger.initialize(&recipient, initial)?;
                    Reply::Resolved {
                        through: ledger.cursor(&recipient)?,
                        notice_pending: ledger.notice_pending(&recipient)?,
                        recipient: recipient.clone(),
                    }
                }
                Operation::Pending { .. } => {
                    let mut page = ledger.pending(&recipient)?;
                    for row in &mut page.rows {
                        if row.wait != Some(Wait::Unknown) {
                            if paused {
                                row.wait = Some(Wait::Paused);
                            } else if !row.urgent && row.arrival <= cutoff && row.wait.is_none() {
                                row.wait = Some(Wait::NextTurnAfterResume);
                            }
                        }
                    }
                    Reply::Page(page)
                }
                Operation::Maintain
                | Operation::Recipients { .. }
                | Operation::Scan { .. }
                | Operation::Page(_) => {
                    return Err(Error::Profile("unexpected attention operation"))
                }
                Operation::Begin { route, .. } => {
                    let eligible: Vec<_> = readable
                        .iter()
                        .filter(|(_, arrival, urgent)| !paused && (*urgent || *arrival > cutoff))
                        .map(|(hash, _, _)| *hash)
                        .collect();
                    Reply::Attempt(ledger.begin(&recipient, route, &eligible)?)
                }
                Operation::Dispatch { attempt, outcome } => {
                    ledger.dispatch(&attempt, outcome)?;
                    Reply::Done
                }
                Operation::Admit {
                    notice_id, route, ..
                } => {
                    if paused
                        || !readable
                            .iter()
                            .any(|(_, arrival, urgent)| *urgent || *arrival > cutoff)
                    {
                        return Err(Error::Profile(
                            "attention notice has no currently eligible source",
                        ));
                    }
                    ledger.admit_notice(&recipient, notice_id, route)?;
                    Reply::Done
                }
                Operation::CancelPrepared {
                    sources, ticket, ..
                } => {
                    ledger.cancel_prepared(&recipient, &sources, ticket)?;
                    Reply::Done
                }
                Operation::Prepare { ticket, input, .. } => {
                    for (hash, arrival, urgent) in &readable {
                        ledger.admit(&recipient, *hash, *arrival, *urgent, None, now)?;
                    }
                    let hashes: Vec<_> = readable.iter().map(|(hash, _, _)| *hash).collect();
                    Reply::Prepared(ledger.prepare(&recipient, &hashes, ticket, input)?)
                }
                Operation::Received { ticket, .. } => {
                    let hashes: Vec<_> = readable.iter().map(|(hash, _, _)| *hash).collect();
                    ledger.received(&recipient, &hashes, ticket, now)?;
                    Reply::Done
                }
                Operation::Observed(receipt) => {
                    ledger.observed(&receipt, now)?;
                    Reply::Done
                }
            };
            if ledger.finish()? {
                batch.commit()?;
            }
            Ok(reply)
        })();
        result.map_err(|error| {
            if !matches!(error, Error::Profile(_)) {
                self.poison(&error);
            }
            error.to_string()
        })
    }
}

impl ChannelState {
    fn attention_row(
        &mut self,
        store: &Store,
        hash: Digest32,
        now: u64,
    ) -> std::result::Result<Option<crate::node::api::MessageRow>, String> {
        match self.saved_history_query(
            store,
            history::Query::NoticeExact { entry: hash },
            64 * 1024,
            now,
        )? {
            history::Reply::NoticeExact(row) => Ok(row.map(|r| r.row)),
            _ => Err("unexpected attention source answer".into()),
        }
    }
    fn scan_attention(
        &mut self,
        store: &Store,
        owner: Digest32,
        recipient: &Recipient,
        harness: &str,
        route: Option<Digest32>,
        now: u64,
    ) -> std::result::Result<Reply, String> {
        use crate::node::attention::ledger::ThreadScan;
        use vox_agentcomms::envelope::Envelope;
        let (mut through, audience_turn, audience_work) = {
            let mut batch = store.batch().map_err(|e| e.to_string())?;
            let ledger = Ledger::open(&mut batch, &self.sek, self.channel_id, recipient.instance)
                .map_err(|e| e.to_string())?;
            let (through, audience_turn) =
                ledger.scan_state(recipient).map_err(|e| e.to_string())?;
            let work = if audience_turn {
                Some(ledger.audience_work(recipient).map_err(|e| e.to_string())?)
            } else {
                None
            };
            (through, audience_turn, work)
        };
        if self.room_pause().paused {
            return Ok(Reply::Done);
        }
        let mut admitted = Vec::new();
        let mut deferred = Vec::new();
        let mut answered = Vec::new();
        let mut audience_result = None;
        let owner_text = crate::node::link::b32_encode(&owner);
        let participant = |row: &crate::node::api::MessageRow| {
            Envelope::parse(&row.text).is_ok_and(|env| {
                (row.author == owner && (env.from.is_empty() || env.from == recipient.session))
                    || (!env.to.is_empty()
                        && env.is_addressed_to_session(&owner_text, &recipient.session))
            })
        };
        let audience_after = audience_work.as_ref().map(|(after, _)| *after);
        if let Some((_, Some(mut pending))) = audience_work {
            let eligible = if self.attention_row(store, pending.source, now)?.is_some() {
                let root = self.attention_row(store, pending.root, now)?;
                if root.as_ref().is_some_and(&participant) {
                    Some(true)
                } else {
                    match self.saved_history_query(
                        store,
                        history::Query::CursorPage {
                            after: Some(crate::node::api::HistoryCursor {
                                instance: recipient.instance,
                                arrival: pending.after,
                            }),
                            selection: Some(history::Selection::All(vec![
                                entry_store::Filter::Thread(pending.root),
                            ])),
                            // 16 queued slots + source/root + 46 rows stays within 64 inspected rows.
                            limit: 46,
                        },
                        128 * 1024,
                        now,
                    )? {
                        history::Reply::CursorPage(page) => {
                            if page.rows.iter().any(&participant) {
                                Some(true)
                            } else if let Some(next) = page.next {
                                pending.after = next.arrival;
                                None
                            } else if root.is_some() {
                                Some(false)
                            } else {
                                pending.after = 0;
                                None
                            }
                        }
                        _ => return Err("unexpected attention thread page".into()),
                    }
                }
            } else {
                Some(false)
            };
            audience_result = Some((pending, eligible));
        } else if !audience_turn {
            let page = match self.saved_history_query(
                store,
                history::Query::CursorPage {
                    after: Some(crate::node::api::HistoryCursor {
                        instance: recipient.instance,
                        arrival: through,
                    }),
                    selection: None,
                    // Each source may inspect at most nine explicit reply ancestors.
                    limit: 6,
                },
                128 * 1024,
                now,
            )? {
                history::Reply::CursorPage(page) => page,
                _ => return Err("unexpected attention arrival page".into()),
            };
            for row in page.rows {
                through = row.arrival;
                let Ok(env) = Envelope::parse(&row.text) else {
                    continue;
                };
                if row.author == owner && env.from == recipient.session && env.kind == "answer" {
                    if let Some(source) = env
                        .re
                        .as_deref()
                        .and_then(|re| crate::node::link::b32_decode(re, "answer").ok())
                    {
                        answered.push((source, row.entry_hash));
                    }
                }
                let addressed = !env.to.is_empty()
                    && env.is_addressed_to_session(&owner_text, &recipient.session);
                if self.attention_eligible(store, owner, recipient, &row, &env, now)? {
                    if let Some(root) = env
                        .thread
                        .as_deref()
                        .and_then(|root| crate::node::link::b32_decode(root, "thread").ok())
                        .filter(|_| !addressed)
                    {
                        deferred.push((
                            ThreadScan {
                                source: row.entry_hash,
                                arrival: row.arrival,
                                root,
                                after: 0,
                            },
                            env.urgent,
                        ));
                    } else {
                        admitted.push((row.entry_hash, row.arrival, env.urgent));
                    }
                }
            }
            if let Some(next) = page.next {
                through = through.max(next.arrival);
            }
        }
        let wait = match harness {
            "codex" => Some(Wait::NextCodexTurn),
            "opencode" | "claude" if route.is_some() => None,
            _ => Some(Wait::AdapterUnavailable),
        };
        let result = (|| -> Result<Reply> {
            let mut batch = store.batch()?;
            batch.ruled();
            let mut ledger =
                Ledger::open(&mut batch, &self.sek, self.channel_id, recipient.instance)?;
            ledger.availability(recipient, wait, route)?;
            for (source, arrival, urgent) in admitted {
                ledger.admit(recipient, source, arrival, urgent, None, now)?;
            }
            for (pending, urgent) in deferred {
                ledger.defer_audience(recipient, pending, urgent, now)?;
            }
            if let Some((pending, eligible)) = audience_result {
                ledger.audience_progress(recipient, &pending, eligible)?;
            }
            for (source, answer) in answered {
                ledger.answered(recipient, source, answer, now)?;
            }
            ledger.scanned(recipient, through, audience_after)?;
            if ledger.finish()? {
                batch.commit()?;
            }
            Ok(Reply::Done)
        })();
        result.map_err(|error| {
            if !matches!(error, Error::Profile(_)) {
                self.poison(&error);
            }
            error.to_string()
        })
    }
}

impl ChannelState {
    fn attention_recipient(
        &self,
        store: &Store,
        instance: [u8; 16],
        session: String,
        opening: Digest32,
    ) -> std::result::Result<Recipient, String> {
        self.attention_recipient_in(
            &store.snapshot().map_err(|error| error.to_string())?,
            instance,
            session,
            opening,
        )
        .map_err(|error| error.to_string())
    }

    fn attention_recipient_in(
        &self,
        snapshot: &crate::node::store::Snapshot,
        instance: [u8; 16],
        session: String,
        opening: Digest32,
    ) -> Result<Recipient> {
        let boundary = self.private_attention_after_in(snapshot, &opening)?;
        if boundary.is_some_and(|b| b.after.instance != instance) {
            return Err(Error::Profile(
                "attention opening belongs to a different saved room",
            ));
        }
        Ok(Recipient {
            room: self.channel_id,
            instance,
            session,
            opening,
            identity: boundary.map_or(opening, |b| b.identity),
        })
    }

    fn maintain_attention(
        &mut self,
        store: &Store,
        owner: Digest32,
        instance: [u8; 16],
        now: u64,
    ) -> std::result::Result<Reply, String> {
        use super::session_projection::{Query as Q, Reply as R};
        let (after, records) = {
            let mut batch = store.batch().map_err(|e| e.to_string())?;
            let ledger = Ledger::open(&mut batch, &self.sek, self.channel_id, instance)
                .map_err(|e| e.to_string())?;
            ledger.maintenance().map_err(|e| e.to_string())?
        };
        let mut expired = Vec::new();
        for (recipient, record) in records {
            let closed = match self.session_query(
                store,
                Q::Lookup {
                    node: owner,
                    id: recipient.session.clone(),
                },
                1,
                now,
            )? {
                R::Lookup(Some(row)) if row.open => {
                    self.attention_recipient(store, instance, row.id, row.opening)?
                        .identity
                        != recipient.identity
                }
                _ => true,
            };
            if let Some((source, state)) = record {
                if closed
                    || state == crate::node::attention::State::Unavailable
                    || self.attention_row(store, source, now)?.is_none()
                {
                    expired.push((recipient, Some(source), closed));
                }
            } else if closed {
                expired.push((recipient, None, true));
            }
        }
        let result = (|| -> Result<Reply> {
            let mut batch = store.batch()?;
            batch.ruled();
            let mut ledger = Ledger::open(&mut batch, &self.sek, self.channel_id, instance)?;
            for (recipient, source, closed) in expired {
                if let Some(source) = source {
                    ledger.retire(&recipient, source, closed, now)?;
                } else {
                    ledger.retire_empty(&recipient)?;
                }
            }
            ledger.maintained(after);
            if ledger.finish()? {
                batch.commit()?;
            }
            Ok(Reply::Done)
        })();
        result.map_err(|error| {
            if !matches!(error, Error::Profile(_)) {
                self.poison(&error);
            }
            error.to_string()
        })
    }
}

impl ChannelState {
    fn attention_eligible(
        &mut self,
        store: &Store,
        owner: Digest32,
        recipient: &Recipient,
        row: &crate::node::api::MessageRow,
        env: &vox_agentcomms::envelope::Envelope,
        now: u64,
    ) -> std::result::Result<bool, String> {
        if row.author == owner && env.from == recipient.session {
            return Ok(false);
        }
        let owner_text = crate::node::link::b32_encode(&owner);
        let addressed =
            !env.to.is_empty() && env.is_addressed_to_session(&owner_text, &recipient.session);
        if env.is_ordinary_conversation() && (env.to.is_empty() || addressed) {
            return Ok(true);
        }
        let (hops, spoke, answers) = if env.re.is_some() {
            self.attention_reply_context(store, owner, &recipient.session, env, now)?
        } else {
            (env.hops, false, false)
        };
        Ok((env.urgent
            && addressed
            && hops > 0
            && !spoke
            && !vox_agentcomms::envelope::is_plumbing(&env.kind))
            || (answers
                && hops > 0
                && !["ack", "status", "hello", "bye", "ping", "pong"].contains(&env.kind.as_str())))
    }
    fn attention_reply_context(
        &mut self,
        store: &Store,
        owner: Digest32,
        session: &str,
        envelope: &vox_agentcomms::envelope::Envelope,
        now: u64,
    ) -> std::result::Result<(u32, bool, bool), String> {
        use vox_agentcomms::envelope::{Envelope, DEFAULT_HOPS};
        let mut hops = envelope.hops;
        let mut spoke = false;
        let mut answers = false;
        let mut re = envelope.re.clone();
        for depth in 1..=DEFAULT_HOPS + 1 {
            let Some(hash) = re
                .as_deref()
                .and_then(|hash| crate::node::link::b32_decode(hash, "reply").ok())
            else {
                break;
            };
            let Some(row) = self.attention_row(store, hash, now)? else {
                break;
            };
            if depth > DEFAULT_HOPS {
                hops = 0;
                break;
            }
            let Ok(parent) = Envelope::parse(&row.text) else {
                break;
            };
            if row.author == owner && parent.from == session {
                spoke = true;
                if depth == 1 && !parent.to.is_empty() {
                    answers = true;
                }
            }
            hops = hops.min(parent.hops.saturating_sub(depth));
            re = parent.re;
        }
        Ok((hops, spoke, answers))
    }
}
