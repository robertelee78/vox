//! Authenticated exact-hash legacy Session subtype evidence (#804).
//!
//! Two sealed pages per log-id namespace: the even page records a target's known subtype;
//! the odd page holds the remaining references of that entry's authenticated declaration.
//! Pending pages follow local first-seen and ordinary retention. A resolved target page lives
//! with its verified skeleton, independently of the declaration's later expiry. No page grants
//! drive or changes `owed_wants`: subtype and permission eligibility are separate facts.

use super::*;
use crate::node::content::{LegacySessionIndex, MAX_LEGACY_SESSION_HASHES};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Page {
    Pending {
        declaration: Digest32,
        author: Digest32,
        first_seen: u64,
        steps: Vec<Digest32>,
    },
    Target {
        hash: Digest32,
        author: Digest32,
        session: bool,
    },
}

impl Page {
    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Pending {
                declaration,
                author,
                first_seen,
                steps,
            } => {
                e.array(6)
                    .uint(1)
                    .uint(0)
                    .bytes(declaration)
                    .bytes(author)
                    .uint(*first_seen)
                    .array(steps.len());
                for hash in steps {
                    e.bytes(hash);
                }
            }
            Self::Target {
                hash,
                author,
                session,
            } => {
                e.array(4)
                    .uint(1)
                    .uint(if *session { 1 } else { 2 })
                    .bytes(hash)
                    .bytes(author);
            }
        }
        e.finish()
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        if d.uint()? != 1 {
            return Err(Error::MalformedAtRest("Session classification version"));
        }
        let kind = d.uint()?;
        let hash = digest(&mut d)?;
        let author = digest(&mut d)?;
        let page = match (arity, kind) {
            (4, 1 | 2) => Self::Target {
                hash,
                author,
                session: kind == 1,
            },
            (6, 0) => {
                let first_seen = d.uint()?;
                let n = d.array()?;
                if n == 0 || n > MAX_LEGACY_SESSION_HASHES {
                    return Err(Error::MalformedAtRest("Session classification length"));
                }
                let mut steps = Vec::with_capacity(n);
                for _ in 0..n {
                    let h = digest(&mut d)?;
                    if steps.last().is_some_and(|last| *last >= h) {
                        return Err(Error::MalformedAtRest("Session classification order"));
                    }
                    steps.push(h);
                }
                Self::Pending {
                    declaration: hash,
                    author,
                    first_seen,
                    steps,
                }
            }
            _ => return Err(Error::MalformedAtRest("Session classification page")),
        };
        d.finish()?;
        Ok(page)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("Session classification digest"))
}

fn page_id(log_id: u64, pending: bool) -> Result<u64> {
    log_id
        .checked_mul(2)
        .and_then(|id| id.checked_add(u64::from(pending)))
        .ok_or(Error::SizeLimitExceeded("Session classification pages"))
}

#[derive(Debug, Default)]
pub(super) struct LegacySessions {
    pages: BTreeMap<u64, Page>,
    /// A view of Target pages, including durable contradictions (false).
    targets: BTreeMap<Digest32, bool>,
    /// Deletes are dirty ids with no corresponding page. Cleared only after durable commit.
    dirty: BTreeSet<u64>,
    /// Verified incoming bodies inspected before their log id is allocated and before floors
    /// may discard them. Absorption transfers these into durable target pages in its batch.
    pub(super) observed: BTreeMap<Digest32, (Digest32, bool)>,
}

impl LegacySessions {
    pub(super) fn is_session(&self, hash: &Digest32) -> bool {
        self.targets.get(hash) == Some(&true)
    }

    pub(super) fn dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    pub(super) fn committed(&mut self) {
        self.dirty.clear();
    }

    fn put(&mut self, id: u64, page: Page) {
        if self.pages.get(&id) == Some(&page) {
            return;
        }
        if let Page::Target { hash, session, .. } = &page {
            self.targets.insert(*hash, *session);
        }
        self.pages.insert(id, page);
        self.dirty.insert(id);
    }

    fn remove(&mut self, id: u64) {
        if let Some(Page::Target { hash, .. }) = self.pages.remove(&id) {
            self.targets.remove(&hash);
        }
        self.dirty.insert(id);
    }
}

impl ChannelState {
    /// A verified target, not a claimed time/sequence range or an unverified bare hash.
    fn legacy_target(&self, hash: &Digest32, author: &Digest32) -> Option<&Entry> {
        self.dag.get_by_hash(hash).filter(|entry| {
            entry.skeleton.channel_id == self.channel_id
                && entry.skeleton.author_id == *author
                && entry.skeleton.seq <= self.dag.verified_head(author)
        })
    }

    /// Inspect an authenticated available body before Session floors discard it. A copied
    /// receiver state checks a decryptable subtype without consuming the live chain twice.
    /// Its serialized keys and plaintext are zeroized; neither becomes a cache or permission.
    fn available_legacy_kind(&self, entry: &Entry) -> Option<bool> {
        let payload = entry.payload.as_deref()?;
        if !matches!(classify_payload(payload), Ok(EntryKind::Content)) {
            return Some(false);
        }
        let Ok(msg) = GroupMessage::from_wire(payload) else {
            return Some(false);
        };
        if msg.header.channel_id != drive_channel(&self.channel_id) {
            return Some(false);
        }
        let slot = (entry.skeleton.author_id, msg.header.chain_id);
        let chain = self.drive.receivers.get(&slot)?;
        if !chain.can_open_iteration(msg.header.iteration) {
            return None;
        }
        let mut copied = ReceiverChain::from_state(&chain.to_state()).ok()?;
        let plaintext = Zeroizing::new(copied.decrypt(&msg).ok()?);
        Some(matches!(
            crate::node::content::decode(&plaintext),
            Ok(Decoded::Session(_))
        ))
    }

    pub(super) fn remember_legacy_kind(
        &mut self,
        hash: Digest32,
        author: Digest32,
        session: bool,
    ) -> Result<()> {
        let Some(log_id) = self.log_ids.get(&hash).copied() else {
            self.legacy_sessions
                .observed
                .insert(hash, (author, session));
            return Ok(());
        };
        self.legacy_sessions.put(
            page_id(log_id, false)?,
            Page::Target {
                hash,
                author,
                session,
            },
        );
        Ok(())
    }

    /// Called before receive filtering, while a late contradictory body is still available.
    pub(super) fn inspect_legacy_bodies(&mut self, staged: &[Vec<u8>]) -> Result<()> {
        for wire in staged {
            let Ok(incoming) = Entry::from_wire(wire) else {
                continue;
            };
            let hash = incoming.entry_hash();
            let author = incoming.skeleton.author_id;
            let kind = self
                .legacy_target(&hash, &author)
                .and_then(|entry| self.available_legacy_kind(entry));
            if let Some(session) = kind {
                // A new entry has no log id yet. Absorption repeats the inspection once it
                // allocates its page; a refilled skeleton already has its durable log id.
                self.remember_legacy_kind(hash, author, session)?;
            }
        }
        Ok(())
    }

    pub(super) fn accept_legacy_index(
        &mut self,
        declaration: Digest32,
        outer_author: Digest32,
        index: LegacySessionIndex,
        now_ms: u64,
    ) -> Result<()> {
        if index.channel_id != self.channel_id || index.author != outer_author {
            return Ok(());
        }
        let Some(entry) = self.legacy_target(&declaration, &outer_author) else {
            return Ok(());
        };
        if entry.payload.is_none() {
            return Ok(());
        }
        let log_id = *self
            .log_ids
            .get(&declaration)
            .ok_or(Error::MalformedAtRest(
                "Session declaration has no log page",
            ))?;
        let first_seen = self
            .retention
            .get(&declaration)
            .map_or(now_ms, |t| t.first_seen_ms);
        self.legacy_sessions.put(
            page_id(log_id, true)?,
            Page::Pending {
                declaration,
                author: outer_author,
                first_seen,
                steps: index.steps,
            },
        );
        self.reconcile_legacy_sessions(now_ms)
    }

    /// Resolve only authenticated skeletons. Missing references age with their declaration;
    /// resolving a target moves its evidence into that target's own sealed page.
    pub(super) fn reconcile_legacy_sessions(&mut self, now_ms: u64) -> Result<()> {
        let pending: Vec<_> = self
            .legacy_sessions
            .pages
            .iter()
            .filter_map(|(id, page)| match page {
                Page::Pending { .. } => Some((*id, page.clone())),
                Page::Target { .. } => None,
            })
            .collect();
        let ttl = self.effective_retention();
        for (id, page) in pending {
            let Page::Pending {
                declaration,
                author,
                first_seen,
                steps,
            } = page
            else {
                continue;
            };
            // This sealed page already authenticates the declaration. Its verified skeleton
            // remains sufficient after body pruning: a remote backdated timestamp must not
            // shorten the pending references' local first-seen lifetime.
            if self.legacy_target(&declaration, &author).is_none()
                || (ttl != 0 && first_seen <= now_ms.saturating_sub(ttl.saturating_mul(1_000)))
            {
                self.legacy_sessions.remove(id);
                continue;
            }
            let mut remaining = Vec::new();
            for hash in steps {
                let Some(entry) = self.dag.get_by_hash(&hash) else {
                    remaining.push(hash);
                    continue;
                };
                if entry.skeleton.seq > self.dag.verified_head(&entry.skeleton.author_id) {
                    remaining.push(hash);
                    continue;
                }
                if entry.skeleton.channel_id != self.channel_id
                    || entry.skeleton.author_id != author
                {
                    continue;
                }
                let session = self
                    .available_legacy_kind(entry)
                    .or_else(|| self.legacy_sessions.targets.get(&hash).copied())
                    // A bare verified skeleton proves its signer/room/hash, not its subtype:
                    // the same author's authenticated exact-hash declaration supplies that.
                    .unwrap_or(true);
                self.remember_legacy_kind(hash, author, session)?;
            }
            if remaining.is_empty() {
                self.legacy_sessions.remove(id);
            } else {
                self.legacy_sessions.put(
                    id,
                    Page::Pending {
                        declaration,
                        author,
                        first_seen,
                        steps: remaining,
                    },
                );
            }
        }
        Ok(())
    }

    pub(super) fn restore_legacy_sessions(&mut self, store: &Store, now_ms: u64) -> Result<()> {
        for (id, segment) in store.segments(&self.channel_id, SegmentKind::SessionClassification)? {
            let bytes = open_segment(&self.sek, SegmentKind::SessionClassification, id, &segment)?;
            let page = Page::read(&bytes)?;
            let (hash, author, pending) = match &page {
                Page::Pending {
                    declaration,
                    author,
                    ..
                } => (*declaration, *author, true),
                Page::Target { hash, author, .. } => (*hash, *author, false),
            };
            if let Some(log_id) = self.log_ids.get(&hash) {
                if page_id(*log_id, pending)? != id {
                    return Err(Error::MalformedAtRest(
                        "Session classification page binding",
                    ));
                }
            } else {
                self.legacy_sessions.dirty.insert(id);
                continue;
            }
            if self.legacy_target(&hash, &author).is_none() {
                return Err(Error::MalformedAtRest(
                    "Session classification target binding",
                ));
            }
            self.legacy_sessions.put(id, page);
        }
        // Loaded pages need no rewrite; only reconciliation below creates dirty state.
        let stale: BTreeSet<_> = self
            .legacy_sessions
            .dirty
            .iter()
            .filter(|id| !self.legacy_sessions.pages.contains_key(id))
            .copied()
            .collect();
        self.legacy_sessions.dirty = stale;
        let known: Vec<_> = self
            .legacy_sessions
            .pages
            .values()
            .filter_map(|page| match page {
                Page::Target { hash, author, .. } => Some((*hash, *author)),
                Page::Pending { .. } => None,
            })
            .collect();
        for (hash, author) in known {
            if let Some(session) = self
                .legacy_target(&hash, &author)
                .and_then(|entry| self.available_legacy_kind(entry))
            {
                self.remember_legacy_kind(hash, author, session)?;
            }
        }
        self.reconcile_legacy_sessions(now_ms)?;
        if self.legacy_sessions.dirty() {
            let mut batch = store.batch()?;
            self.queue_legacy_sessions(&mut batch)?;
            batch.commit()?;
            self.legacy_sessions.committed();
        }
        Ok(())
    }

    pub(super) fn queue_legacy_sessions(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
    ) -> Result<()> {
        for id in &self.legacy_sessions.dirty {
            match self.legacy_sessions.pages.get(id) {
                Some(page) => {
                    let segment = seal_segment(
                        &self.sek,
                        SegmentKind::SessionClassification,
                        *id,
                        &page.wire(),
                    )?;
                    batch.put_segment(
                        &self.channel_id,
                        SegmentKind::SessionClassification,
                        *id,
                        &segment,
                    )?;
                }
                None => {
                    batch.delete_segment(
                        &self.channel_id,
                        SegmentKind::SessionClassification,
                        *id,
                    )?;
                }
            }
        }
        Ok(())
    }
}
