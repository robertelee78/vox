//! Bounded named-index reconstruction of current semantic governance facts. Historical notices
//! and durable authority checks use ephemeral checked readers; none survives a turn.

use super::authority::Grant;
use super::facts::{hash_key, Read, Table};
use super::fold::{self, kind_key};
use crate::atrest::sek::Sek;
use crate::cbor::Decoder;
use crate::error::{Error, Result};
use crate::governance::entry::{GovBody, GovEntry};
use crate::governance::evaluator::{DenyReason, Lifecycle};
use crate::governance::genesis::{ChannelPolicy, Genesis};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::nat::bootstrap::BootstrapSet;
use crate::node::store::Store;

pub(in crate::node::channel) const REFRESHING: &str =
    "room governance is refreshing; try again when it is ready";
pub(in crate::node::channel) const PAGE_ROWS: usize = 64;

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}
fn pair(left: &Digest32, right: &Digest32) -> [u8; 64] {
    let mut key = hash_key(left);
    key[32..].copy_from_slice(right);
    key
}

/// No historical event list, no snapshot and no Store reference survives in the
/// Channel's last-good display. Names and bootstrap addresses have wire bounds.
#[derive(Clone, Debug)]
pub(in crate::node::channel) struct Display {
    pub name: Option<String>,
    pub policy: ChannelPolicy,
    pub step_ttl_ms: u64,
    pub lifecycle: Lifecycle,
    pub anchors: Option<BootstrapSet>,
    pub revision: u64,
    pub valid_until: u64,
}
impl Display {
    pub(in crate::node::channel) fn genesis(genesis: &Genesis) -> Self {
        Self {
            name: None,
            policy: genesis.body.policy,
            step_ttl_ms: crate::governance::step_policy::DEFAULT_STEP_TTL_MS,
            lifecycle: Lifecycle::default(),
            anchors: None,
            revision: 0,
            valid_until: 0,
        }
    }
}

/// A room's current consent facts held in memory (ADR-038 FX-22): each author/target's
/// granted or revoked sequence, each author's reset, and every pair ever revoked. This same
/// projection serves saved readers and user pagination, including off-roster identities.
/// Reconstruction is bounded per turn, rather than narrowing the identities callers may query.
/// Persistent ordered trees keep snapshots immutable without copying the full projection:
/// cloning this value shares roots, and mutation copies only the affected search paths.
/// The nested target maps also share roots when an author-map node is copied.
#[derive(Clone, Default)]
pub(in crate::node::channel) struct ConsentFacts {
    consent: imbl::OrdMap<Digest32, imbl::OrdMap<Digest32, Consent>>,
    resets: imbl::OrdMap<Digest32, u64>,
    revoked: imbl::OrdSet<[u8; 64]>,
}

#[derive(Clone, Copy)]
pub(in crate::node::channel) enum Consent {
    Granted(u64),
    Revoked(u64),
}

impl ConsentFacts {
    pub(in crate::node::channel) fn set_consent(
        &mut self,
        author: Digest32,
        target: Digest32,
        state: Option<Consent>,
    ) {
        match state {
            Some(state) => {
                self.consent
                    .entry(author)
                    .or_default()
                    .insert(target, state);
            }
            None => {
                if let Some(readers) = self.consent.get_mut(&author) {
                    readers.remove(&target);
                    if readers.is_empty() {
                        self.consent.remove(&author);
                    }
                }
            }
        }
    }

    pub(in crate::node::channel) fn set_reset(&mut self, author: Digest32, seq: Option<u64>) {
        match seq {
            Some(seq) => {
                self.resets.insert(author, seq);
            }
            None => {
                self.resets.remove(&author);
            }
        }
    }

    pub(in crate::node::channel) fn set_ever_revoked(
        &mut self,
        author: Digest32,
        target: Digest32,
        revoked: bool,
    ) {
        if revoked {
            self.revoked.insert(pair(&author, &target));
        } else {
            self.revoked.remove(&pair(&author, &target));
        }
    }

    /// Apply one newly committed current-input fact without consulting storage. Older arrivals
    /// cannot replace a newer fact, exactly as `facts::Write::latest` behaves.
    pub(in crate::node::channel) fn observe(&mut self, author: Digest32, seq: u64, body: &GovBody) {
        match body {
            GovBody::ConsentGrant(grant) if grant.body.epoch == 0 => {
                let target = grant.body.target_id;
                let readers = self.consent.entry(author).or_default();
                let replace = readers.get(&target).is_none_or(|state| match state {
                    Consent::Granted(held) | Consent::Revoked(held) => *held < seq,
                });
                if replace {
                    readers.insert(target, Consent::Granted(seq));
                }
            }
            GovBody::ConsentRevocation(revoke) => {
                let target = revoke.body.target_id;
                self.revoked.insert(pair(&author, &target));
                if revoke.body.epoch == 0 {
                    let readers = self.consent.entry(author).or_default();
                    let replace = readers.get(&target).is_none_or(|state| match state {
                        Consent::Granted(held) | Consent::Revoked(held) => *held < seq,
                    });
                    if replace {
                        readers.insert(target, Consent::Revoked(seq));
                    }
                }
            }
            GovBody::Presence(presence) if presence.body.here && presence.body.epoch == 0 => {
                let reset = self.resets.entry(author).or_default();
                *reset = (*reset).max(seq);
            }
            _ => {}
        }
    }

    /// Whether the reader holds a current grant after the author's reset.
    pub(in crate::node::channel) fn can_read(&self, reader: &Digest32, author: &Digest32) -> bool {
        self.grant_sequence(author, reader).is_some()
    }

    /// The current granted sequence, after applying the author's reset.
    pub(in crate::node::channel) fn grant_sequence(
        &self,
        author: &Digest32,
        target: &Digest32,
    ) -> Option<u64> {
        match self
            .consent
            .get(author)
            .and_then(|readers| readers.get(target))
        {
            Some(Consent::Granted(seq)) if *seq > self.resets.get(author).copied().unwrap_or(0) => {
                Some(*seq)
            }
            _ => None,
        }
    }

    /// Whether any authenticated revocation for this pair has been recorded.
    pub(in crate::node::channel) fn ever_revoked(
        &self,
        author: &Digest32,
        target: &Digest32,
    ) -> bool {
        self.revoked.contains(&pair(author, target))
    }
}

/// Folded current values, not index rows or retained source bodies. Off-roster identities keep
/// their exact lookup and pagination semantics; only reconstruction work is page-bounded.
#[derive(Default)]
pub(in crate::node::channel) struct SemanticFacts {
    authority: std::collections::BTreeMap<Digest32, Grant>,
    shares: std::collections::BTreeMap<(Digest32, Digest32), Option<super::super::Share>>,
    fingerprints: std::collections::BTreeMap<(Digest32, Digest32), Digest32>,
    consent: std::sync::Arc<ConsentFacts>,
    admin_clock: Option<u64>,
}

#[derive(Default)]
pub(in crate::node::channel) struct SemanticState {
    source: Option<(u64, u64)>,
    ready: bool,
    facts: SemanticFacts,
    building: Option<SemanticBuild>,
    serial: u64,
}

struct SemanticBuild {
    source: (u64, u64),
    phase: usize,
    after: Option<[u8; 64]>,
    facts: SemanticFacts,
}

/// Owned rebuild continuation. Preparation moves only partial semantic maps; the published
/// last-good values remain available in the room throughout native worker execution.
pub(in crate::node::channel) struct SemanticWork {
    serial: u64,
    source: Option<(u64, u64)>,
    building: Option<SemanticBuild>,
    ready: bool,
    completed: bool,
    admin_clock: Option<Option<u64>>,
}

impl SemanticState {
    pub(in crate::node::channel) fn invalidate(&mut self) -> Result<()> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or(invalid("governance semantic input generation exhausted"))?;
        Ok(())
    }

    /// Withdraw public authority but retain the last completed basis for comparison after
    /// canonical work settles. Sequence-only receipts fence workers without retiring it.
    pub(in crate::node::channel) fn retire(&mut self) -> Result<()> {
        self.invalidate()?;
        self.ready = false;
        self.building = None;
        Ok(())
    }

    pub(in crate::node::channel) fn observe_consent(
        &mut self,
        author: Digest32,
        seq: u64,
        body: &GovBody,
    ) -> Result<()> {
        self.invalidate()?;
        let changes_consent = match body {
            GovBody::ConsentGrant(grant) => grant.body.epoch == 0,
            GovBody::ConsentRevocation(_) => true,
            GovBody::Presence(presence) => presence.body.here && presence.body.epoch == 0,
            _ => false,
        };
        if !changes_consent {
            return Ok(());
        }
        std::sync::Arc::make_mut(&mut self.facts.consent).observe(author, seq, body);
        if let Some(build) = &mut self.building {
            std::sync::Arc::make_mut(&mut build.facts.consent).observe(author, seq, body);
        }
        Ok(())
    }

    pub(in crate::node::channel) fn consent_facts(&self) -> Option<std::sync::Arc<ConsentFacts>> {
        self.source
            .filter(|_| self.ready)
            .map(|_| std::sync::Arc::clone(&self.facts.consent))
    }

    pub(in crate::node::channel) fn take_work(&mut self) -> SemanticWork {
        SemanticWork {
            serial: self.serial,
            source: self.source,
            building: self.building.take(),
            ready: false,
            completed: false,
            admin_clock: None,
        }
    }

    pub(in crate::node::channel) fn matches(&self, work: &SemanticWork) -> bool {
        self.serial == work.serial
    }

    pub(in crate::node::channel) fn install(&mut self, mut work: SemanticWork) -> bool {
        if !self.matches(&work) {
            return false;
        }
        if work.completed {
            let Some(build) = work.building.take() else {
                return false;
            };
            self.facts = build.facts;
            self.source = work.source;
        }
        if let Some(clock) = work.admin_clock {
            self.facts.admin_clock = clock;
        }
        self.ready = work.ready;
        self.building = work.building;
        true
    }

    pub(in crate::node::channel) fn advance(&mut self, view: &View<'_>) -> Result<bool> {
        let mut work = self.take_work();
        let ready = work.advance(view)?;
        self.install(work);
        Ok(ready)
    }

    pub(in crate::node::channel) fn current(
        &self,
        revision: u64,
        deadline: u64,
    ) -> Result<&SemanticFacts> {
        if !self.ready || self.source != Some((revision, deadline)) {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(&self.facts)
    }
}

impl SemanticWork {
    /// Named current-index slots only, never historical log replay. A turn retains folded
    /// values and a scalar cursor and inspects at most one production page in total.
    pub(in crate::node::channel) fn advance(&mut self, view: &View<'_>) -> Result<bool> {
        self.ready = false;
        let source = (view.revision(), view.facts.deadline());
        self.admin_clock = Some(view.admin_clock());
        if self.source == Some(source) {
            self.ready = true;
            return Ok(true);
        }
        if self
            .building
            .as_ref()
            .is_none_or(|build| build.source != source)
        {
            self.building = Some(SemanticBuild {
                source,
                phase: 0,
                after: None,
                facts: SemanticFacts {
                    admin_clock: view.admin_clock(),
                    ..SemanticFacts::default()
                },
            });
        }
        let build = self
            .building
            .as_mut()
            .ok_or(invalid("governance semantic build"))?;
        let tables = [
            Table::CurrentAuthority,
            Table::Shares,
            Table::Consent,
            Table::ConsentReset,
            Table::EverRevoked,
        ];
        let mut inspected = 0;
        while build.phase < tables.len() && inspected < PAGE_ROWS {
            let Some((key, log)) = view.facts.first(tables[build.phase], build.after)? else {
                build.phase += 1;
                build.after = None;
                continue;
            };
            inspected += 1;
            build.after = Some(key);
            let author: Digest32 = key[..32]
                .try_into()
                .map_err(|_| invalid("governance semantic author"))?;
            let target: Digest32 = key[32..]
                .try_into()
                .map_err(|_| invalid("governance semantic target"))?;
            match build.phase {
                0 => {
                    if target != [0; 32] {
                        return Err(invalid("governance authority key padding"));
                    }
                    let grant = view.authority(&author)?.0;
                    if grant.present && author != view.root {
                        build.facts.authority.insert(author, grant);
                    }
                }
                1 => {
                    let share = view.share_record(log, &author, &target)?;
                    if let Some(share) = &share {
                        let fingerprint = crate::governance::share::service_fingerprint(
                            view.room,
                            &author,
                            &share.name,
                        );
                        build
                            .facts
                            .fingerprints
                            .insert((author, fingerprint), target);
                    }
                    build.facts.shares.insert((author, target), share);
                }
                2 => {
                    std::sync::Arc::make_mut(&mut build.facts.consent).set_consent(
                        author,
                        target,
                        view.consent_state(&author, &target)?,
                    );
                }
                3 => {
                    if target != [0; 32] {
                        return Err(invalid("governance reset key padding"));
                    }
                    std::sync::Arc::make_mut(&mut build.facts.consent)
                        .set_reset(author, view.consent_reset(&author)?);
                }
                4 => {
                    std::sync::Arc::make_mut(&mut build.facts.consent).set_ever_revoked(
                        author,
                        target,
                        view.ever_revoked(&author, &target)?,
                    );
                }
                _ => return Err(invalid("governance semantic phase")),
            }
        }
        if build.phase != tables.len() {
            return Ok(false);
        }
        self.source = Some(build.source);
        // The same owned maps become the completed result; never reserve a second
        // inline SemanticFacts payload or allocate another capsule at this boundary.
        self.completed = true;
        self.ready = true;
        Ok(true)
    }
}

impl SemanticFacts {
    pub(in crate::node::channel) fn admin_clock(&self) -> Option<u64> {
        self.admin_clock
    }

    pub(in crate::node::channel) fn is_admin(&self, target: &Digest32, root: &Digest32) -> bool {
        target == root
            || self
                .authority
                .get(target)
                .is_some_and(|grant| grant.present)
    }

    pub(in crate::node::channel) fn grants_policy(
        &self,
        target: &Digest32,
        root: &Digest32,
    ) -> bool {
        target == root
            || self
                .authority
                .get(target)
                .is_some_and(|grant| grant.present && grant.grants_policy())
    }

    pub(in crate::node::channel) fn share_exact(
        &self,
        host: &Digest32,
        name: &str,
    ) -> Result<Option<super::super::Share>> {
        let hash = crate::hash::sha256(name.as_bytes());
        let share = self.shares.get(&(*host, hash)).and_then(Option::as_ref);
        if share.is_some_and(|share| share.name != name) {
            return Err(invalid("governance share name binding"));
        }
        Ok(share.cloned())
    }

    pub(in crate::node::channel) fn share_selector(
        &self,
        host: &Digest32,
        selector: &str,
    ) -> Result<Option<super::super::Share>> {
        if let Some(share) = self.share_exact(host, selector)? {
            return Ok(Some(share));
        }
        let Ok(fingerprint) = crate::node::link::b32_decode(selector, "service fingerprint") else {
            return Ok(None);
        };
        let Some(name) = self.fingerprints.get(&(*host, fingerprint)) else {
            return Ok(None);
        };
        Ok(self.shares.get(&(*host, *name)).and_then(Clone::clone))
    }

    pub(in crate::node::channel) fn admins(
        &self,
        after: Option<Digest32>,
        limit: usize,
    ) -> TargetPage {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut rows = Vec::new();
        for (target, _) in self
            .authority
            .range((after.map_or(Unbounded, Excluded), Unbounded))
        {
            rows.push(*target);
            if rows.len() == limit.clamp(1, PAGE_ROWS) {
                return TargetPage {
                    rows,
                    next: Some(*target),
                };
            }
        }
        TargetPage { rows, next: None }
    }

    pub(in crate::node::channel) fn shares(
        &self,
        after: Option<(Digest32, Digest32)>,
        limit: usize,
    ) -> SharePage {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut rows = Vec::new();
        for (inspected, (key, share)) in self
            .shares
            .range((after.map_or(Unbounded, Excluded), Unbounded))
            .enumerate()
        {
            if let Some(share) = share {
                rows.push(share.clone());
            }
            if inspected + 1 == limit.clamp(1, PAGE_ROWS) {
                return SharePage {
                    rows,
                    next: Some(*key),
                };
            }
        }
        SharePage { rows, next: None }
    }

    pub(in crate::node::channel) fn consenters(
        &self,
        author: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> TargetPage {
        use std::ops::Bound::{Excluded, Unbounded};
        let Some(readers) = self.consent.consent.get(author) else {
            return TargetPage {
                rows: Vec::new(),
                next: None,
            };
        };
        let mut rows = Vec::new();
        for (inspected, (target, _)) in readers
            .range((after.map_or(Unbounded, Excluded), Unbounded))
            .enumerate()
        {
            if self.consent.can_read(target, author) {
                rows.push(*target);
            }
            if inspected + 1 == limit.clamp(1, PAGE_ROWS) {
                return TargetPage {
                    rows,
                    next: Some(*target),
                };
            }
        }
        TargetPage { rows, next: None }
    }
}

pub(in crate::node::channel) struct View<'a> {
    facts: Read<'a>,
    root: Digest32,
    room: &'a Digest32,
}
impl<'a> View<'a> {
    pub(in crate::node::channel) fn revision(&self) -> u64 {
        self.facts.revision()
    }

    pub(in crate::node::channel) fn open(
        store: &Store,
        sek: &'a Sek,
        room: &'a Digest32,
        root: Digest32,
        now: u64,
    ) -> Result<Self> {
        let facts = Read::open(store, sek, room)?;
        if !facts.ready(now)? {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(Self { facts, root, room })
    }

    /// Single-writer consent/presence/share facts do not depend on the admin
    /// fold. Their source receipt barrier must still be complete.
    pub(in crate::node::channel) fn current(
        store: &Store,
        sek: &'a Sek,
        room: &'a Digest32,
        root: Digest32,
    ) -> Result<Self> {
        let facts = Read::open(store, sek, room)?;
        if !facts.current_ready()? {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(Self { facts, root, room })
    }

    /// The exact current single-writer Presence source, not the last-good display or an
    /// inventory claim. The canonical facts reader retains its normal freshness/binding checks.
    pub(in crate::node::channel) fn presence_sender_generation(
        &self,
        author: &Digest32,
    ) -> Result<Option<u64>> {
        let Some(log) = self.facts.get(Table::Presence, &hash_key(author))? else {
            return Ok(None);
        };
        let entry = self.facts.entry(log)?;
        match GovEntry::body_bound_to(&entry)? {
            GovBody::Presence(presence)
                if entry.skeleton.author_id == *author
                    && presence.body.author_id == *author
                    && presence.body.channel_id == entry.skeleton.channel_id
                    && presence.body.epoch == entry.skeleton.epoch =>
            {
                Ok(Some(presence.body.chain_id))
            }
            _ => Err(invalid("own recovery presence source binding")),
        }
    }

    pub(in crate::node::channel) fn admin_clock(&self) -> Option<u64> {
        self.facts.admin_clock()
    }

    /// Preserve the existing remove-admin selection: every certificate naming
    /// this target that no effective authorized revocation has removed. Return
    /// at most one page, including progress through already revoked statements.
    pub(in crate::node::channel) fn certificates(
        &self,
        target: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<TargetPage> {
        let mut cursor = after;
        let mut rows = Vec::new();
        for _ in 0..limit.clamp(1, PAGE_ROWS) {
            let row = match cursor {
                Some(hash) => self
                    .facts
                    .first(Table::AllCerts, Some(pair(target, &hash)))?,
                None => self.facts.at_or_after(Table::AllCerts, hash_key(target))?,
            }
            .filter(|(key, _)| key[..32] == target[..]);
            let Some((key, log)) = row else {
                return Ok(TargetPage { rows, next: None });
            };
            let hash = key[32..]
                .try_into()
                .map_err(|_| invalid("governance certificate cursor"))?;
            let entry = self.facts.entry(log)?;
            let GovBody::AdminCert(cert) = GovEntry::body_bound_to(&entry)? else {
                return Err(invalid("governance certificate kind"));
            };
            if cert.body.delegate_id() != *target || entry.entry_hash() != hash {
                return Err(invalid("governance certificate binding"));
            }
            cursor = Some(hash);
            if self.facts.get(Table::NamedRevoked, &hash_key(&hash))?
                != Some(self.facts.authority_generation())
            {
                rows.push(hash);
            }
        }
        Ok(TargetPage { rows, next: cursor })
    }

    fn share_record(
        &self,
        log: u64,
        host: &Digest32,
        name_hash: &Digest32,
    ) -> Result<Option<super::super::Share>> {
        let entry = self.facts.entry(log)?;
        let GovBody::ServiceShare(share) = GovEntry::body_bound_to(&entry)? else {
            return Err(invalid("governance share kind"));
        };
        if entry.skeleton.author_id != *host
            || share.body.author_id != *host
            || crate::hash::sha256(share.body.name.as_bytes()) != *name_hash
        {
            return Err(invalid("governance share binding"));
        }
        Ok(share.body.shared.then_some(super::super::Share {
            host: *host,
            name: share.body.name,
            udp: share.body.udp,
            kind: share.body.kind,
        }))
    }

    pub(in crate::node::channel) fn display(&self, genesis: &Genesis) -> Result<Display> {
        self.display_from(Display::genesis(genesis))
    }

    pub(in crate::node::channel) fn display_from(&self, mut display: Display) -> Result<Display> {
        display.revision = self.facts.revision();
        display.valid_until = self.facts.deadline();
        for kind in [
            fold::NAME,
            fold::MESSAGES,
            fold::STEPS,
            fold::END,
            fold::IDLE,
            fold::ANCHORS,
        ] {
            let Some(entry) = self.effect(kind, kind == fold::END)? else {
                continue;
            };
            match GovEntry::body_bound_to(&entry)? {
                GovBody::RoomName(name) if kind == fold::NAME => {
                    display.name = Some(name.body.name)
                }
                GovBody::PolicyUpdate(policy) if kind == fold::MESSAGES => {
                    display.policy.ttl_ms = policy
                        .body
                        .ttl_ms
                        .ok_or(invalid("governance retention effect missing"))?;
                }
                GovBody::StepPolicyUpdate(policy) if kind == fold::STEPS => {
                    display.step_ttl_ms = policy.ttl_ms
                }
                GovBody::Lifecycle(lifecycle) if kind == fold::END => {
                    if !matches!(
                        lifecycle.body.kind,
                        crate::governance::lifecycle::LifecycleKind::End
                    ) {
                        return Err(invalid("governance end effect kind"));
                    }
                    display.lifecycle.ended_by = Some(entry.entry_hash());
                }
                GovBody::Lifecycle(lifecycle) if kind == fold::IDLE => {
                    let crate::governance::lifecycle::LifecycleKind::IdleEnd(ms) =
                        lifecycle.body.kind
                    else {
                        return Err(invalid("governance idle effect kind"));
                    };
                    display.lifecycle.idle_end_ms = Some(ms);
                }
                GovBody::RoomAnchors(anchors) if kind == fold::ANCHORS => {
                    display.anchors = Some(anchors.body.anchors)
                }
                _ => return Err(invalid("governance display effect kind")),
            }
        }
        Ok(display)
    }

    fn effect(&self, kind: u64, first: bool) -> Result<Option<Entry>> {
        let row = if first {
            self.facts
                .at_or_after(Table::EffectKinds, kind_key(kind, 0))?
        } else {
            self.facts
                .last(Table::EffectKinds, Some(kind_key(kind + 1, 0)))?
        };
        row.filter(|(key, _)| key[..8] == kind.to_be_bytes())
            .map(|(_, log)| self.facts.entry(log))
            .transpose()
    }

    fn authority(&self, target: &Digest32) -> Result<(Grant, DenyReason)> {
        if target == &self.root {
            return Ok((Grant::root(), DenyReason::NotAdmin));
        }
        let Some(record) = self.facts.get(Table::CurrentAuthority, &hash_key(target))? else {
            return Ok((Grant::default(), DenyReason::NotAdmin));
        };
        let bytes = self.facts.record(record)?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 4 || d.uint()? != 1 || d.uint()? != self.facts.authority_generation() {
            return Err(invalid("governance current authority stale"));
        }
        let grant = Grant::read(&mut d)?;
        let deny = match d.uint()? {
            1 => DenyReason::NotAdmin,
            2 => DenyReason::CapabilityNotHeld,
            3 => DenyReason::OverAttenuated,
            4 => DenyReason::Expired,
            5 => DenyReason::Revoked,
            _ => return Err(invalid("governance current denial")),
        };
        d.finish()?;
        Ok((grant, deny))
    }

    pub(in crate::node::channel) fn can_end(&self, target: &Digest32) -> Result<bool> {
        let grant = self.authority(target)?.0;
        Ok(grant.present && (grant.admin || grant.policy))
    }

    /// The exact current consent slot, before applying the author's reset. Used only by the
    /// bounded semantic projection rebuild.
    pub(in crate::node::channel) fn consent_state(
        &self,
        author: &Digest32,
        target: &Digest32,
    ) -> Result<Option<Consent>> {
        let Some(log) = self.facts.get(Table::Consent, &pair(author, target))? else {
            return Ok(None);
        };
        let entry = self.facts.entry(log)?;
        if entry.skeleton.author_id != *author {
            return Err(invalid("governance consent author"));
        }
        match GovEntry::body_bound_to(&entry)? {
            GovBody::ConsentGrant(grant)
                if grant.body.target_id == *target
                    && grant.body.author_id == *author
                    && grant.body.epoch == 0 =>
            {
                Ok(Some(Consent::Granted(entry.skeleton.seq)))
            }
            GovBody::ConsentRevocation(revoke)
                if revoke.body.author_id == *author
                    && revoke.body.target_id == *target
                    && revoke.body.epoch == 0 =>
            {
                Ok(Some(Consent::Revoked(entry.skeleton.seq)))
            }
            _ => Err(invalid("governance consent locator binding")),
        }
    }

    pub(in crate::node::channel) fn consent_reset(&self, author: &Digest32) -> Result<Option<u64>> {
        self.facts
            .get(Table::ConsentReset, &hash_key(author))?
            .map(|log| self.facts.entry(log).map(|entry| entry.skeleton.seq))
            .transpose()
    }

    pub(in crate::node::channel) fn ever_revoked(
        &self,
        author: &Digest32,
        target: &Digest32,
    ) -> Result<bool> {
        let Some(log) = self.facts.get(Table::EverRevoked, &pair(author, target))? else {
            return Ok(false);
        };
        let entry = self.facts.entry(log)?;
        match GovEntry::body_bound_to(&entry)? {
            GovBody::ConsentRevocation(revoke)
                if entry.skeleton.author_id == *author
                    && revoke.body.author_id == *author
                    && revoke.body.target_id == *target =>
            {
                Ok(true)
            }
            _ => Err(invalid("governance revoked locator binding")),
        }
    }

    /// Newest-first disk continuation returned in chronological order. Caller
    /// supplies the same exact published revision when asking for older rows.
    pub(in crate::node::channel) fn notices(
        &self,
        before: Option<(u64, Digest32)>,
        revision: Option<u64>,
        limit: usize,
    ) -> Result<NoticePage> {
        self.notices_between(before, None, false, revision, limit)
    }

    pub(in crate::node::channel) fn notices_between(
        &self,
        cursor: Option<(u64, Digest32)>,
        end: Option<(u64, Digest32)>,
        forward: bool,
        revision: Option<u64>,
        limit: usize,
    ) -> Result<NoticePage> {
        if revision.is_some_and(|revision| revision != self.facts.revision()) {
            return Err(Error::Profile(
                "room notices changed; reload the visible page",
            ));
        }
        let first_name = self
            .effect(fold::NAME, true)?
            .map(|entry| entry.entry_hash());
        let mut before_key = cursor.map(|(clock, hash)| {
            let mut key = [0; 64];
            key[..8].copy_from_slice(&clock.to_be_bytes());
            key[8..40].copy_from_slice(&hash);
            key
        });
        let mut rows = Vec::new();
        let mut next = None;
        for _ in 0..limit.clamp(1, PAGE_ROWS) {
            let candidate = if forward {
                self.facts.first(Table::Notices, before_key)?
            } else {
                self.facts.last(Table::Notices, before_key)?
            };
            let Some((key, log)) = candidate else {
                if !forward {
                    rows.reverse();
                }
                return Ok(NoticePage {
                    rows,
                    next: None,
                    revision: self.facts.revision(),
                });
            };
            if key[40..].iter().any(|byte| *byte != 0) {
                return Err(invalid("governance notice order padding"));
            }
            let clock = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| invalid("governance notice clock"))?,
            );
            let hash: Digest32 = key[8..40]
                .try_into()
                .map_err(|_| invalid("governance notice hash"))?;
            if forward && end.is_some_and(|end| (clock, hash) >= end) {
                return Ok(NoticePage {
                    rows,
                    next: None,
                    revision: self.facts.revision(),
                });
            }
            let entry = self.facts.entry(log)?;
            if entry.entry_hash() != hash {
                return Err(invalid("governance notice locator binding"));
            }
            let what = match GovEntry::body_bound_to(&entry)? {
                GovBody::RoomName(name) => {
                    if first_name == Some(hash) {
                        format!("named the room {}", name.body.name)
                    } else {
                        format!("renamed the room to {}", name.body.name)
                    }
                }
                GovBody::PolicyUpdate(policy) => {
                    let ttl = policy
                        .body
                        .ttl_ms
                        .ok_or(invalid("governance notice retention missing"))?;
                    if ttl == 0 {
                        "set the room's retention to forever: from now on no message is removed for its age".to_owned()
                    } else {
                        let d = crate::node::retention::describe(ttl / 1_000);
                        format!(
                            "set the room's retention to {d}: messages older than {d} are removed from now on"
                        )
                    }
                }
                _ => return Err(invalid("governance notice kind")),
            };
            rows.push((
                clock,
                super::super::RoomNotice {
                    entry_hash: hash,
                    author: entry.skeleton.author_id,
                    created_millis: entry.skeleton.claimed_ms,
                    after: None,
                    what,
                },
            ));
            next = Some((clock, hash));
            before_key = Some(key);
        }
        if !forward {
            rows.reverse();
        }
        Ok(NoticePage {
            rows,
            next,
            revision: self.facts.revision(),
        })
    }
}

pub(in crate::node::channel) struct TargetPage {
    pub rows: Vec<Digest32>,
    pub next: Option<Digest32>,
}
pub(in crate::node::channel) struct NoticePage {
    pub rows: Vec<(u64, super::super::RoomNotice)>,
    pub next: Option<(u64, Digest32)>,
    pub revision: u64,
}

pub(in crate::node::channel) struct SharePage {
    pub rows: Vec<super::super::Share>,
    pub next: Option<(Digest32, Digest32)>,
}
