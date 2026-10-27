//! Bounded checked reads of published governance. Historical bodies remain in
//! the source log; callers retain only their scalar view or one requested page.

use super::authority::Grant;
use super::facts::{hash_key, Read, Table};
use super::fold::{self, kind_key};
use crate::atrest::sek::Sek;
use crate::cbor::Decoder;
use crate::error::{Error, Result};
use crate::governance::capability::Capability;
use crate::governance::entry::{GovBody, GovEntry};
use crate::governance::evaluator::{DenyReason, Lifecycle, Verdict};
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

/// A room's admitted-member consent facts held in memory (ADR-038 FX-22): per author, the readers
/// it has consented to with that fact's sequence; each author's reset; every admitted pair ever
/// revoked. Admission bounds this projection by [`AUTHORS_HARD_LIMIT`](super::super::AUTHORS_HARD_LIMIT)
/// squared. Explicit user pagination still reads the sealed index a bounded page at a time, so
/// departed and not-yet-admitted targets keep their cursor semantics without living in RAM.
#[derive(Clone, Default)]
pub(in crate::node::channel) struct ConsentFacts {
    consent: std::collections::BTreeMap<Digest32, std::collections::BTreeMap<Digest32, Consent>>,
    resets: std::collections::BTreeMap<Digest32, u64>,
    revoked: std::collections::BTreeSet<[u8; 64]>,
}

#[derive(Clone, Copy)]
pub(in crate::node::channel) enum Consent {
    Granted(u64),
    Revoked(u64),
}

impl ConsentFacts {
    pub(in crate::node::channel) fn empty() -> Self {
        Self::default()
    }

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

    /// What [`View::can_read`] answers from the index, from memory.
    pub(in crate::node::channel) fn can_read(&self, reader: &Digest32, author: &Digest32) -> bool {
        self.grant_sequence(author, reader).is_some()
    }

    /// What [`View::grant_sequence`] answers from the index, from memory.
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

    /// What [`View::ever_revoked`] answers from the index, from memory.
    pub(in crate::node::channel) fn ever_revoked(
        &self,
        author: &Digest32,
        target: &Digest32,
    ) -> bool {
        self.revoked.contains(&pair(author, target))
    }
}

pub(in crate::node::channel) struct View<'a> {
    facts: Read<'a>,
    root: Digest32,
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
        Ok(Self { facts, root })
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
        Ok(Self { facts, root })
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

    pub(in crate::node::channel) fn admins(
        &self,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<TargetPage> {
        let mut cursor = after;
        let mut rows = Vec::new();
        for _ in 0..limit.clamp(1, PAGE_ROWS) {
            let Some((key, _)) = self
                .facts
                .first(Table::ActiveAdmins, cursor.as_ref().map(hash_key))?
            else {
                return Ok(TargetPage { rows, next: None });
            };
            let target = key[..32]
                .try_into()
                .map_err(|_| invalid("governance admin cursor"))?;
            cursor = Some(target);
            if target == self.root || !self.is_admin(&target)? {
                return Err(invalid("governance active admin binding"));
            }
            rows.push(target);
        }
        Ok(TargetPage { rows, next: cursor })
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

    pub(in crate::node::channel) fn share(
        &self,
        host: &Digest32,
        name: &str,
    ) -> Result<Option<super::super::Share>> {
        let name_hash = crate::hash::sha256(name.as_bytes());
        let Some(log) = self.facts.get(Table::Shares, &pair(host, &name_hash))? else {
            return Ok(None);
        };
        let row = self.share_record(log, host, &name_hash)?;
        if row.as_ref().is_some_and(|row| row.name != name) {
            return Err(invalid("governance share name binding"));
        }
        Ok(row)
    }

    pub(in crate::node::channel) fn share_selector(
        &self,
        host: &Digest32,
        selector: &str,
    ) -> Result<Option<super::super::Share>> {
        if let Some(share) = self.share(host, selector)? {
            return Ok(Some(share));
        }
        let Ok(fingerprint) = crate::node::link::b32_decode(selector, "service fingerprint") else {
            return Ok(None);
        };
        let Some(log) = self
            .facts
            .get(Table::ShareFingerprints, &pair(host, &fingerprint))?
        else {
            return Ok(None);
        };
        let entry = self.facts.entry(log)?;
        let GovBody::ServiceShare(share) = GovEntry::body_bound_to(&entry)? else {
            return Err(invalid("governance share fingerprint kind"));
        };
        if crate::governance::share::service_fingerprint(
            &entry.skeleton.channel_id,
            host,
            &share.body.name,
        ) != fingerprint
        {
            return Err(invalid("governance share fingerprint binding"));
        }
        self.share_record(log, host, &crate::hash::sha256(share.body.name.as_bytes()))
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

    pub(in crate::node::channel) fn shares(
        &self,
        after: Option<(Digest32, Digest32)>,
        limit: usize,
    ) -> Result<SharePage> {
        let mut cursor = after;
        let mut rows = Vec::new();
        for _ in 0..limit.clamp(1, PAGE_ROWS) {
            let Some((key, log)) = self
                .facts
                .first(Table::Shares, cursor.map(|(host, name)| pair(&host, &name)))?
            else {
                return Ok(SharePage { rows, next: None });
            };
            let host = key[..32]
                .try_into()
                .map_err(|_| invalid("governance share host cursor"))?;
            let name = key[32..]
                .try_into()
                .map_err(|_| invalid("governance share name cursor"))?;
            cursor = Some((host, name));
            if let Some(row) = self.share_record(log, &host, &name)? {
                rows.push(row);
            }
        }
        Ok(SharePage { rows, next: cursor })
    }

    pub(in crate::node::channel) fn display(&self, genesis: &Genesis) -> Result<Display> {
        let mut display = Display::genesis(genesis);
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

    pub(in crate::node::channel) fn is_admin(&self, target: &Digest32) -> Result<bool> {
        Ok(self.authority(target)?.0.present)
    }

    pub(in crate::node::channel) fn can_end(&self, target: &Digest32) -> Result<bool> {
        let grant = self.authority(target)?.0;
        Ok(grant.present && (grant.admin || grant.policy))
    }

    pub(in crate::node::channel) fn grants(
        &self,
        target: &Digest32,
        cap: &Capability,
    ) -> Result<Verdict> {
        let (grant, denied) = self.authority(target)?;
        if !grant.present {
            return Ok(Verdict::Denied(denied));
        }
        let set = grant.capabilities();
        if !set.grants(cap) {
            return Ok(Verdict::Denied(DenyReason::CapabilityNotHeld));
        }
        Ok(Verdict::Granted {
            governing: if grant.admin {
                Capability::Admin
            } else {
                cap.clone()
            },
            effective_set: set,
        })
    }

    pub(in crate::node::channel) fn can_read(
        &self,
        reader: &Digest32,
        author: &Digest32,
    ) -> Result<bool> {
        let Some(log) = self.facts.get(Table::Consent, &pair(author, reader))? else {
            return Ok(false);
        };
        let entry = self.facts.entry(log)?;
        if entry.skeleton.author_id != *author {
            return Err(invalid("governance consent author"));
        }
        let grant = match GovEntry::body_bound_to(&entry)? {
            GovBody::ConsentGrant(grant) => grant,
            GovBody::ConsentRevocation(revoke)
                if revoke.body.author_id == *author
                    && revoke.body.target_id == *reader
                    && revoke.body.epoch == 0 =>
            {
                return Ok(false)
            }
            _ => return Err(invalid("governance consent locator kind")),
        };
        if grant.body.target_id != *reader
            || grant.body.author_id != *author
            || grant.body.epoch != 0
        {
            return Err(invalid("governance consent locator binding"));
        }
        let reset = self
            .facts
            .get(Table::ConsentReset, &hash_key(author))?
            .map(|log| self.facts.entry(log))
            .transpose()?
            .map_or(0, |entry| entry.skeleton.seq);
        Ok(entry.skeleton.seq > reset)
    }

    /// The exact current consent slot, before applying the author's reset. Used only by the
    /// bounded admitted-member projection rebuild.
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

    /// The cursor advances over at most one bounded page of index slots, including withdrawn or
    /// reset consent. Explicit pagination preserves off-roster targets without retaining them in
    /// the admitted-member in-memory projection.
    pub(in crate::node::channel) fn consenters(
        &self,
        author: &Digest32,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<TargetPage> {
        let mut after = after;
        let mut rows = Vec::new();
        for _ in 0..limit.clamp(1, PAGE_ROWS) {
            let row = match after {
                Some(target) => self
                    .facts
                    .first(Table::Consent, Some(pair(author, &target)))?,
                None => self.facts.at_or_after(Table::Consent, hash_key(author))?,
            }
            .filter(|(key, _)| key[..32] == author[..]);
            let Some((key, _)) = row else {
                return Ok(TargetPage { rows, next: None });
            };
            let target = key[32..]
                .try_into()
                .map_err(|_| invalid("governance consenter cursor"))?;
            after = Some(target);
            if self.can_read(&target, author)? {
                rows.push(target);
            }
        }
        Ok(TargetPage { rows, next: after })
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
