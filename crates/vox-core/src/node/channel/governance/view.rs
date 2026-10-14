//! Bounded checked reads of published governance. Historical bodies remain in
//! the source log; callers retain only their scalar view or one requested page.

use super::authority::Grant;
use super::facts::{Read, Table, hash_key};
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

pub(super) const REFRESHING: &str = "room governance is refreshing; try again when it is ready";
pub(super) const PAGE_ROWS: usize = 64;

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
pub(super) struct Display {
    pub name: Option<String>,
    pub policy: ChannelPolicy,
    pub step_ttl_ms: u64,
    pub lifecycle: Lifecycle,
    pub anchors: Option<BootstrapSet>,
    pub revision: u64,
}
impl Display {
    pub(super) fn genesis(genesis: &Genesis) -> Self {
        Self {
            name: None,
            policy: genesis.body.policy,
            step_ttl_ms: crate::governance::step_policy::DEFAULT_STEP_TTL_MS,
            lifecycle: Lifecycle::default(),
            anchors: None,
            revision: 0,
        }
    }
}

pub(super) struct View<'a> {
    facts: Read<'a>,
    root: Digest32,
}
impl<'a> View<'a> {
    pub(super) fn open(
        store: &Store,
        sek: &'a Sek,
        room: &'a Digest32,
        root: Digest32,
        through: u64,
        now: u64,
    ) -> Result<Self> {
        let facts = Read::open(store, sek, room)?;
        if !facts.ready(through, now) {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(Self { facts, root })
    }

    pub(super) fn display(&self, genesis: &Genesis) -> Result<Display> {
        let mut display = Display::genesis(genesis);
        display.revision = self.facts.revision();
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

    pub(super) fn is_admin(&self, target: &Digest32) -> Result<bool> {
        Ok(self.authority(target)?.0.present)
    }

    pub(super) fn grants(&self, target: &Digest32, cap: &Capability) -> Result<Verdict> {
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

    pub(super) fn can_read(&self, reader: &Digest32, author: &Digest32) -> Result<bool> {
        let Some(log) = self.facts.get(Table::Consent, &pair(author, reader))? else {
            return Ok(false);
        };
        let entry = self.facts.entry(log)?;
        if entry.skeleton.author_id != *author {
            return Err(invalid("governance consent author"));
        }
        let GovBody::ConsentGrant(grant) = GovEntry::body_bound_to(&entry)? else {
            return Ok(false);
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

    pub(super) fn ever_revoked(&self, author: &Digest32, target: &Digest32) -> Result<bool> {
        Ok(self
            .facts
            .get(Table::EverRevoked, &pair(author, target))?
            .is_some())
    }

    pub(super) fn presence(&self, author: &Digest32) -> Result<Option<(u64, bool)>> {
        let Some(log) = self.facts.get(Table::Presence, &hash_key(author))? else {
            return Ok(None);
        };
        let entry = self.facts.entry(log)?;
        let GovBody::Presence(body) = GovEntry::body_bound_to(&entry)? else {
            return Err(invalid("governance presence kind"));
        };
        if entry.skeleton.author_id != *author || body.body.author_id != *author {
            return Err(invalid("governance presence author"));
        }
        Ok(Some((entry.skeleton.seq, body.body.here)))
    }

    pub(super) fn back(&self, author: &Digest32) -> Result<Option<(u64, u64)>> {
        let Some(log) = self.facts.get(Table::Back, &hash_key(author))? else {
            return Ok(None);
        };
        let entry = self.facts.entry(log)?;
        let GovBody::Presence(body) = GovEntry::body_bound_to(&entry)? else {
            return Err(invalid("governance admission kind"));
        };
        if entry.skeleton.author_id != *author || !body.body.here {
            return Err(invalid("governance admission binding"));
        }
        Ok(Some((entry.skeleton.seq, entry.skeleton.claimed_ms)))
    }

    pub(super) fn grant_sequence(
        &self,
        author: &Digest32,
        target: &Digest32,
    ) -> Result<Option<u64>> {
        if !self.can_read(target, author)? {
            return Ok(None);
        }
        let log = self
            .facts
            .get(Table::Consent, &pair(author, target))?
            .ok_or(invalid("governance consent disappeared"))?;
        Ok(Some(self.facts.entry(log)?.skeleton.seq))
    }

    /// The cursor advances over inspected slots, including withdrawn/reset
    /// consent. An empty page is not an end-of-range claim.
    pub(super) fn consenters(
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
    pub(super) fn notices(
        &self,
        before: Option<(u64, Digest32)>,
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
        let mut before_key = before.map(|(clock, hash)| {
            let mut key = [0; 64];
            key[..8].copy_from_slice(&clock.to_be_bytes());
            key[8..40].copy_from_slice(&hash);
            key
        });
        let mut rows = Vec::new();
        let mut next = None;
        for _ in 0..limit.clamp(1, PAGE_ROWS) {
            let Some((key, log)) = self.facts.last(Table::Notices, before_key)? else {
                rows.reverse();
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
        rows.reverse();
        Ok(NoticePage {
            rows,
            next,
            revision: self.facts.revision(),
        })
    }
}

pub(super) struct TargetPage {
    pub rows: Vec<Digest32>,
    pub next: Option<Digest32>,
}
pub(super) struct NoticePage {
    pub rows: Vec<(u64, super::super::RoomNotice)>,
    pub next: Option<(u64, Digest32)>,
    pub revision: u64,
}
