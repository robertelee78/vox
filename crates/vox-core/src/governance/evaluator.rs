//! The deterministic governance evaluator (ADR-007 §"Canonical encoding &
//! evaluator", §"Conflict resolution under partition") — the release-gated core.
//!
//! The evaluator is a **total function of log state**: given the genesis record,
//! the set of governance entries with their causal coordinates
//! ([`crate::governance::entry::GovEntry`]), and a resolver from author
//! fingerprint to that author's composite root key, it computes the *same* verdict
//! on every client, regardless of the order entries were received. That totality
//! is the precondition for the golden-vector equality gate (two correct
//! implementations agree bit-for-bit on every vector).
//!
//! ## What it decides
//! - **Admin authority** for any key: is there a valid delegation chain to genesis
//!   granting a capability, not expired, and not superseded by a revocation?
//!   ([`Evaluator::authority_of`], [`Evaluator::grants`]).
//! - **Consent visibility**: who can read whom, from the single-writer consent
//!   timeline ([`Evaluator::can_read`], [`Evaluator::readers_of`]).
//! - **Effective channel policy**: the genesis policy with the latest retention (TTL)
//!   from policy-updates ([`Evaluator::policy`]).
//!
//! ## One causal relation + one canonical order (the unifying construction)
//! There is a **single** causal relation (`Causality`), used identically for the
//! canonical order and every happens-after query — they can never diverge.
//! `predecessors(node) = node.causal_predecessors (present-in-set) ∪ { the
//! same-author seq-1 entry }`, closed transitively. The **canonical order** is the
//! deterministic Kahn linear extension that, among entries whose predecessors are
//! already emitted, emits the **smallest entry hash** next — a total function of
//! (entry set + causal edges), independent of input/receipt order. All governance
//! state is folded over this single order (no non-transitive comparator).
//!
//! ## The rules (ADR-007 §"Conflict resolution")
//! 1. **Chain to genesis.** Every authority claim chains back to the genesis
//!    creator (the root admin). A delegation issued by a non-admin is void.
//! 2. **Monotonic attenuation.** A delegation grants only capabilities at or below
//!    its issuer's set ([`crate::governance::capability::CapabilitySet::is_within`]).
//!    An over-attenuation cert is rejected, regardless of ordering.
//! 3. **Expiry.** A cert with non-zero `expiry <= now` confers nothing.
//! 4. **Revocation-wins (by delegate lineage), stratified by causal position.** An
//!    admin-delegation revocation `R` names a delegation cert; its effect is to
//!    remove the **named cert's delegate's** authority for every delegation of that
//!    delegate that is **concurrent-with-or-after** `R` (a delegation survives only
//!    if it is causally-after `R` — a re-delegation). Crucially, `R`'s own
//!    *authorization* is decided from authority over all delegations applying only
//!    the authorized revocations **strictly causally-before `R`** — never
//!    concurrent/later ones. Because causality is a DAG, processing revocations in
//!    canonical order makes each one's authorization final when reached: the
//!    computation is **acyclic — there is no fixed-point oscillation** (a
//!    self-revocation converges to one stable verdict). (Consent has no race —
//!    single-writer — so it uses "the delegate's latest action in canonical order
//!    wins".)
//! 5. **Causal supersession + tie-break.** Among a delegate's surviving
//!    delegations, the **causally-maximal** ones govern; a causally-later
//!    attenuation supersedes an earlier broader grant. Among causally-maximal
//!    *concurrent* survivors, the one **latest in the canonical order** (largest
//!    entry hash) governs — the deterministic tie-break, applied *only* to the
//!    concurrent maximal set, never across causally-ordered delegations.
//!
//! There is **no fixed-point iteration**: every decision recurses into the strict
//! causal past (`hb(X)`), which shrinks strictly along the DAG, so the computation
//! is well-founded and acyclic by construction. Results per entry are memoized.
//!
//! ## Enforcement honesty (ADR-007 §"Enforcement honesty")
//! The evaluator decides *authorization*; only **forward** guarantees are
//! cryptographic. A consent revocation stops a target reading the author's
//! **future** messages (the author rotated to a key the target never receives);
//! it cannot recall ciphertext the target already holds keys for. The evaluator
//! reflects this: [`Evaluator::can_read`] reports the *current* authorization, not
//! a claim that past traffic became unreadable.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::governance::capability::{Capability, CapabilitySet};
use crate::governance::entry::{GovBody, GovEntry};
use crate::governance::genesis::{ChannelPolicy, Genesis};
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;

/// The verdict for an authority query: granted (with the governing capability and
/// the effective set) or denied (with a reason).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The query is authorized. `governing` is the specific capability that
    /// authorized it; `effective_set` is the full capability set the key holds.
    Granted {
        /// The capability that authorized the specific query.
        governing: Capability,
        /// The full effective capability set of the queried key.
        effective_set: CapabilitySet,
    },
    /// The query is denied, with a machine-stable reason.
    Denied(DenyReason),
}

impl Verdict {
    /// Whether this verdict authorizes the query.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, Verdict::Granted { .. })
    }
}

/// Why an authority query was denied — a closed, machine-stable set so golden
/// vectors can pin the exact reason, not just "denied".
///
/// For a key with no effective authority, the resolver classifies **every**
/// in-scope delegation to that key (revoked / expired / over-attenuated /
/// chain-less or out-of-epoch) and reports the highest-priority reason:
/// `Revoked` > `Expired` > `OverAttenuated` > `NotAdmin` — a deliberate removal
/// outranks a passive lapse, which outranks a void cert, which outranks having
/// no chain at all. Deterministic, so vectors can pin it. *(2026-09-19 review:
/// every such case previously collapsed to `NotAdmin`.)*
///
/// **The declaration order is that priority**, lowest first: the resolver keeps the `max` of the
/// reasons it meets, and `Ord` is derived. `OverAttenuated` was declared last, so it outranked
/// `Revoked` and `Expired`, the inverse of the rule above (V210-83).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DenyReason {
    /// The key holds no valid authority chain to genesis at all.
    NotAdmin,
    /// A chain exists but does not grant the queried capability.
    CapabilityNotHeld,
    /// A delegation in the chain over-attenuated (granted more than its issuer
    /// held); the chain is void.
    OverAttenuated,
    /// The only chain(s) granting it have expired.
    Expired,
    /// The only chain(s) granting it were revoked (revocation-wins).
    Revoked,
}

/// The deterministic evaluator over a channel's governance log.
///
/// Built once from the genesis + the governance entries via [`Evaluator::build`],
/// which performs all structural verification (signatures, channel/epoch binding,
/// chain-to-genesis, attenuation) up front so queries are pure lookups over the
/// resolved state.
#[derive(Debug)]
pub struct Evaluator {
    /// The channelID this evaluator is scoped to (from genesis).
    channel_id: Digest32,
    /// The root admin (genesis creator) fingerprint.
    root_admin: Digest32,
    /// Resolved effective capability set per identity fingerprint (admins only;
    /// non-admins are absent). Computed with attenuation + expiry + revocation +
    /// tie-break already applied.
    authority: BTreeMap<Digest32, CapabilitySet>,
    /// For each identity that was named as a delegate but holds no effective
    /// authority, the classified reason (see [`DenyReason`]). Identities never
    /// named are simply absent (plain `NotAdmin`).
    denied: BTreeMap<Digest32, DenyReason>,
    /// The effective channel policy after applying policy-updates over genesis.
    policy: ChannelPolicy,
    /// The channel-global epoch: the genesis epoch, 0. Passphrase rotation, the only
    /// thing that advanced it, is removed (V030-32).
    current_epoch: u64,
    /// Consent edges: author `A` → set of targets `N` that `A` currently consents
    /// to (after single-writer latest-causal resolution).
    consent: BTreeMap<Digest32, BTreeSet<Digest32>>,
    /// The identities this node has admitted as authors of the channel — its view of
    /// *who is a member*.
    ///
    /// Membership in ADR-007 is emergent and has no roster: each node admits authors
    /// from a join it witnessed or a vouched bundle record, so this is necessarily
    /// local state. That is not a weakness here, because the decision it feeds is
    /// local too — a host deciding whether to serve *its own* service consults the
    /// keys it verified itself, and refuses anyone it has not (fail closed).
    /// The admitted-author set this evaluator was built with. Not an authorization input
    /// (membership confers no capability, ADR-017 M17.7), and kept because callers ask an
    /// evaluator what membership it was built over.
    #[allow(
        dead_code,
        reason = "read by callers via accessors; no longer an authorization input"
    )]
    members: BTreeSet<Digest32>,
    /// The room's lifecycle as its log states it (V030-08): who has left, whether the creator
    /// ended it, and the idle end the creator chose.
    lifecycle: Lifecycle,
    /// The entries that passed pass 1 (bound to this channel, signature verified under
    /// their author's root), by entry hash: what [`Evaluator::build_reusing`] need not
    /// verify again.
    verified: BTreeSet<Digest32>,
}

/// What a room's lifecycle facts say (V030-08), folded from the log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lifecycle {
    /// The log entry in which the creator ended the room, if it has.
    pub ended_by: Option<Digest32>,
    /// The idle end the creator chose, in seconds; `None` when it chose none.
    pub idle_end_secs: Option<u64>,
}

impl Evaluator {
    /// Build the evaluator from genesis + governance entries.
    ///
    /// `now_secs` is the wall clock used only for **expiry** comparisons (a cert
    /// with `0 < expiry <= now_secs` is expired). `author_key` resolves an author
    /// fingerprint to its composite root public key for signature verification;
    /// returning `None` for an entry's author makes that entry's signature
    /// unverifiable and the entry is dropped (it cannot confer authority).
    ///
    /// Steps:
    /// 1. Verify the genesis self-signature; keep only entries bound to this
    ///    channel whose composite signature verifies under their author's root.
    /// 2. Build the single `Causality` relation (predecessors + transitive
    ///    ancestors + canonical total order).
    /// 3. Run the well-founded stratified `Resolver`: admin authority, established
    ///    epoch, policy, and consent — every authorization/epoch-admission decision
    ///    derived from the deciding entry's strict causal past only, with the
    ///    concurrent removal-wins kill test, causal supersession, and the
    ///    ascending-hash tie-break applied to the head authority.
    pub fn build<F>(
        genesis: &Genesis,
        entries: &[GovEntry],
        now_secs: u64,
        author_key: F,
    ) -> Result<Self>
    where
        F: Fn(&Digest32) -> Option<CompositePublicKey>,
    {
        Self::build_with_members(genesis, entries, now_secs, author_key, BTreeSet::new())
    }

    /// [`Evaluator::build`] with this node's **admitted-author set**, recorded so callers
    /// can ask what membership an evaluator was built over. Membership confers no
    /// capability (ADR-017 M17.7, PRD-001 R44).
    pub fn build_with_members<F>(
        genesis: &Genesis,
        entries: &[GovEntry],
        now_secs: u64,
        author_key: F,
        members: BTreeSet<Digest32>,
    ) -> Result<Self>
    where
        F: Fn(&Digest32) -> Option<CompositePublicKey>,
    {
        Self::build_reusing(genesis, entries, now_secs, author_key, members, None)
    }

    /// [`Evaluator::build_with_members`], taking from `prior` — an evaluator built earlier for
    /// the same channel — which entries have already passed pass 1, so their signatures are
    /// not verified again (V210-71).
    ///
    /// Sound because an entry's hash covers its signed body, and an author's root key is
    /// fixed by its fingerprint: an entry that verified under its author's key once verifies
    /// under it for good. The author's key must still be known now, exactly as for an entry
    /// verified afresh. Every other pass runs over the whole set as before, so the result is
    /// the one [`Evaluator::build_with_members`] gives.
    ///
    /// A room re-verified every governance signature on every rebuild, under its lock: a
    /// joiner's first sync of a room with a few hundred consents spent minutes doing so.
    pub fn build_reusing<F>(
        genesis: &Genesis,
        entries: &[GovEntry],
        now_secs: u64,
        author_key: F,
        members: BTreeSet<Digest32>,
        prior: Option<&Evaluator>,
    ) -> Result<Self>
    where
        F: Fn(&Digest32) -> Option<CompositePublicKey>,
    {
        genesis.verify()?;
        let channel_id = genesis.channel_id();
        let root_admin = genesis.creator_pubkey().fingerprint();
        let known = prior
            .filter(|p| p.channel_id == channel_id)
            .map(|p| &p.verified);

        // ---- Pass 1: keep only entries that bind to THIS channel and whose
        // composite signature verifies under their author's root. ----
        let mut verified: Vec<&GovEntry> = Vec::new();
        for e in entries {
            let (cid, _epoch) = e.body.channel_and_epoch();
            if cid != channel_id {
                continue; // cross-channel: never trusted (ADR-007 binding)
            }
            let Some(key) = author_key(&e.author_id) else {
                continue; // author key unknown: cannot verify, cannot trust
            };
            if known.is_some_and(|k| k.contains(&e.entry_hash))
                || Self::verify_body(&e.body, &key).is_ok()
            {
                verified.push(e);
            }
        }
        let verified_hashes: BTreeSet<Digest32> = verified.iter().map(|e| e.entry_hash).collect();

        // ---- Pass 2: the single causal relation + canonical order. ----
        let causality = Causality::build(&verified)?;

        // ---- Pass 3: one well-founded stratified resolution. Every authorization
        // and epoch-admission decision is computed from the deciding entry's STRICT
        // causal past only (`hb(X)`); the only concurrent-or-after consultation is
        // the final removal-wins kill test on the head authority. ----
        let mut resolver = Resolver::new(root_admin, &causality, now_secs);
        let head = resolver.head()?;
        let authority = head.authority;
        let denied = head.denied;
        let current_epoch = head.epoch;
        let policy = resolver.resolve_policy(genesis)?;
        let consent = resolver.resolve_consent()?;
        let lifecycle = resolver.resolve_lifecycle()?;

        Ok(Self {
            channel_id,
            root_admin,
            authority,
            denied,
            policy,
            current_epoch,
            consent,
            members,
            lifecycle,
            verified: verified_hashes,
        })
    }

    /// Verify one governance body's signature under `author_key` (the body's
    /// issuer/author root). Genesis verifies its own self-signature.
    fn verify_body(body: &GovBody, author_key: &CompositePublicKey) -> Result<()> {
        match body {
            GovBody::Genesis(g) => g.verify(),
            GovBody::AdminCert(c) => c.verify(author_key),
            GovBody::AdminRevocation(r) => r.verify(author_key),
            GovBody::ConsentGrant(g) => g.verify(author_key),
            GovBody::ConsentRevocation(r) => r.verify(author_key),
            GovBody::PolicyUpdate(p) => p.verify(author_key),
            GovBody::Lifecycle(l) => l.verify(author_key),
            GovBody::Presence(p) => p.verify(author_key),
            GovBody::ServiceShare(s) => s.verify(author_key),
        }
    }

    // ---- Queries (pure lookups over resolved state) ----

    /// The channelID this evaluator is scoped to.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The root admin (genesis creator) fingerprint.
    #[must_use]
    pub fn root_admin(&self) -> Digest32 {
        self.root_admin
    }

    /// The effective channel policy (the genesis policy, with the retention from updates).
    #[must_use]
    pub fn policy(&self) -> ChannelPolicy {
        self.policy
    }

    /// The current channel-global epoch: the genesis epoch, 0 (V030-32 removed the
    /// passphrase rotation that advanced it). Callers binding sender keys / join to
    /// `(channelID, epoch)` use this as the in-force epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Whether `key` is currently an admin (holds any authority chain to genesis).
    #[must_use]
    pub fn is_admin(&self, key: &Digest32) -> bool {
        self.authority.contains_key(key)
    }

    /// The full effective capability set of `key`, or an empty set if it holds no
    /// authority.
    #[must_use]
    pub fn authority_of(&self, key: &Digest32) -> CapabilitySet {
        self.authority.get(key).cloned().unwrap_or_default()
    }

    /// The authoritative verdict for "does `key` hold `cap`?": the governing
    /// capability + effective set on grant, or a stable [`DenyReason`] on denial.
    ///
    /// One source: **certificates** — the ADR-007 delegation chain rooted at the genesis
    /// creator, already resolved with attenuation, expiry, revocation and the tie-break
    /// applied. Membership confers nothing, and neither does a genesis's legacy service
    /// grant (ADR-017 M17.7, PRD-001 R44): reach to a service is the host's own decision at
    /// its dial gate, never a capability.
    #[must_use]
    pub fn grants(&self, key: &Digest32, cap: &Capability) -> Verdict {
        match self.authority.get(key) {
            None => Verdict::Denied(
                self.denied
                    .get(key)
                    .copied()
                    .unwrap_or(DenyReason::NotAdmin),
            ),
            Some(set) => {
                if set.grants(cap) {
                    // The governing capability is `admin` if held (it implies all),
                    // else the exact capability.
                    let governing = if set.grants(&Capability::Admin) {
                        Capability::Admin
                    } else {
                        cap.clone()
                    };
                    Verdict::Granted {
                        governing,
                        effective_set: set.clone(),
                    }
                } else {
                    Verdict::Denied(DenyReason::CapabilityNotHeld)
                }
            }
        }
    }

    /// The room's lifecycle as its log states it: who has left, whether its creator ended it,
    /// and the idle end its creator chose (V030-08).
    #[must_use]
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }
    /// Whether `reader` currently has consent to read `author` (outbound axis
    /// only; compose with [`crate::governance::visibility`] for the inbound axis).
    /// Forward-guarantee semantics: this is the *current* authorization.
    #[must_use]
    pub fn can_read(&self, reader: &Digest32, author: &Digest32) -> bool {
        self.consent
            .get(author)
            .is_some_and(|targets| targets.contains(reader))
    }

    /// The set of identities `author` currently consents to (who may read
    /// `author`), in deterministic order.
    #[must_use]
    pub fn readers_of(&self, author: &Digest32) -> BTreeSet<Digest32> {
        self.consent.get(author).cloned().unwrap_or_default()
    }

    /// Every identity that currently holds admin authority, in deterministic order.
    #[must_use]
    pub fn admins(&self) -> BTreeSet<Digest32> {
        self.authority.keys().copied().collect()
    }
}

/// Resolved authority + established epoch over some causal scope, plus the
/// classified reason for every named delegate that ended up with no authority.
#[derive(Clone)]
struct Resolved {
    authority: BTreeMap<Digest32, CapabilitySet>,
    denied: BTreeMap<Digest32, DenyReason>,
    epoch: u64,
}

/// The well-founded stratified resolver (ADR-007 §"Conflict resolution").
///
/// For ANY entry `X`, its *authorization* and the *epoch it is admitted under* are
/// computed from `hb(X)` — its strict causal past — only, never from concurrent or
/// causally-later facts. Because `hb` shrinks strictly along the causal DAG, the
/// recursion is well-founded; results are memoized per entry. The single place a
/// concurrent-or-after fact is consulted is the **removal-wins** kill test on the
/// final (head) authority.
///
/// Over a scope it resolves the **authority** (chain-to-genesis + monotonic
/// attenuation + expiry + removal-wins + the causal-supersession/ascending-hash
/// tie-break) and the established epoch, which is always the genesis epoch since
/// passphrase rotation was removed (V030-32).
///
/// An entry is **in-effect** iff its body epoch equals the epoch established in its
/// strict past: an entry bound to any other epoch confers nothing.
struct Resolver<'a> {
    root_admin: Digest32,
    causality: &'a Causality<'a>,
    now_secs: u64,
    /// Memo: entry hash → resolved authority+epoch over that entry's STRICT past.
    strict_before: BTreeMap<Digest32, Resolved>,
    /// Entries whose strict-past resolution is currently on the call stack. A
    /// re-entry means the causal graph has a cycle the `Causality` cycle check did
    /// not catch; the resolver fails with [`Error::GovernanceCycle`] instead of
    /// recursing without bound (defense-in-depth — `Causality::build` already
    /// rejects cycles, so for well-formed input this never triggers).
    in_progress: BTreeSet<Digest32>,
}

impl<'a> Resolver<'a> {
    fn new(root_admin: Digest32, causality: &'a Causality<'a>, now_secs: u64) -> Self {
        Self {
            root_admin,
            causality,
            now_secs,
            strict_before: BTreeMap::new(),
            in_progress: BTreeSet::new(),
        }
    }

    /// The head resolution over ALL entries.
    fn head(&mut self) -> Result<Resolved> {
        let all: BTreeSet<Digest32> = self.causality.order.iter().map(|e| e.entry_hash).collect();
        self.resolve_scope(&all)
    }

    /// The resolved authority+epoch over an entry's STRICT causal past
    /// (`ancestors[X]`), memoized. This is the *only* authority/epoch a decision
    /// about `X` (authorizing a revocation or a delegation's issuer)
    /// may consult.
    fn strict_before(&mut self, x: &Digest32) -> Result<Resolved> {
        if let Some(r) = self.strict_before.get(x) {
            return Ok(r.clone());
        }
        // Re-entrancy ⇒ a cycle slipped past `Causality::build`'s check; fail loud.
        if !self.in_progress.insert(*x) {
            return Err(Error::GovernanceCycle);
        }
        let past = self.causality.ancestors.get(x).cloned().unwrap_or_default();
        let resolved = self.resolve_scope(&past)?;
        self.in_progress.remove(x);
        self.strict_before.insert(*x, resolved.clone());
        Ok(resolved)
    }

    /// Whether entry `e` is **in-effect**: its body epoch equals the epoch
    /// established in its strict past. (Genesis/cert/consent/etc. all carry an
    /// epoch via `channel_and_epoch`.)
    fn in_effect(&mut self, e: &GovEntry) -> Result<bool> {
        let (_cid, body_epoch) = e.body.channel_and_epoch();
        let before = self.strict_before(&e.entry_hash)?;
        Ok(body_epoch == before.epoch)
    }

    /// Resolve authority + established epoch over `scope` (a downward-closed set of
    /// entry hashes). Every entry's admission and authorization is decided from its
    /// own strict past (recursively, memoized); removal-wins is applied within
    /// `scope`.
    fn resolve_scope(&mut self, scope: &BTreeSet<Digest32>) -> Result<Resolved> {
        // ---- Established epoch: always the genesis epoch. Only a passphrase rotation
        // ever moved it, and rotation is removed (V030-32): no command wrote one, and a
        // body of that kind no longer parses. ----
        let epoch = 0u64;

        // ---- Authorized revocations in scope: each authorized from ITS strict
        // past (not from `scope` at large, never from concurrent/later facts). ----
        let mut authorized_revs: Vec<(&GovEntry, Digest32)> = Vec::new();
        for e in &self.causality.order {
            if !scope.contains(&e.entry_hash) {
                continue;
            }
            let GovBody::AdminRevocation(rb) = &e.body else {
                continue;
            };
            if !self.in_effect(e)? {
                continue; // a stale/future-epoch revocation has no effect
            }
            // The named cert must be a delegation in scope; resolve its delegate.
            let Some(target) = self.causality.order.iter().find_map(|o| match &o.body {
                GovBody::AdminCert(c)
                    if o.entry_hash == rb.body.revoked_delegation_hash
                        && scope.contains(&o.entry_hash) =>
                {
                    Some(c.body.delegate_id())
                }
                _ => None,
            }) else {
                continue;
            };
            let before = self.strict_before(&e.entry_hash)?;
            if before
                .authority
                .get(&rb.body.issuer_id)
                .is_some_and(|c| c.grants(&Capability::Admin))
            {
                authorized_revs.push((e, target));
            }
        }

        // ---- Authority: grants LFP over in-effect delegations whose ISSUER is
        // authorized in the delegation's strict past, with removal-wins + causal
        // supersession + ascending-hash tie-break. ----
        // Pre-compute, per in-effect delegation in scope, whether its issuer holds
        // a superset in the delegation's strict past (chain-to-genesis is already
        // baked into that recursive authority).
        // Alongside, classify why a delegation does NOT confer authority, so a
        // denied query can name the reason. Per delegation the checks are ranked
        // Revoked > Expired > OverAttenuated > NotAdmin (an out-of-epoch cert or
        // one whose issuer holds no chain at all is "no valid chain").
        let mut issuer_ok: BTreeMap<Digest32, bool> = BTreeMap::new();
        let mut reason_for: BTreeMap<Digest32, DenyReason> = BTreeMap::new();
        for e in &self.causality.order {
            if !scope.contains(&e.entry_hash) {
                continue;
            }
            let GovBody::AdminCert(c) = &e.body else {
                continue;
            };
            let unexpired = c.body.expiry == 0 || c.body.expiry > self.now_secs;
            let in_effect = self.in_effect(e)?;
            let before = self.strict_before(&e.entry_hash)?;
            // The issuer must hold a superset of the granted set in this
            // delegation's strict past (chain-to-genesis + monotonic attenuation),
            // and the cert must be unexpired and bound to the in-force epoch.
            let issuer_authority = before.authority.get(&c.body.issuer_id);
            let issuer_superset =
                issuer_authority.is_some_and(|ic| c.body.capability_set.is_within(ic));
            // Only the room's creator names admins (#319): a certificate any
            // other member issued confers nothing, whatever that member holds.
            let by_creator = c.body.issuer_id == self.root_admin;
            issuer_ok.insert(
                e.entry_hash,
                unexpired && in_effect && issuer_superset && by_creator,
            );

            // Removal-wins: killed iff some authorized revocation of this delegate's
            // lineage is NOT causally-before this delegation (concurrent or after).
            // Evaluated for every delegation (not only structurally valid ones) so
            // a revoked-and-expired cert still classifies as Revoked.
            let delegate = c.body.delegate_id();
            let killed = authorized_revs.iter().any(|(r, target)| {
                *target == delegate && !self.causality.happens_after(&e.entry_hash, &r.entry_hash)
            });
            let reason = if killed {
                DenyReason::Revoked
            } else if !unexpired {
                DenyReason::Expired
            } else if in_effect && issuer_authority.is_some() && !issuer_superset {
                DenyReason::OverAttenuated
            } else {
                DenyReason::NotAdmin
            };
            let slot = reason_for.entry(delegate).or_insert(reason);
            *slot = (*slot).max(reason);
        }

        let mut authority: BTreeMap<Digest32, CapabilitySet> = BTreeMap::new();
        authority.insert(self.root_admin, CapabilitySet::admin());

        let mut effective_for: BTreeMap<Digest32, Vec<&GovEntry>> = BTreeMap::new();
        for e in &self.causality.order {
            if !scope.contains(&e.entry_hash) {
                continue;
            }
            let GovBody::AdminCert(c) = &e.body else {
                continue;
            };
            if !issuer_ok.get(&e.entry_hash).copied().unwrap_or(false) {
                continue;
            }
            let delegate = c.body.delegate_id();
            let killed = authorized_revs.iter().any(|(r, target)| {
                *target == delegate && !self.causality.happens_after(&e.entry_hash, &r.entry_hash)
            });
            if killed {
                continue;
            }
            effective_for.entry(delegate).or_default().push(e);
        }

        for (delegate, candidates) in effective_for {
            if delegate == self.root_admin {
                continue; // root authority is genesis-fixed
            }
            // Causal supersession: keep only the causally-maximal candidates.
            let maximal: Vec<&GovEntry> = candidates
                .iter()
                .copied()
                .filter(|d| {
                    !candidates.iter().any(|o| {
                        o.entry_hash != d.entry_hash
                            && self.causality.happens_after(&o.entry_hash, &d.entry_hash)
                    })
                })
                .collect();
            // Ascending-hash tie-break among concurrent maximals: the last in the
            // canonical order (largest entry hash) governs.
            if let Some(governing) = maximal.last() {
                if let GovBody::AdminCert(c) = &governing.body {
                    authority.insert(delegate, c.body.capability_set.clone());
                }
            }
        }

        // A named delegate with no effective authority keeps its classified
        // reason; one that ended up authorized (or is the genesis root) needs none.
        let denied: BTreeMap<Digest32, DenyReason> = reason_for
            .into_iter()
            .filter(|(d, _)| !authority.contains_key(d))
            .collect();

        Ok(Resolved {
            authority,
            denied,
            epoch,
        })
    }

    /// Resolve the effective channel policy: fold in-effect policy-updates whose
    /// author holds `policy` in the update's STRICT past, over the canonical order,
    /// taking the latest retention (`ttl`). A policy update carries nothing else
    /// (V030-32): history mode and the suite floor stay as the genesis set them.
    fn resolve_policy(&mut self, genesis: &Genesis) -> Result<ChannelPolicy> {
        let mut policy = genesis.body.policy;
        let order: Vec<&GovEntry> = self.causality.order.clone();
        for e in order {
            let GovBody::PolicyUpdate(p) = &e.body else {
                continue;
            };
            if !self.in_effect(e)? {
                continue;
            }
            let before = self.strict_before(&e.entry_hash)?;
            if !before
                .authority
                .get(&e.author_id)
                .is_some_and(|c| c.grants(&Capability::Policy))
            {
                continue;
            }
            if let Some(ttl) = p.body.ttl {
                policy.ttl = ttl;
            }
        }
        Ok(policy)
    }

    /// Resolve consent edges. Consent is single-writer (`A` alone authors `A`'s
    /// grants/revocations), so the last in-effect action per `(A, target)` in the
    /// canonical order wins. Only in-effect (correct-epoch) actions count.
    fn resolve_consent(&mut self) -> Result<BTreeMap<Digest32, BTreeSet<Digest32>>> {
        let mut last: BTreeMap<(Digest32, Digest32), bool> = BTreeMap::new();
        let order: Vec<&GovEntry> = self.causality.order.clone();
        for e in order {
            let in_effect = self.in_effect(e)?;
            if !in_effect {
                continue;
            }
            match &e.body {
                GovBody::ConsentGrant(g) => {
                    last.insert((g.body.author_id, g.body.target_id), true);
                }
                GovBody::ConsentRevocation(r) => {
                    last.insert((r.body.author_id, r.body.target_id), false);
                }
                // A member that left and joined again starts its consents over (V030-08): it
                // joined from scratch and holds none of the keys its earlier grants released,
                // so they no longer describe who reads it. Its statement that it is back says so.
                GovBody::Presence(p) if p.body.here && p.body.author_id == e.author_id => {
                    last.retain(|(author, _), _| *author != p.body.author_id);
                }
                _ => {}
            }
        }
        let mut consent: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
        for ((author, target), granted) in last {
            if granted {
                consent.entry(author).or_default().insert(target);
            }
        }
        Ok(consent)
    }

    /// Fold the room-lifecycle facts (V030-08). Each counts only from its signer (`issuer_id` is
    /// the signer, and the signer is the entry's author). An end counts from the root admin, or
    /// from an admin the creator delegated, as of the end's strict causal past; an idle end only
    /// from the root admin. The last idle end wins.
    fn resolve_lifecycle(&mut self) -> Result<Lifecycle> {
        use crate::governance::lifecycle::LifecycleKind;
        let mut out = Lifecycle::default();
        let order: Vec<&GovEntry> = self.causality.order.clone();
        for e in order {
            let GovBody::Lifecycle(l) = &e.body else {
                continue;
            };
            if l.body.issuer_id != e.author_id {
                continue;
            }
            match l.body.kind {
                LifecycleKind::End => {
                    let admin = l.body.issuer_id == self.root_admin
                        || self
                            .strict_before(&e.entry_hash)?
                            .authority
                            .get(&l.body.issuer_id)
                            .is_some_and(|c| !c.is_empty());
                    if admin {
                        out.ended_by.get_or_insert(e.entry_hash);
                    }
                }
                LifecycleKind::IdleEnd(secs) if l.body.issuer_id == self.root_admin => {
                    out.idle_end_secs = Some(secs);
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The **single causal relation** over a governance entry set, plus its canonical
/// total order — the one source of truth used by both ordering and every
/// happens-after query (so they can never diverge).
///
/// The causal predecessor of a node is the unified set:
/// `predecessors(node) = node.causal_predecessors (present-in-set)
///   ∪ { the same-author entry at seq-1 }`.
/// `ancestors` is the transitive closure of that relation (strict — excludes the
/// node itself). `order` is the deterministic Kahn linear extension that, among all
/// entries whose predecessors are already emitted, emits the **smallest entry hash**
/// next — a total function of (entry set + causal edges), independent of input
/// order. A causal cycle (impossible in a hash-linked DAG, but possible in
/// malformed/adversarial caller input) is rejected with [`Error::GovernanceCycle`]
/// rather than producing a bogus order or risking unbounded recursion.
struct Causality<'a> {
    /// The canonical total order (a linear extension of the causal DAG).
    order: Vec<&'a GovEntry>,
    /// Strict transitive ancestors per entry hash (excludes the entry itself).
    ancestors: BTreeMap<Digest32, BTreeSet<Digest32>>,
}

impl<'a> Causality<'a> {
    /// Build the unified relation, its transitive closure, and the canonical order.
    ///
    /// Returns [`Error::GovernanceCycle`] if the caller-supplied causal edges form a
    /// cycle (the Kahn pass cannot make progress while entries remain). A genuine
    /// hash-linked log is acyclic, so this only fires on malformed/adversarial
    /// input — and rejecting it here keeps the strict-past recursion in [`Resolver`]
    /// well-founded (no unbounded recursion / stack overflow).
    fn build(entries: &[&'a GovEntry]) -> Result<Self> {
        // **Near-linear in the edges, not cubic** (V210-71). A node names every governance
        // entry it holds as a causal predecessor (`gov_heads`), so the edges are dense, and the
        // three steps below were O(N^2), O(N^3) and O(N^3) as written first. The relation, the
        // order and the closure they produce are unchanged.
        let present: BTreeSet<Digest32> = entries.iter().map(|e| e.entry_hash).collect();
        let by_hash: BTreeMap<Digest32, &GovEntry> =
            entries.iter().map(|e| (e.entry_hash, *e)).collect();

        // Same-author seq-1 predecessor: the greatest-seq entry below this one's seq
        // for the same author. This is the within-author causal edge. Among entries tied on
        // that seq, the last in input order, as `Iterator::max_by_key` chose it.
        let mut by_author: BTreeMap<Digest32, Vec<(u64, usize)>> = BTreeMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_author.entry(e.author_id).or_default().push((e.seq, i));
        }
        for seqs in by_author.values_mut() {
            seqs.sort_unstable();
        }
        let prev_same_author = |e: &GovEntry| -> Option<Digest32> {
            let seqs = by_author.get(&e.author_id)?;
            let below = seqs.partition_point(|(s, _)| *s < e.seq);
            below
                .checked_sub(1)
                .map(|at| entries[seqs[at].1].entry_hash)
        };

        // Direct predecessors (in-set only).
        let mut preds: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
        for e in entries {
            let mut p: BTreeSet<Digest32> = e
                .causal_predecessors
                .iter()
                .copied()
                .filter(|h| present.contains(h))
                .collect();
            if let Some(prev) = prev_same_author(e) {
                p.insert(prev);
            }
            preds.insert(e.entry_hash, p);
        }

        // Canonical order: Kahn, smallest-hash-ready-first (over the SAME `preds`), with a
        // ready set and a count of unemitted predecessors per entry rather than a rescan.
        let mut waiting: BTreeMap<Digest32, usize> = BTreeMap::new();
        let mut successors: BTreeMap<Digest32, Vec<Digest32>> = BTreeMap::new();
        let mut ready: BTreeSet<Digest32> = BTreeSet::new();
        for (h, p) in &preds {
            waiting.insert(*h, p.len());
            if p.is_empty() {
                ready.insert(*h);
            }
            for d in p {
                successors.entry(*d).or_default().push(*h);
            }
        }
        let mut order: Vec<&GovEntry> = Vec::with_capacity(entries.len());
        let mut position: BTreeMap<Digest32, usize> = BTreeMap::new();
        while order.len() < entries.len() {
            let Some(h) = ready.pop_first() else {
                // No ready node while entries remain ⇒ a cycle in the supplied
                // causal edges. Reject rather than producing a bogus order or
                // risking unbounded strict-past recursion (defense-in-depth: the
                // `Resolver` also guards re-entrancy).
                return Err(Error::GovernanceCycle);
            };
            position.insert(h, order.len());
            if let Some(e) = by_hash.get(&h) {
                order.push(e);
            }
            for s in successors.get(&h).into_iter().flatten() {
                if let Some(n) = waiting.get_mut(s) {
                    *n -= 1;
                    if *n == 0 {
                        ready.insert(*s);
                    }
                }
            }
        }

        // Transitive ancestor closure over the SAME predecessor relation, computed
        // in canonical order so each node's ancestors are already final (the order
        // is a valid topological sort, guaranteed acyclic by the check above).
        //
        // Direct predecessors are taken latest first, and one already in the set is skipped:
        // it got there as an ancestor of a predecessor taken before it, so its own ancestors
        // are in the set already (the closure is transitive).
        let mut ancestors: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
        for e in &order {
            let mut anc: BTreeSet<Digest32> = BTreeSet::new();
            if let Some(direct) = preds.get(&e.entry_hash) {
                let mut latest_first: Vec<&Digest32> = direct.iter().collect();
                latest_first.sort_unstable_by_key(|d| std::cmp::Reverse(position.get(*d)));
                for d in latest_first {
                    if !anc.insert(*d) {
                        continue;
                    }
                    if let Some(da) = ancestors.get(d) {
                        anc.extend(da.iter().copied());
                    }
                }
            }
            ancestors.insert(e.entry_hash, anc);
        }

        Ok(Self { order, ancestors })
    }

    /// Whether `a` causally happens-**after** `b` (i.e. `b` is a strict ancestor of
    /// `a`) under the one unified relation.
    fn happens_after(&self, a: &Digest32, b: &Digest32) -> bool {
        self.ancestors.get(a).is_some_and(|anc| anc.contains(b))
    }
}

/// Re-exported for callers building expiry-aware queries; the evaluator compares a
/// non-zero cert expiry against this many epoch-seconds at [`Evaluator::build`].
pub type EpochSeconds = u64;
