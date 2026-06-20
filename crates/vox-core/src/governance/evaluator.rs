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
//! - **Effective channel policy**: the latest history/TTL from policy-updates over
//!   genesis, with `deniability_mode` pinned to genesis ([`Evaluator::policy`]).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyReason {
    /// The key holds no valid authority chain to genesis at all.
    NotAdmin,
    /// A chain exists but does not grant the queried capability.
    CapabilityNotHeld,
    /// The only chain(s) granting it have expired.
    Expired,
    /// The only chain(s) granting it were revoked (revocation-wins).
    Revoked,
    /// A delegation in the chain over-attenuated (granted more than its issuer
    /// held); the chain is void.
    OverAttenuated,
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
    /// The effective channel policy after applying policy-updates over genesis.
    policy: ChannelPolicy,
    /// The current channel-global epoch after applying authorized passphrase
    /// rotations over genesis (genesis = epoch 0).
    current_epoch: u64,
    /// Consent edges: author `A` → set of targets `N` that `A` currently consents
    /// to (after single-writer latest-causal resolution + revocation rotation).
    consent: BTreeMap<Digest32, BTreeSet<Digest32>>,
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
        genesis.verify()?;
        let channel_id = genesis.channel_id();
        let root_admin = genesis.creator_pubkey().fingerprint();

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
            if Self::verify_body(&e.body, &key).is_ok() {
                verified.push(e);
            }
        }

        // ---- Pass 2: the single causal relation + canonical order. ----
        let causality = Causality::build(&verified)?;

        // ---- Pass 3: one well-founded stratified resolution. Every authorization
        // and epoch-admission decision is computed from the deciding entry's STRICT
        // causal past only (`hb(X)`); the only concurrent-or-after consultation is
        // the final removal-wins kill test on the head authority. ----
        let mut resolver = Resolver::new(root_admin, &causality, now_secs);
        let head = resolver.head()?;
        let authority = head.authority;
        let current_epoch = head.epoch;
        let policy = resolver.resolve_policy(genesis)?;
        let consent = resolver.resolve_consent()?;

        Ok(Self {
            channel_id,
            root_admin,
            authority,
            policy,
            current_epoch,
            consent,
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
            GovBody::PassphraseRotation(r) => r.verify(author_key),
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

    /// The effective channel policy (history/ttl from updates; deniability pinned).
    #[must_use]
    pub fn policy(&self) -> ChannelPolicy {
        self.policy
    }

    /// The current channel-global epoch (genesis = 0, advanced by each authorized
    /// passphrase-rotation). Callers binding sender keys / join to `(channelID,
    /// epoch)` use this as the in-force epoch.
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
    #[must_use]
    pub fn grants(&self, key: &Digest32, cap: &Capability) -> Verdict {
        match self.authority.get(key) {
            None => Verdict::Denied(DenyReason::NotAdmin),
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

/// Resolved authority + established epoch over some causal scope.
#[derive(Clone)]
struct Resolved {
    authority: BTreeMap<Digest32, CapabilitySet>,
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
/// Two intertwined quantities are resolved together over a scope:
/// - the **established epoch** (chain of in-effect, authorized passphrase-rotations,
///   each chaining `old_epoch == current`), and
/// - the **authority** (chain-to-genesis + monotonic attenuation + expiry +
///   removal-wins + the causal-supersession/ascending-hash tie-break).
///
/// An entry is **in-effect** iff its body epoch equals the epoch established in its
/// strict past (`epoch_strict_before`): a stale- or future-epoch entry confers
/// nothing — which structurally prevents the future-epoch bootstrap (an epoch-1
/// cert is not in-effect at the causal position where the rotation-to-epoch-1 is
/// being authorized, so it cannot authorize that rotation).
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
    /// about `X` (authorizing a revocation, a rotation, or a delegation's issuer)
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
    /// epoch via `channel_and_epoch`; a rotation carries its `old_epoch`.)
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
        // ---- Established epoch: fold in-effect, authorized rotations in canonical
        // order, each chaining old_epoch == current. ----
        let mut epoch = 0u64;
        for e in &self.causality.order {
            if !scope.contains(&e.entry_hash) {
                continue;
            }
            let GovBody::PassphraseRotation(r) = &e.body else {
                continue;
            };
            // In-effect: the rotation's old_epoch must equal the epoch established
            // in ITS strict past, AND chain off the running epoch.
            if !self.in_effect(e)? {
                continue;
            }
            if r.body.old_epoch != epoch {
                continue;
            }
            // Authorized: author holds passphrase-rotate in the rotation's strict
            // past (never from concurrent/later facts).
            let before = self.strict_before(&e.entry_hash)?;
            let authorized = before
                .authority
                .get(&e.author_id)
                .is_some_and(|c| c.grants(&Capability::PassphraseRotate));
            if authorized && r.body.new_epoch > epoch {
                epoch = r.body.new_epoch;
            }
        }

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
                .is_some_and(|c| c.grants(&Capability::Delegate))
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
        let mut issuer_ok: BTreeMap<Digest32, bool> = BTreeMap::new();
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
            let issuer_superset = before
                .authority
                .get(&c.body.issuer_id)
                .is_some_and(|ic| c.body.capability_set.is_within(ic));
            issuer_ok.insert(e.entry_hash, unexpired && in_effect && issuer_superset);
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
            // Removal-wins: killed iff some authorized revocation of this delegate's
            // lineage is NOT causally-before this delegation (concurrent or after).
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

        Ok(Resolved { authority, epoch })
    }

    /// Resolve the effective channel policy: fold in-effect policy-updates whose
    /// author holds `policy` in the update's STRICT past, over the canonical order,
    /// taking the latest history/ttl. `deniability_mode` is genesis-immutable.
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
            if let Some(hm) = p.body.history_mode {
                policy.history_mode = hm;
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
        let present: BTreeSet<Digest32> = entries.iter().map(|e| e.entry_hash).collect();
        let by_hash: BTreeMap<Digest32, &GovEntry> =
            entries.iter().map(|e| (e.entry_hash, *e)).collect();

        // Same-author seq-1 predecessor: the greatest-seq entry below this one's seq
        // for the same author. This is the within-author causal edge.
        let prev_same_author = |e: &GovEntry| -> Option<Digest32> {
            entries
                .iter()
                .filter(|o| o.author_id == e.author_id && o.seq < e.seq)
                .max_by_key(|o| o.seq)
                .map(|o| o.entry_hash)
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

        // Canonical order: Kahn, smallest-hash-ready-first (over the SAME `preds`).
        let mut remaining: BTreeMap<Digest32, BTreeSet<Digest32>> = preds.clone();
        let mut emitted: BTreeSet<Digest32> = BTreeSet::new();
        let mut order: Vec<&GovEntry> = Vec::with_capacity(entries.len());
        while order.len() < entries.len() {
            let next = remaining
                .iter()
                .find(|(_, p)| p.iter().all(|d| emitted.contains(d)))
                .map(|(h, _)| *h);
            match next {
                Some(h) => {
                    emitted.insert(h);
                    remaining.remove(&h);
                    if let Some(e) = by_hash.get(&h) {
                        order.push(e);
                    }
                }
                None => {
                    // No ready node while entries remain ⇒ a cycle in the supplied
                    // causal edges. Reject rather than producing a bogus order or
                    // risking unbounded strict-past recursion (defense-in-depth: the
                    // `Resolver` also guards re-entrancy).
                    return Err(Error::GovernanceCycle);
                }
            }
        }

        // Transitive ancestor closure over the SAME predecessor relation, computed
        // in canonical order so each node's ancestors are already final (the order
        // is a valid topological sort, guaranteed acyclic by the check above).
        let mut ancestors: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
        for e in &order {
            let mut anc: BTreeSet<Digest32> = BTreeSet::new();
            if let Some(direct) = preds.get(&e.entry_hash) {
                for d in direct {
                    anc.insert(*d);
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

#[cfg(test)]
mod causality_tests {
    use super::*;
    use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
    use crate::governance::GovBody;
    use crate::identity::composite::SoftwareRootSigner;

    /// A throwaway governance body (its content is irrelevant to the causal
    /// relation, which only reads author_id/seq/entry_hash/causal_predecessors).
    fn dummy_body() -> GovBody {
        let r = SoftwareRootSigner::from_component_seeds(&[1; 32], &[2; 32]).unwrap();
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
        };
        GovBody::Genesis(Box::new(
            Genesis::create_with_nonce(&r, 0, policy, [0; 16]).unwrap(),
        ))
    }

    fn node(author: u8, seq: u64, hash: u8, preds: &[u8]) -> GovEntry {
        let mut p = BTreeSet::new();
        for h in preds {
            p.insert([*h; 32]);
        }
        GovEntry::from_parts(dummy_body(), [hash; 32], [author; 32], seq, p)
    }

    #[test]
    fn reachability_closes_through_same_author_chain_across_authors() {
        // B authors B1 (seq1) then B2 (seq2, same author). C (a different author)
        // references ONLY B2. C must causally reach B1 THROUGH B2's same-author
        // seq-1 edge — the bug the fix closes (previously C did not reach B1).
        let b1 = node(0xB, 1, 0x01, &[]);
        let b2 = node(0xB, 2, 0x02, &[]); // same author, seq2; implicit edge → B1
        let c = node(0xC, 1, 0x03, &[0x02]); // references B2 only
        let entries = [&b1, &b2, &c];
        let causality = Causality::build(&entries).unwrap();

        // C happens-after B2 (direct) AND B1 (transitively via B2's seq chain).
        assert!(causality.happens_after(&[0x03; 32], &[0x02; 32]));
        assert!(
            causality.happens_after(&[0x03; 32], &[0x01; 32]),
            "C must reach B1 through B2's same-author seq edge"
        );
        // B2 happens-after B1 (same-author seq). B1 after nothing.
        assert!(causality.happens_after(&[0x02; 32], &[0x01; 32]));
        assert!(!causality.happens_after(&[0x01; 32], &[0x02; 32]));
    }

    #[test]
    fn canonical_order_and_happens_after_agree() {
        // The canonical order must be consistent with happens_after: if X
        // happens-after Y, X appears later in the order (one relation, two views).
        let b1 = node(0xB, 1, 0x10, &[]);
        let b2 = node(0xB, 2, 0x05, &[]); // smaller hash but causally AFTER b1
        let c = node(0xC, 1, 0x01, &[0x05]); // smallest hash but AFTER b2 (→b1)
        let entries = [&b1, &b2, &c];
        let causality = Causality::build(&entries).unwrap();

        let pos = |h: u8| {
            causality
                .order
                .iter()
                .position(|e| e.entry_hash == [h; 32])
                .unwrap()
        };
        // Despite c having the smallest hash, causality forces b1 < b2 < c.
        assert!(pos(0x10) < pos(0x05));
        assert!(pos(0x05) < pos(0x01));
        assert!(causality.happens_after(&[0x01; 32], &[0x10; 32]));
    }

    #[test]
    fn cyclic_causal_predecessors_rejected_not_hung() {
        // Two cross-author entries each name the other as a causal predecessor: a
        // cycle. `Causality::build` must return Err(GovernanceCycle), not loop.
        let a = node(0xA, 1, 0x01, &[0x02]); // A → references P (hash 0x02)
        let p = node(0xB, 1, 0x02, &[0x01]); // P → references A (hash 0x01): cycle
        let entries = [&a, &p];
        assert!(matches!(
            Causality::build(&entries),
            Err(Error::GovernanceCycle)
        ));
    }

    #[test]
    fn self_referential_predecessor_rejected() {
        // An entry naming ITSELF as a causal predecessor is a trivial cycle.
        let a = node(0xA, 1, 0x01, &[0x01]);
        let entries = [&a];
        assert!(matches!(
            Causality::build(&entries),
            Err(Error::GovernanceCycle)
        ));
    }
}
