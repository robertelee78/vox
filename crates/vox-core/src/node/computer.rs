//! Daemon-owned computer identity and the signed records of explicit computer trust (ADR-035).
//! This is separate from node identities, rooms, and their passphrases. The account daemon is
//! the sole writer; one atomic file contains its vault and retained management transaction.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::atrest::{Argon2Profile, IdentityVault};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, sha256_concat, Digest32};
use crate::identity::backup::{IdentityBackup, SelfSeed};
use crate::identity::composite::{
    CompositePublicKey, CompositeSignature, RootSigner, SoftwareRootSigner,
};
use crate::identity::rng::random_array;
use crate::node::paths::{create_private_dir, write_private_file, Account};
use zeroize::Zeroizing;

mod pairing;
pub use pairing::{ComputerIdentity, ComputerStatus, Management, PairingPreview};

/// The one fixed policy, displayed before either operator approves an enrollment.
pub const POLICY: &str = "Every managed node can read every other managed node. Each computer's selected personal node can drive the non-personal nodes. Earlier individual grants are replaced by this policy; there are no per-node exceptions. Pairing does not join rooms or change repository bindings.";
/// Typed computer-management protocol version, checked before pairing payloads.
pub const PROTOCOL: u64 = 1;
/// One-time invitations last ten minutes.
pub const INVITE_LIFETIME_MS: u64 = 600_000;
const MAX_RECORDS: usize = 4096;
const MAX_STATE: u64 = 64 * 1024 * 1024;

fn bad() -> Error {
    Error::Profile("computer management state is malformed; it was left unchanged")
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn arity(d: &mut Decoder<'_>, n: usize) -> Result<()> {
    if d.array()? == n {
        Ok(())
    } else {
        Err(bad())
    }
}
fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?.try_into().map_err(|_| bad())
}
fn count(d: &mut Decoder<'_>) -> Result<usize> {
    let n = d.array()?;
    if n <= MAX_RECORDS {
        Ok(n)
    } else {
        Err(bad())
    }
}

/// Canonical signed management record. The domain is supplied by its typed caller, never by a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// Canonical body bytes.
    pub body: Vec<u8>,
    /// Composite public identity.
    pub public: Vec<u8>,
    /// Composite signature over domain and body.
    pub signature: Vec<u8>,
}
impl Signed {
    /// Sign one canonical body under its application-specific domain.
    pub fn create(domain: &[u8], body: Vec<u8>, signer: &dyn RootSigner) -> Result<Self> {
        let signature = signer.sign(&[domain, &body].concat())?.to_bytes().to_vec();
        Ok(Self {
            body,
            public: signer.public_key().to_bytes().to_vec(),
            signature,
        })
    }
    /// Verify the complete composite signature and the expected management identity.
    pub fn verify(&self, domain: &[u8], expected: &Digest32) -> Result<()> {
        let key =
            CompositePublicKey::from_bytes(self.public.as_slice().try_into().map_err(|_| bad())?)?;
        if key.fingerprint() != *expected {
            return Err(Error::SignatureInvalid);
        }
        key.verify(
            &[domain, &self.body].concat(),
            &CompositeSignature::from_bytes(
                self.signature.as_slice().try_into().map_err(|_| bad())?,
            )?,
        )
    }
    /// Canonical envelope.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&self.body)
            .bytes(&self.public)
            .bytes(&self.signature);
        e.finish()
    }
    /// Read a canonical envelope without interpreting its signed body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        arity(&mut d, 3)?;
        let s = Self {
            body: d.bytes()?.to_vec(),
            public: d.bytes()?.to_vec(),
            signature: d.bytes()?.to_vec(),
        };
        d.finish()?;
        Ok(s)
    }
}

/// Authenticated presentation of one installation. Names never establish authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    /// Management composite public key.
    pub public: Vec<u8>,
    /// Presented computer name.
    pub name: String,
    /// Stable installation discriminator, independent of the physical machine or account name.
    pub installation: Digest32,
}
impl Description {
    /// Identity fingerprint.
    pub fn fingerprint(&self) -> Result<Digest32> {
        Ok(
            CompositePublicKey::from_bytes(self.public.as_slice().try_into().map_err(|_| bad())?)?
                .fingerprint(),
        )
    }
    /// Canonical presentation bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&self.public)
            .text(&self.name)
            .bytes(&self.installation);
        e.finish()
    }
    /// Read a presentation; controls and unbounded display names are rejected.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        arity(&mut d, 3)?;
        let s = Self {
            public: d.bytes()?.to_vec(),
            name: d.text()?.to_owned(),
            installation: digest(&mut d)?,
        };
        d.finish()?;
        s.fingerprint()?;
        if s.name.is_empty() || s.name.len() > 128 || s.name.chars().any(char::is_control) {
            return Err(bad());
        }
        Ok(s)
    }
}

/// The exact initial group intent approved by both operators. Neither founder has a special role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// Inviter-authenticated deadline for fresh approvals, Unix milliseconds.
    pub expires: u64,
    /// Random incarnation nonce.
    pub nonce: Digest32,
    /// Inviting installation, then joining installation.
    pub computers: [Description; 2],
    /// Fresh grant identities, in the same order.
    pub grants: [Digest32; 2],
    /// Both signatures of the identical canonical body, when approved.
    pub approvals: [Option<Signed>; 2],
}
impl Genesis {
    /// The fixed policy digest binds its version and permission meaning.
    pub fn policy_digest() -> Digest32 {
        sha256_concat(&[b"vox/computer-policy/v1\0", POLICY.as_bytes()])
    }
    /// Canonical genesis; presentation names are bound but do not identify a member.
    pub fn body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(8)
            .uint(PROTOCOL)
            .bytes(&self.nonce)
            .bytes(&Self::policy_digest())
            .bytes(&self.computers[0].encode())
            .bytes(&self.computers[1].encode())
            .bytes(&self.grants[0])
            .bytes(&self.grants[1])
            .uint(self.expires);
        e.finish()
    }
    /// Immutable group incarnation.
    pub fn incarnation(&self) -> Digest32 {
        sha256_concat(&[b"vox/computer-genesis/v1\0", &self.body()])
    }
    /// Verify every approval present, or require both for an active group.
    pub fn verify(&self, complete: bool) -> Result<()> {
        if self.computers[0].fingerprint()? == self.computers[1].fingerprint()?
            || self.grants[0] == self.grants[1]
        {
            return Err(bad());
        }
        for (i, a) in self.approvals.iter().enumerate() {
            match a {
                Some(a) => {
                    if a.body != self.body() {
                        return Err(bad());
                    }
                    a.verify(
                        b"vox/computer-genesis/v1\0",
                        &self.computers[i].fingerprint()?,
                    )?;
                }
                None if complete => {
                    return Err(Error::Profile(
                        "computer pairing still needs the other operator's approval",
                    ))
                }
                None => {}
            }
        }
        Ok(())
    }
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3).bytes(&self.body());
        for a in &self.approvals {
            e.bytes(&a.as_ref().map(Signed::encode).unwrap_or_default());
        }
        e.finish()
    }
    fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        arity(&mut d, 3)?;
        let mut body = Decoder::new(d.bytes()?);
        arity(&mut body, 8)?;
        if body.uint()? != PROTOCOL {
            return Err(bad());
        }
        let nonce = digest(&mut body)?;
        if digest(&mut body)? != Self::policy_digest() {
            return Err(bad());
        }
        let computers = [
            Description::decode(body.bytes()?)?,
            Description::decode(body.bytes()?)?,
        ];
        let grants = [digest(&mut body)?, digest(&mut body)?];
        let expires = body.uint()?;
        body.finish()?;
        let mut approvals = [None, None];
        for a in &mut approvals {
            let b = d.bytes()?;
            if !b.is_empty() {
                *a = Some(Signed::decode(b)?);
            }
        }
        d.finish()?;
        let g = Self {
            expires,
            nonce,
            computers,
            grants,
            approvals,
        };
        g.verify(false)?;
        Ok(g)
    }
}

/// A node's proof of opted-in management, also countersigned by its enrolled computer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Node signature binds both complete identities, group, nonce, and previous binding.
    pub node: Signed,
    /// Manager countersignature of exactly the same body.
    pub computer: Signed,
    /// Presented node name; authenticated in its computer's roster, never an authority.
    pub name: String,
}
impl Binding {
    /// Initial binding input, signed inside the already-unlocked node actor.
    pub fn body(
        node: &CompositePublicKey,
        computer: &CompositePublicKey,
        group: &Digest32,
        nonce: &Digest32,
    ) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .uint(PROTOCOL)
            .bytes(&node.to_bytes())
            .bytes(&computer.to_bytes())
            .bytes(group)
            .bytes(nonce)
            .bytes(&[]);
        e.finish()
    }
    /// Verify both identities. An initial binding cannot claim a transfer from another manager.
    pub fn verify(&self, manager: &Digest32, group: &Digest32) -> Result<Digest32> {
        if self.node.body != self.computer.body {
            return Err(bad());
        }
        let mut d = Decoder::new(&self.node.body);
        arity(&mut d, 6)?;
        if d.uint()? != PROTOCOL {
            return Err(bad());
        }
        let key = CompositePublicKey::from_bytes(d.bytes()?.try_into().map_err(|_| bad())?)?;
        let cp = CompositePublicKey::from_bytes(d.bytes()?.try_into().map_err(|_| bad())?)?;
        if cp.fingerprint() != *manager || digest(&mut d)? != *group {
            return Err(bad());
        }
        let _nonce = digest(&mut d)?;
        if !d.bytes()?.is_empty() {
            return Err(bad());
        }
        d.finish()?;
        self.node
            .verify(b"vox/computer-binding/v1\0", &key.fingerprint())?;
        self.computer
            .verify(b"vox/computer-binding/v1\0", manager)?;
        if !super::presentation::safe_name(&self.name) {
            return Err(bad());
        }
        Ok(key.fingerprint())
    }
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .bytes(&self.node.encode())
            .bytes(&self.computer.encode())
            .text(&self.name);
        e.finish()
    }
    fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        arity(&mut d, 3)?;
        let s = Self {
            node: Signed::decode(d.bytes()?)?,
            computer: Signed::decode(d.bytes()?)?,
            name: d.text()?.to_owned(),
        };
        d.finish()?;
        Ok(s)
    }
}

/// One signed roster, including the saved app selection. Headless installations have none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    /// Signed canonical roster body, retained verbatim for receipts and replay checking.
    pub signed: Signed,
}
impl Roster {
    /// Produce a control event from locally obtained bindings. Every event names its exact
    /// author grant, predecessor and complete known causal frontier.
    fn create(
        g: &Genesis,
        previous: Option<&Roster>,
        mut heads: Vec<Digest32>,
        bindings: &[Binding],
        personal: Option<Digest32>,
        signer: &dyn RootSigner,
    ) -> Result<Self> {
        let author = signer.fingerprint();
        let side = g
            .computers
            .iter()
            .position(|c| c.fingerprint().ok() == Some(author))
            .ok_or(Error::SignatureInvalid)?;
        let (sequence, previous) = match previous {
            Some(r) => (r.event()?.sequence.checked_add(1).ok_or_else(bad)?, r.id()),
            None => (1, [0; 32]),
        };
        if previous != [0; 32] {
            heads.push(previous);
        }
        if heads.is_empty() {
            heads.push(g.incarnation());
        }
        heads.sort();
        heads.dedup();
        let mut body = Encoder::new();
        body.array(2)
            .bytes(personal.as_ref().map(|v| v.as_slice()).unwrap_or_default())
            .array(bindings.len());
        for b in bindings {
            b.verify(&author, &g.incarnation())?;
            body.bytes(&b.encode());
        }
        let mut e = Encoder::new();
        e.array(10)
            .uint(PROTOCOL)
            .bytes(&g.incarnation())
            .bytes(&signer.public_key().to_bytes())
            .bytes(&g.grants[side])
            .uint(sequence)
            .bytes(&previous)
            .array(heads.len());
        for head in heads {
            e.bytes(&head);
        }
        e.text("roster")
            .bytes(&body.finish())
            .bytes(&random_array::<32>()?);
        Ok(Self {
            signed: Signed::create(b"vox/computer-control/v1\0", e.finish(), signer)?,
        })
    }
    fn id(&self) -> Digest32 {
        sha256(&self.signed.encode())
    }
    fn event(&self) -> Result<RosterEvent> {
        let mut d = Decoder::new(&self.signed.body);
        arity(&mut d, 10)?;
        if d.uint()? != PROTOCOL {
            return Err(bad());
        }
        let group = digest(&mut d)?;
        let public = d.bytes()?;
        if public != self.signed.public {
            return Err(Error::SignatureInvalid);
        }
        let author =
            CompositePublicKey::from_bytes(public.try_into().map_err(|_| bad())?)?.fingerprint();
        let grant = digest(&mut d)?;
        let sequence = d.uint()?;
        let previous = digest(&mut d)?;
        let n = count(&mut d)?;
        let mut heads = Vec::with_capacity(n);
        for _ in 0..n {
            heads.push(digest(&mut d)?);
        }
        if heads.is_empty()
            || heads.windows(2).any(|w| w[0] >= w[1])
            || (previous != [0; 32] && !heads.contains(&previous))
            || sequence == 0
        {
            return Err(bad());
        }
        if d.text()? != "roster" {
            return Err(bad());
        }
        let mut body = Decoder::new(d.bytes()?);
        arity(&mut body, 2)?;
        let p = body.bytes()?;
        let personal = if p.is_empty() {
            None
        } else {
            Some(p.try_into().map_err(|_| bad())?)
        };
        let n = count(&mut body)?;
        let mut bindings = Vec::with_capacity(n);
        for _ in 0..n {
            bindings.push(Binding::decode(body.bytes()?)?);
        }
        body.finish()?;
        let _operation = digest(&mut d)?;
        d.finish()?;
        Ok(RosterEvent {
            group,
            author,
            grant,
            sequence,
            previous,
            heads,
            personal,
            bindings,
        })
    }
    /// Verify the signed event and its node bindings; causal admission is performed by the
    /// retained-history fold before this roster can become effective policy.
    pub fn read(
        &self,
        manager: &Digest32,
        group: &Digest32,
    ) -> Result<(u64, Option<Digest32>, Vec<Binding>)> {
        self.signed.verify(b"vox/computer-control/v1\0", manager)?;
        let e = self.event()?;
        if e.author != *manager || e.group != *group {
            return Err(bad());
        }
        let mut seen = std::collections::BTreeSet::new();
        for b in &e.bindings {
            if !seen.insert(b.verify(manager, group)?) {
                return Err(bad());
            }
        }
        if e.personal.is_some_and(|p| !seen.contains(&p)) {
            return Err(bad());
        }
        Ok((e.sequence, e.personal, e.bindings))
    }
}
struct RosterEvent {
    group: Digest32,
    author: Digest32,
    grant: Digest32,
    sequence: u64,
    previous: Digest32,
    heads: Vec<Digest32>,
    personal: Option<Digest32>,
    bindings: Vec<Binding>,
}

#[derive(Clone)]
pub(crate) struct Invitation {
    pub id: Digest32,
    pub secret: Zeroizing<[u8; 16]>,
    pub transport: Zeroizing<Digest32>,
    pub expires: u64,
    pub nonce: Digest32,
    pub grants: [Digest32; 2],
    pub cancelled: bool,
    pub target: Option<Digest32>,
}
impl Invitation {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::for_secrets();
        e.array(9)
            .bytes(&self.id)
            .bytes(self.secret.as_ref())
            .bytes(self.transport.as_ref())
            .uint(self.expires)
            .bytes(&self.nonce)
            .bytes(&self.grants[0])
            .bytes(&self.grants[1])
            .uint(u64::from(self.cancelled))
            .bytes(
                self.target
                    .as_ref()
                    .map(|x| x.as_slice())
                    .unwrap_or_default(),
            );
        e.finish()
    }
    fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        arity(&mut d, 9)?;
        let id = digest(&mut d)?;
        let secret = Zeroizing::new(d.bytes()?.try_into().map_err(|_| bad())?);
        let transport = Zeroizing::new(digest(&mut d)?);
        let expires = d.uint()?;
        let nonce = digest(&mut d)?;
        let grants = [digest(&mut d)?, digest(&mut d)?];
        let cancelled = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(bad()),
        };
        let p = d.bytes()?;
        let target = if p.is_empty() {
            None
        } else {
            Some(p.try_into().map_err(|_| bad())?)
        };
        d.finish()?;
        Ok(Self {
            id,
            secret,
            transport,
            expires,
            nonce,
            grants,
            cancelled,
            target,
        })
    }
}

#[derive(Clone)]
pub(crate) struct AppliedPolicy {
    pub revision: u64,
    pub interval: Digest32,
    // Creation revisions of covered grants are retained even after withdrawal. The fixed
    // policy consumes previous individual authority rather than concealing a fallback grant.
    pub grants: BTreeMap<Digest32, u64>,
}

#[derive(Clone)]
pub(crate) struct State {
    pub cancelled_links: Vec<Zeroizing<String>>,
    pub cancelled: BTreeMap<Digest32, Genesis>,
    pub history: BTreeMap<Digest32, Roster>,
    pub quarantined: std::collections::BTreeSet<Digest32>,
    pub pair_link: Option<Zeroizing<String>>,
    pub pending_expires: u64,
    pub receipts: BTreeMap<Digest32, Signed>,
    pub vault: Vec<u8>,
    pub description: Description,
    pub revision: u64,
    pub invitations: Vec<Invitation>,
    pub genesis: Option<Genesis>,
    pub rosters: BTreeMap<Digest32, Roster>,
    /// A pending intent, including approvals already made, survives a crash before both arrive.
    pub pending: Option<Genesis>,
    /// Exact local policy application revision for each attached node; never a distributed clock.
    pub applied: BTreeMap<Digest32, AppliedPolicy>,
}
impl State {
    fn heads(&self) -> Vec<Digest32> {
        let group = self
            .genesis
            .as_ref()
            .or(self.pending.as_ref())
            .map(Genesis::incarnation);
        let current: Vec<_> = self
            .history
            .iter()
            .filter(|(_, r)| r.event().ok().is_some_and(|e| Some(e.group) == group))
            .collect();
        let mut heads: BTreeMap<Digest32, ()> = current.iter().map(|(id, _)| (**id, ())).collect();
        for (_, r) in current {
            if let Ok(e) = r.event() {
                for h in e.heads {
                    heads.remove(&h);
                }
            }
        }
        heads.into_keys().collect()
    }

    fn history_complete(&self) -> bool {
        let Some(g) = self.genesis.as_ref().or(self.pending.as_ref()) else {
            return true;
        };
        let mut known = std::collections::BTreeSet::from([g.incarnation()]);
        let mut pending: Vec<_> = self
            .history
            .iter()
            .filter_map(|(id, r)| {
                r.event()
                    .ok()
                    .filter(|e| e.group == g.incarnation())
                    .map(|e| (*id, e))
            })
            .collect();
        loop {
            let before = pending.len();
            pending.retain(|(id, event)| {
                if event.heads.iter().all(|h| known.contains(h)) {
                    known.insert(*id);
                    false
                } else {
                    true
                }
            });
            if pending.is_empty() {
                return true;
            }
            if pending.len() == before {
                return false;
            }
        }
    }

    /// Retain evidence before folding it. A missing causal parent gives no authority; conflicting
    /// correctly signed author events quarantine the author durably instead of choosing a winner.
    fn retain_roster(&mut self, r: Roster) -> Result<()> {
        if self.history.contains_key(&r.id()) {
            return Ok(());
        }
        let g = self
            .genesis
            .as_ref()
            .or(self.pending.as_ref())
            .ok_or_else(bad)?;
        let e = r.event()?;
        r.read(&e.author, &g.incarnation())?;
        let at = g
            .computers
            .iter()
            .position(|c| c.fingerprint().ok() == Some(e.author))
            .ok_or(Error::SignatureInvalid)?;
        if g.grants[at] != e.grant {
            return Err(Error::SignatureInvalid);
        }
        if self.history.len() >= MAX_RECORDS {
            return Err(Error::Profile(
                "computer control history is full; no authority was discarded",
            ));
        }
        self.history.insert(r.id(), r);
        self.fold_history()
    }

    fn fold_history(&mut self) -> Result<()> {
        let Some(g) = self.genesis.as_ref().or(self.pending.as_ref()) else {
            if self.history.is_empty() {
                return Ok(());
            }
            return Err(bad());
        };
        let before_quarantine = self.quarantined.clone();
        let mut seqs = BTreeMap::new();
        let mut events = BTreeMap::new();
        for (id, r) in &self.history {
            let e = r.event()?;
            if e.group != g.incarnation() {
                continue;
            }
            r.read(&e.author, &g.incarnation())?;
            let at = g
                .computers
                .iter()
                .position(|c| c.fingerprint().ok() == Some(e.author))
                .ok_or(Error::SignatureInvalid)?;
            if g.grants[at] != e.grant {
                return Err(Error::SignatureInvalid);
            }
            if seqs.insert((e.author, e.sequence), *id).is_some() {
                self.quarantined.insert(e.author);
            }
            events.insert(*id, e);
        }
        let mut accepted = std::collections::BTreeSet::from([g.incarnation()]);
        let mut pending: std::collections::BTreeSet<_> = events.keys().copied().collect();
        let mut rosters = BTreeMap::new();
        loop {
            let before = pending.len();
            pending.retain(|id| {
                let e = &events[id];
                if e.heads.iter().any(|h| !accepted.contains(h)) {
                    return true;
                }
                let chain = if e.sequence == 1 {
                    e.previous == [0; 32]
                } else {
                    events.get(&e.previous).is_some_and(|p| {
                        p.author == e.author && p.sequence.checked_add(1) == Some(e.sequence)
                    })
                };
                if !chain {
                    self.quarantined.insert(e.author);
                    return false;
                }
                accepted.insert(*id);
                if !self.quarantined.contains(&e.author) {
                    let replace = rosters
                        .get(&e.author)
                        .and_then(|id| events.get(id))
                        .is_none_or(|old| old.sequence < e.sequence);
                    if replace {
                        rosters.insert(e.author, *id);
                    }
                }
                false
            });
            if pending.len() == before {
                break;
            }
        }
        // A node key claimed by both management identities is a whole-computer fault.
        let mut managers = BTreeMap::new();
        for (manager, id) in &rosters {
            for b in &events[id].bindings {
                let node = b.verify(manager, &g.incarnation())?;
                if let Some(other) = managers.insert(node, *manager) {
                    if other != *manager {
                        self.quarantined.insert(other);
                        self.quarantined.insert(*manager);
                    }
                }
            }
        }
        let next: BTreeMap<_, _> = rosters
            .into_iter()
            .filter(|(author, _)| !self.quarantined.contains(author))
            .map(|(author, id)| (author, self.history[&id].clone()))
            .collect();
        if self.rosters != next || self.quarantined != before_quarantine {
            self.rosters = next;
            self.revision = self.revision.checked_add(1).ok_or_else(bad)?;
            self.receipts.clear();
        }
        Ok(())
    }
    fn body(&self) -> Vec<u8> {
        let mut e = Encoder::for_secrets();
        e.array(15)
            .bytes(&self.description.encode())
            .uint(self.revision)
            .array(self.invitations.len());
        for i in &self.invitations {
            e.bytes(&i.encode());
        }
        e.bytes(
            &self
                .genesis
                .as_ref()
                .map(Genesis::encode)
                .unwrap_or_default(),
        )
        .array(self.rosters.len());
        for (id, r) in &self.rosters {
            e.array(2).bytes(id).bytes(&r.signed.encode());
        }
        e.bytes(
            &self
                .pending
                .as_ref()
                .map(Genesis::encode)
                .unwrap_or_default(),
        )
        .array(self.applied.len());
        for (id, r) in &self.applied {
            e.array(4)
                .bytes(id)
                .uint(r.revision)
                .bytes(&r.interval)
                .array(r.grants.len());
            for (peer, created) in &r.grants {
                e.array(2).bytes(peer).uint(*created);
            }
        }
        e.uint(PROTOCOL)
            .text(
                self.pair_link
                    .as_deref()
                    .map(String::as_str)
                    .unwrap_or_default(),
            )
            .uint(self.pending_expires)
            .array(self.receipts.len());
        for (id, r) in &self.receipts {
            e.array(2).bytes(id).bytes(&r.encode());
        }
        e.array(self.history.len());
        for (id, r) in &self.history {
            e.array(2).bytes(id).bytes(&r.signed.encode());
        }
        e.array(self.quarantined.len());
        for id in &self.quarantined {
            e.bytes(id);
        }
        e.array(self.cancelled.len());
        for (id, g) in &self.cancelled {
            e.array(2).bytes(id).bytes(&g.encode());
        }
        e.array(self.cancelled_links.len());
        for link in &self.cancelled_links {
            e.text(link);
        }
        e.finish()
    }
    fn read(vault: Vec<u8>, body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        arity(&mut d, 15)?;
        let description = Description::decode(d.bytes()?)?;
        let revision = d.uint()?;
        let n = count(&mut d)?;
        let mut invitations = Vec::with_capacity(n);
        for _ in 0..n {
            invitations.push(Invitation::decode(d.bytes()?)?);
        }
        let b = d.bytes()?;
        let genesis = if b.is_empty() {
            None
        } else {
            let g = Genesis::decode(b)?;
            g.verify(true)?;
            Some(g)
        };
        let n = count(&mut d)?;
        let mut rosters = BTreeMap::new();
        for _ in 0..n {
            arity(&mut d, 2)?;
            let id = digest(&mut d)?;
            if rosters
                .insert(
                    id,
                    Roster {
                        signed: Signed::decode(d.bytes()?)?,
                    },
                )
                .is_some()
            {
                return Err(bad());
            }
        }
        let b = d.bytes()?;
        let pending = if b.is_empty() {
            None
        } else {
            Some(Genesis::decode(b)?)
        };
        let n = count(&mut d)?;
        let mut applied = BTreeMap::new();
        for _ in 0..n {
            arity(&mut d, 4)?;
            let id = digest(&mut d)?;
            let revision = d.uint()?;
            let interval = digest(&mut d)?;
            let n = count(&mut d)?;
            let mut grants = BTreeMap::new();
            for _ in 0..n {
                arity(&mut d, 2)?;
                let peer = digest(&mut d)?;
                let created = d.uint()?;
                if created == 0 || created > revision || grants.insert(peer, created).is_some() {
                    return Err(bad());
                }
            }
            if applied
                .insert(
                    id,
                    AppliedPolicy {
                        revision,
                        interval,
                        grants,
                    },
                )
                .is_some()
            {
                return Err(bad());
            }
        }
        if d.uint()? != PROTOCOL {
            return Err(bad());
        }
        let link = d.text()?.to_owned();
        let pair_link = (!link.is_empty()).then(|| Zeroizing::new(link));
        let pending_expires = d.uint()?;
        let n = count(&mut d)?;
        let mut receipts = BTreeMap::new();
        for _ in 0..n {
            arity(&mut d, 2)?;
            let id = digest(&mut d)?;
            if receipts.insert(id, Signed::decode(d.bytes()?)?).is_some() {
                return Err(bad());
            }
        }
        let n = count(&mut d)?;
        let mut history = BTreeMap::new();
        for _ in 0..n {
            arity(&mut d, 2)?;
            let id = digest(&mut d)?;
            let r = Roster {
                signed: Signed::decode(d.bytes()?)?,
            };
            if r.id() != id || history.insert(id, r).is_some() {
                return Err(bad());
            }
        }
        let n = count(&mut d)?;
        let mut quarantined = std::collections::BTreeSet::new();
        for _ in 0..n {
            if !quarantined.insert(digest(&mut d)?) {
                return Err(bad());
            }
        }
        let n = count(&mut d)?;
        let mut cancelled = BTreeMap::new();
        for _ in 0..n {
            arity(&mut d, 2)?;
            let id = digest(&mut d)?;
            let g = Genesis::decode(d.bytes()?)?;
            if id != g.incarnation() || cancelled.insert(id, g).is_some() {
                return Err(bad());
            }
        }
        let n = count(&mut d)?;
        let mut cancelled_links = Vec::with_capacity(n);
        for _ in 0..n {
            cancelled_links.push(Zeroizing::new(d.text()?.to_owned()));
        }
        d.finish()?;
        let mut s = Self {
            cancelled_links,
            cancelled,
            history,
            quarantined,
            pair_link,
            pending_expires,
            receipts,
            vault,
            description,
            revision,
            invitations,
            genesis,
            rosters,
            pending,
            applied,
        };
        // Restart verifies the retained evidence and recomputes exactly the saved authority.
        // Cancelled intents remain evidence, but can never authorize the active incarnation.
        for r in s.history.values() {
            let e = r.event()?;
            let g = s
                .genesis
                .as_ref()
                .or(s.pending.as_ref())
                .filter(|g| g.incarnation() == e.group)
                .or_else(|| s.cancelled.get(&e.group))
                .ok_or_else(bad)?;
            let at = g
                .computers
                .iter()
                .position(|c| c.fingerprint().ok() == Some(e.author))
                .ok_or_else(bad)?;
            if e.grant != g.grants[at] {
                return Err(bad());
            }
            r.read(&e.author, &e.group)?;
        }
        if s.genesis.is_some() || s.pending.is_some() {
            let rosters = s.rosters.clone();
            let quarantined = s.quarantined.clone();
            let revision = s.revision;
            s.fold_history()?;
            if s.rosters != rosters || s.quarantined != quarantined || s.revision != revision {
                return Err(bad());
            }
        } else if !s.rosters.is_empty() {
            return Err(bad());
        }
        Ok(s)
    }
}

/// A complete replacement for the covered part of one node's keyring.
/// `denied` includes retained bindings: a fault cannot reveal an older manual grant.
pub struct PolicyPlan {
    /// Exact durable local policy journal revision.
    pub revision: u64,
    /// Effective fixed-policy grants.
    pub grants: Vec<(Digest32, String, crate::node::trust::Capability)>,
    /// Covered grants that must be purged before networking.
    pub denied: Vec<Digest32>,
}

/// One persistent management identity and transaction domain, owned by its account daemon.
pub struct Computer {
    path: PathBuf,
    pub(crate) signer: Arc<dyn RootSigner + Send + Sync>,
    pub(crate) state: Mutex<State>,
    // Existing live room gates, weakly held: a durable policy change invalidates them before
    // exposing the new revision. Actors republish only after their keyring is reconciled.
    reachers: Mutex<
        Vec<std::sync::Weak<tokio::sync::watch::Sender<std::collections::BTreeSet<Digest32>>>>,
    >,
}
impl Computer {
    /// Local durable policy revision.
    pub fn revision(&self) -> u64 {
        lock(&self.state).revision
    }

    /// A computer with no attached nodes still has an authenticated empty roster.
    pub fn ensure_roster(&self) -> Result<()> {
        if self.binding_group().is_none() {
            return Ok(());
        }
        let local = self.signer.fingerprint();
        self.change(|s| {
            if !s.rosters.contains_key(&local) {
                if s.quarantined.contains(&local)
                    || s.history.values().any(|r| {
                        r.event().ok().is_some_and(|e| {
                            e.author == local
                                && Some(e.group)
                                    == s.genesis
                                        .as_ref()
                                        .or(s.pending.as_ref())
                                        .map(Genesis::incarnation)
                        })
                    })
                {
                    return Ok(());
                }
                let g = s.genesis.as_ref().or(s.pending.as_ref()).ok_or_else(bad)?;
                let r = Roster::create(g, None, s.heads(), &[], None, self.signer.as_ref())?;
                s.retain_roster(r)?;
            }
            Ok(())
        })
    }

    /// The signed group whose local operator has approved management bindings.
    pub fn binding_group(&self) -> Option<Digest32> {
        let s = lock(&self.state);
        let g = s.genesis.as_ref().or(s.pending.as_ref())?;
        let at = g
            .computers
            .iter()
            .position(|d| d.fingerprint().ok() == Some(self.signer.fingerprint()))?;
        g.approvals[at].as_ref()?;
        Some(g.incarnation())
    }

    /// Bind an already unlocked local node. The signer never crosses the daemon's actor boundary.
    /// This does not unlock or create a node, enroll a computer, or authorize an unapproved group.
    pub fn bind_node(&self, signer: &dyn RootSigner, name: &str, personal: bool) -> Result<()> {
        let Some(group) = self.binding_group() else {
            return Ok(());
        };
        let local = self.signer.fingerprint();
        let key = signer.fingerprint();
        self.change(|s| {
            if s.quarantined.contains(&local) {
                return Ok(());
            }
            let (_old_revision, old_personal, mut bindings) = match s.rosters.get(&local) {
                Some(r) => r.read(&local, &group)?,
                None => (0, None, Vec::new()),
            };
            let mut changed = false;
            if !bindings
                .iter()
                .any(|b| b.verify(&local, &group).ok() == Some(key))
            {
                let body = Binding::body(
                    &signer.public_key(),
                    &self.signer.public_key(),
                    &group,
                    &random_array()?,
                );
                bindings.push(Binding {
                    node: Signed::create(b"vox/computer-binding/v1\0", body.clone(), signer)?,
                    computer: Signed::create(
                        b"vox/computer-binding/v1\0",
                        body,
                        self.signer.as_ref(),
                    )?,
                    name: name.to_owned(),
                });
                changed = true;
            }
            let selection = if personal { Some(key) } else { old_personal };
            changed |= selection != old_personal;
            if changed {
                bindings.sort_by_key(|b| sha256(&b.node.public));
                let g = s.genesis.as_ref().or(s.pending.as_ref()).ok_or_else(bad)?;
                let r = Roster::create(
                    g,
                    s.rosters.get(&local),
                    s.heads(),
                    &bindings,
                    selection,
                    self.signer.as_ref(),
                )?;
                s.retain_roster(r)?;
            }
            Ok(())
        })
    }

    /// Exact policy for an attached node, from verified durable rosters. No roster grants room
    /// membership. The revision is local journal order, not a distributed membership clock.
    pub fn plan(&self, node: Digest32) -> Result<Option<PolicyPlan>> {
        let s = lock(&self.state);
        let Some(g) = &s.genesis else {
            return Ok(None);
        };
        let mut covered = std::collections::BTreeSet::new();
        let mut owner = None;
        for r in s.history.values() {
            let e = r.event()?;
            if e.group != g.incarnation() {
                continue;
            }
            for b in &e.bindings {
                let id = b.verify(&e.author, &e.group)?;
                covered.insert(id);
                if id == node {
                    owner = Some(e.author);
                }
            }
        }
        let owner = owner.ok_or(Error::Profile(
            "this managed node has no authenticated binding yet",
        ))?;
        let mut nodes = BTreeMap::new();
        for (manager, r) in &s.rosters {
            if s.quarantined.contains(manager) {
                continue;
            }
            let (_, personal, bindings) = r.read(manager, &g.incarnation())?;
            for b in bindings {
                let id = b.verify(manager, &g.incarnation())?;
                if nodes.insert(id, (b.name, personal == Some(id))).is_some() {
                    return Err(bad());
                }
            }
        }
        let own_personal = nodes.get(&node).is_some_and(|(_, personal)| *personal);
        let grants: Vec<_> = nodes
            .into_iter()
            .filter(|(id, _)| *id != node && !s.quarantined.contains(&owner))
            .map(|(id, (name, personal))| {
                (
                    id,
                    name,
                    if !own_personal && personal {
                        crate::node::trust::Capability::ReadDrive
                    } else {
                        crate::node::trust::Capability::Read
                    },
                )
            })
            .collect();
        covered.remove(&node);
        for (id, _, _) in &grants {
            covered.remove(id);
        }
        Ok(Some(PolicyPlan {
            revision: s.revision,
            grants,
            denied: covered.into_iter().collect(),
        }))
    }

    /// Is this exact local policy revision durably applied to this node's keyring?
    pub fn applied(&self, node: &Digest32, revision: u64) -> bool {
        lock(&self.state)
            .applied
            .get(node)
            .is_some_and(|a| a.revision == revision)
    }

    /// Record application only after the actor saved the complete keyring under the ordinary
    /// node store protection. A crash before this write repeats reconciliation before networking.
    pub fn mark_applied(&self, node: Digest32, revision: u64, covered: &[Digest32]) -> Result<()> {
        self.change(|s| {
            if revision > s.revision {
                return Err(bad());
            }
            // Another authenticated roster may have arrived during the node store write.
            // Record the exact revision actually applied; the actor retries before authorizing.

            let interval = s.genesis.as_ref().ok_or_else(bad)?.incarnation();
            let applied = s.applied.entry(node).or_insert_with(|| AppliedPolicy {
                revision,
                interval,
                grants: BTreeMap::new(),
            });
            if applied.interval != interval {
                return Err(bad());
            }
            for peer in covered {
                applied.grants.entry(*peer).or_insert(revision);
            }
            applied.revision = revision;
            Ok(())
        })
    }

    /// The policy replaces a covered individual entry, including stronger drive. Aliases remain
    /// local metadata. Callers use `None` only when this pair is outside computer mode.
    pub fn capability(
        &self,
        node: Digest32,
        peer: &Digest32,
    ) -> Result<Option<crate::node::trust::Capability>> {
        let Some(plan) = self.plan(node)? else {
            return Ok(None);
        };
        if plan.denied.contains(peer) {
            return Err(Error::Profile(
                "this computer authority is quarantined or retired",
            ));
        }
        Ok(plan
            .grants
            .into_iter()
            .find(|(id, _, _)| id == peer)
            .map(|(_, _, c)| c))
    }
    /// Open or atomically create the separate unattended software vault. Corrupt, unsupported,
    /// wrongly owned or symlinked state is refused unchanged. Call outside async runtime workers.
    pub fn open(account: &Account, name: &str) -> Result<Arc<Self>> {
        let dir = account.daemon_dir().join("computer");
        if dir.try_exists().map_err(|_| bad())? {
            secure(&dir, true)?;
        } else {
            create_private_dir(&dir)?;
            secure(&dir, true)?;
        }
        let path = dir.join("state");
        if path.symlink_metadata().is_ok() {
            secure(&path, false)?;
            let bytes = Zeroizing::new(std::fs::read(&path).map_err(|_| bad())?);
            let mut d = Decoder::new(&bytes);
            arity(&mut d, 3)?;
            if d.uint()? != PROTOCOL {
                return Err(bad());
            }
            let vault = d.bytes()?.to_vec();
            let record = Signed::decode(d.bytes()?)?;
            d.finish()?;
            let signer: Arc<dyn RootSigner + Send + Sync> =
                Arc::new(IdentityVault::from_canonical_slice(&vault)?.unlock_signer(b"")?);
            record.verify(b"vox/computer-state/v1\0", &signer.fingerprint())?;
            let state = State::read(vault, &record.body)?;
            if state.description.fingerprint()? != signer.fingerprint() {
                return Err(bad());
            }
            return Ok(Arc::new(Self {
                path,
                signer,
                state: Mutex::new(state),
                reachers: Mutex::new(Vec::new()),
            }));
        }
        let root = SoftwareRootSigner::generate()?;
        let fpr =
            crate::identity::openpgp::ed25519_v4_fingerprint(&root.public_key().ed25519_bytes(), 0);
        let backup = IdentityBackup::new(
            &root,
            Zeroizing::new(random_array()?),
            &SelfSeed::generate()?,
            &fpr,
        )?;
        let vault =
            IdentityVault::seal(&backup, b"", Argon2Profile::PRODUCTION)?.to_canonical_vec();
        let description = Description {
            public: root.public_key().to_bytes().to_vec(),
            name: name.to_owned(),
            installation: random_array()?,
        };
        Description::decode(&description.encode())?;
        let state = State {
            cancelled_links: Vec::new(),
            cancelled: BTreeMap::new(),
            history: BTreeMap::new(),
            quarantined: std::collections::BTreeSet::new(),
            pair_link: None,
            pending_expires: 0,
            receipts: BTreeMap::new(),
            vault,
            description,
            revision: 0,
            invitations: Vec::new(),
            genesis: None,
            rosters: BTreeMap::new(),
            pending: None,
            applied: BTreeMap::new(),
        };
        let c = Arc::new(Self {
            path,
            signer: Arc::new(root),
            state: Mutex::new(state),
            reachers: Mutex::new(Vec::new()),
        });
        c.save(&lock(&c.state))?;
        Ok(c)
    }
    fn save(&self, s: &State) -> Result<()> {
        secure(self.path.parent().ok_or_else(bad)?, true)?;
        if self.path.symlink_metadata().is_ok() {
            secure(&self.path, false)?;
        }
        let record = Signed::create(b"vox/computer-state/v1\0", s.body(), self.signer.as_ref())?;
        let mut e = Encoder::for_secrets();
        e.array(3)
            .uint(PROTOCOL)
            .bytes(&s.vault)
            .bytes(&record.encode());
        let bytes = Zeroizing::new(e.finish());
        if bytes.len() as u64 > MAX_STATE {
            return Err(Error::Profile(
                "computer management history is full; no state was discarded",
            ));
        }
        write_private_file(&self.path, &bytes)
    }
    /// Commit a complete management transaction before publishing it to live authorization.
    pub(crate) fn change<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut held = lock(&self.state);
        let mut next = held.clone();
        let value = f(&mut next)?;
        if held.body() != next.body() {
            self.save(&next)?;
            if held.revision != next.revision {
                lock(&self.reachers).retain(|weak| {
                    if let Some(gate) = weak.upgrade() {
                        crate::node::tunnel::publish_reachers(&gate, Default::default());
                        true
                    } else {
                        false
                    }
                });
            }
            *held = next;
        }
        Ok(value)
    }
    /// Publish into an existing room gate only while its node's durable keyring matches
    /// current policy. Register the same gate for synchronous invalidation on later changes.
    pub(crate) fn publish_reachers(
        &self,
        gate: &crate::node::tunnel::Reachers,
        next: std::collections::BTreeSet<Digest32>,
        applied: u64,
    ) {
        let state = lock(&self.state);
        let mut gates = lock(&self.reachers);
        if !gates.iter().any(|weak| weak.ptr_eq(&Arc::downgrade(gate))) {
            gates.push(Arc::downgrade(gate));
        }
        crate::node::tunnel::publish_reachers(
            gate,
            if state.genesis.is_none() || applied == state.revision {
                next
            } else {
                Default::default()
            },
        );
    }

    /// Persistent authenticated installation presentation.
    pub fn description(&self) -> Description {
        lock(&self.state).description.clone()
    }
    /// Whether computer mode has been explicitly established, never inferred from node trust.
    pub fn grouped(&self) -> bool {
        lock(&self.state).genesis.is_some()
    }
    /// Digest of the current signed transaction body, for local diagnostics without its secrets.
    pub fn state_digest(&self) -> Digest32 {
        sha256(&lock(&self.state).body())
    }
}

fn secure(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::symlink_metadata(path).map_err(|_| bad())?;
    let mode = if directory { 0o700 } else { 0o600 };
    if m.file_type().is_symlink()
        || m.is_dir() != directory
        || (!directory && (!m.is_file() || m.nlink() != 1 || m.len() > MAX_STATE))
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.permissions().mode() & 0o777 != mode
    {
        return Err(Error::Profile(
            "computer management path must be owned by this account, private, and not a symlink",
        ));
    }
    Ok(())
}

impl std::fmt::Debug for Computer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Computer")
            .field("fingerprint", &self.signer.fingerprint())
            .finish_non_exhaustive()
    }
}

/// The existing operator boundary, shared by the app's FFI and the terminal pairing client.
/// A malformed session mark still denotes an agent process. This is not OS-account isolation.
pub fn operator_only() -> Result<()> {
    if ["VOX_SESSION", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
    {
        return Err(Error::Profile("computer pairing is the person's action: use your own terminal or Vox.app outside the agent session"));
    }
    Ok(())
}
