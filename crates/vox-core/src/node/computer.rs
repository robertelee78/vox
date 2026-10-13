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
pub use pairing::{
    ComputerApplication, ComputerIdentity, ComputerStatus, Management, PairingPreview,
};

/// The one fixed policy, displayed before either operator approves an enrollment.
pub const POLICY: &str = "Every managed node can read every other managed node. Each computer's selected personal node can drive the non-personal nodes. Earlier individual grants are replaced by this policy; there are no per-node exceptions. Pairing does not join rooms or change repository bindings.";
/// Typed computer-management protocol version, checked before pairing payloads.
pub const PROTOCOL: u64 = 1;
/// One-time invitations last ten minutes.
pub const INVITE_LIFETIME_MS: u64 = 600_000;
const MAX_RECORDS: usize = 4096;
const MAX_STATE: u64 = 64 * 1024 * 1024;
const HISTORY_FULL: &str = "computer control history is full; no authority was discarded";
const STORAGE_FAILED: &str = "computer policy storage failed; computer trust is suspended until storage is repaired and the daemon restarted";

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
pub struct Enrollment {
    /// Existing incarnation for an ADD; absent only for the initial two-party genesis.
    pub group: Option<Digest32>,
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
impl Enrollment {
    /// The fixed policy digest binds its version and permission meaning.
    pub fn policy_digest() -> Digest32 {
        sha256_concat(&[b"vox/computer-policy/v1\0", POLICY.as_bytes()])
    }
    /// Canonical genesis; presentation names are bound but do not identify a member.
    pub fn body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .uint(PROTOCOL)
            .bytes(&self.nonce)
            .bytes(&Self::policy_digest())
            .bytes(&self.computers[0].encode())
            .bytes(&self.computers[1].encode())
            .bytes(&self.grants[0])
            .bytes(&self.grants[1])
            .uint(self.expires)
            .bytes(
                self.group
                    .as_ref()
                    .map(|g| g.as_slice())
                    .unwrap_or_default(),
            );
        e.finish()
    }
    /// Immutable pairing operation, distinct from the existing group for an ADD.
    pub fn operation(&self) -> Digest32 {
        sha256_concat(&[b"vox/computer-genesis/v1\0", &self.body()])
    }
    /// The pinned group never changes when another equal member enrolls a computer.
    pub fn incarnation(&self) -> Digest32 {
        self.group.unwrap_or_else(|| self.operation())
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
        arity(&mut body, 9)?;
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
        let group = body.bytes()?;
        let group = if group.is_empty() {
            None
        } else {
            Some(group.try_into().map_err(|_| bad())?)
        };
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
            group,
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
pub struct Control {
    /// Signed canonical roster body, retained verbatim for receipts and replay checking.
    pub signed: Signed,
}
impl Control {
    fn create(
        s: &State,
        bindings: &[Binding],
        personal: Option<Digest32>,
        signer: &dyn RootSigner,
    ) -> Result<Self> {
        let author = signer.fingerprint();
        let previous = s.rosters.get(&author);
        let revision = previous
            .map(|r| r.event().map(|e| e.roster_revision))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(bad)?;
        let mut body = Encoder::new();
        body.array(4)
            .uint(revision)
            .bytes(&previous.map(Self::id).unwrap_or([0; 32]))
            .bytes(personal.as_ref().map(|v| v.as_slice()).unwrap_or_default())
            .array(bindings.len());
        for b in bindings {
            body.bytes(&b.encode());
        }
        Self::sign(s, "roster", body.finish(), signer)
    }
    fn sign(s: &State, kind: &str, body: Vec<u8>, signer: &dyn RootSigner) -> Result<Self> {
        let group = s.group().ok_or_else(bad)?;
        let author = signer.fingerprint();
        let grant = s.grant(&author).ok_or(Error::SignatureInvalid)?;
        let previous = s
            .history
            .values()
            .filter_map(|r| {
                r.event()
                    .ok()
                    .filter(|e| e.group == group && e.author == author)
                    .map(|e| (e.sequence, r.id()))
            })
            .max()
            .unwrap_or((0, [0; 32]));
        let mut heads = s.heads();
        if previous.1 != [0; 32] {
            heads.push(previous.1);
        }
        if heads.is_empty() {
            heads.push(group);
        }
        heads.sort();
        heads.dedup();
        let mut e = Encoder::new();
        e.array(10)
            .uint(PROTOCOL)
            .bytes(&group)
            .bytes(&signer.public_key().to_bytes())
            .bytes(&grant)
            .uint(previous.0.checked_add(1).ok_or_else(bad)?)
            .bytes(&previous.1)
            .array(heads.len());
        for head in heads {
            e.bytes(&head);
        }
        e.text(kind).bytes(&body).bytes(&random_array::<32>()?);
        Ok(Self {
            signed: Signed::create(b"vox/computer-control/v1\0", e.finish(), signer)?,
        })
    }
    fn id(&self) -> Digest32 {
        sha256(&self.signed.encode())
    }
    fn event(&self) -> Result<ControlEvent> {
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
        let kind = d.text()?;
        let mut body = Decoder::new(d.bytes()?);
        let (mut personal, mut bindings, mut addition, mut reach) = (None, Vec::new(), None, None);
        let (mut roster_revision, mut previous_roster) = (0, [0; 32]);
        match kind {
            "roster" => {
                arity(&mut body, 4)?;
                roster_revision = body.uint()?;
                previous_roster = digest(&mut body)?;
                let p = body.bytes()?;
                personal = if p.is_empty() {
                    None
                } else {
                    Some(p.try_into().map_err(|_| bad())?)
                };
                for _ in 0..count(&mut body)? {
                    bindings.push(Binding::decode(body.bytes()?)?);
                }
                if roster_revision == 0 {
                    return Err(bad());
                }
            }
            "add" => {
                arity(&mut body, 1)?;
                addition = Some(Enrollment::decode(body.bytes()?)?);
            }
            "reach" => {
                arity(&mut body, 1)?;
                reach = Some(Reach::decode(body.bytes()?)?);
            }
            _ => return Err(bad()),
        }
        body.finish()?;
        let _operation = digest(&mut d)?;
        d.finish()?;
        Ok(ControlEvent {
            group,
            author,
            grant,
            sequence,
            previous,
            heads,
            personal,
            bindings,
            roster_revision,
            previous_roster,
            addition,
            reach,
        })
    }
    fn verify(&self, group: &Digest32) -> Result<ControlEvent> {
        let e = self.event()?;
        self.signed
            .verify(b"vox/computer-control/v1\0", &e.author)?;
        if e.group != *group {
            return Err(bad());
        }
        let mut seen = std::collections::BTreeSet::new();
        for b in &e.bindings {
            if !seen.insert(b.verify(&e.author, group)?) {
                return Err(bad());
            }
        }
        if e.personal.is_some_and(|p| !seen.contains(&p)) {
            return Err(bad());
        }
        if let Some(a) = &e.addition {
            a.verify(true)?;
            if a.group != Some(*group)
                || a.computers[0].fingerprint()? != e.author
                || a.grants[0] != e.grant
            {
                return Err(Error::SignatureInvalid);
            }
        }
        Ok(e)
    }
    /// The node roster is effective only after its complete control ancestry is authenticated.
    pub fn read(
        &self,
        manager: &Digest32,
        group: &Digest32,
    ) -> Result<(u64, Option<Digest32>, Vec<Binding>)> {
        let e = self.verify(group)?;
        if e.author != *manager || e.roster_revision == 0 {
            return Err(bad());
        }
        Ok((e.roster_revision, e.personal, e.bindings))
    }
}
#[derive(Clone)]
struct ControlEvent {
    group: Digest32,
    author: Digest32,
    grant: Digest32,
    sequence: u64,
    previous: Digest32,
    heads: Vec<Digest32>,
    personal: Option<Digest32>,
    bindings: Vec<Binding>,
    roster_revision: u64,
    previous_roster: Digest32,
    addition: Option<Enrollment>,
    reach: Option<Reach>,
}
/// Current authenticated contact facts, carried by the same author chain as membership.
/// The independent token authorizes exact management transport pairs, never room access.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reach {
    endpoints: crate::nat::multiaddr::EndpointList,
    anchors: crate::nat::bootstrap::BootstrapSet,
    token: Digest32,
}
impl Reach {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3).array(self.endpoints.len());
        for a in self.endpoints.addrs() {
            e.text(&a.to_string());
        }
        e.bytes(&self.anchors.to_bytes()).bytes(&self.token);
        e.finish()
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        arity(&mut d, 3)?;
        let n = d.array()?;
        if n > 8 {
            return Err(bad());
        }
        let mut endpoints = Vec::new();
        for _ in 0..n {
            endpoints.push(crate::nat::multiaddr::Multiaddr::parse(d.text()?)?);
        }
        let result = Self {
            endpoints: crate::nat::multiaddr::EndpointList::new(endpoints)?,
            anchors: crate::nat::bootstrap::BootstrapSet::from_bytes(d.bytes()?)?,
            token: digest(&mut d)?,
        };
        d.finish()?;
        Ok(result)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Grant {
    computer: Description,
    sponsor: Option<Digest32>,
    event: Digest32,
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
    links: Vec<Zeroizing<String>>,
    group_genesis: Option<Enrollment>,
    members: BTreeMap<Digest32, Grant>,
    reaches: BTreeMap<Digest32, Reach>,
    pub cancelled_links: Vec<Zeroizing<String>>,
    pub cancelled: BTreeMap<Digest32, Enrollment>,
    pub history: BTreeMap<Digest32, Control>,
    pub quarantined: std::collections::BTreeSet<Digest32>,
    pub pair_link: Option<Zeroizing<String>>,
    pub pending_expires: u64,
    pub receipts: BTreeMap<Digest32, Signed>,
    pub vault: Vec<u8>,
    pub description: Description,
    pub revision: u64,
    pub invitations: Vec<Invitation>,
    pub genesis: Option<Enrollment>,
    pub rosters: BTreeMap<Digest32, Control>,
    /// A pending intent, including approvals already made, survives a crash before both arrive.
    pub pending: Option<Enrollment>,
    /// Exact local policy application revision for each attached node; never a distributed clock.
    pub applied: BTreeMap<Digest32, AppliedPolicy>,
}
impl State {
    fn group(&self) -> Option<Digest32> {
        self.genesis
            .as_ref()
            .or(self.group_genesis.as_ref())
            .or(self.pending.as_ref())
            .map(Enrollment::incarnation)
    }
    fn grant(&self, author: &Digest32) -> Option<Digest32> {
        if self.quarantined.contains(author) {
            return None;
        }
        self.members
            .iter()
            .find(|(_, g)| g.computer.fingerprint().ok() == Some(*author))
            .map(|(id, _)| *id)
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|g| self.genesis.is_none() && g.group.is_none())
                    .and_then(|g| {
                        g.computers
                            .iter()
                            .position(|d| d.fingerprint().ok() == Some(*author))
                            .map(|i| g.grants[i])
                    })
            })
    }
    fn descriptions(&self) -> BTreeMap<Digest32, Description> {
        self.members
            .values()
            .filter_map(|g| {
                g.computer
                    .fingerprint()
                    .ok()
                    .map(|id| (id, g.computer.clone()))
            })
            .collect()
    }
    fn heads(&self) -> Vec<Digest32> {
        let current: Vec<_> = self
            .history
            .iter()
            .filter_map(|(id, r)| {
                r.event()
                    .ok()
                    .filter(|e| Some(e.group) == self.group())
                    .map(|e| (*id, e))
            })
            .collect();
        let mut heads: std::collections::BTreeSet<_> = current.iter().map(|(id, _)| *id).collect();
        for (_, e) in current {
            for h in e.heads {
                heads.remove(&h);
            }
        }
        heads.into_iter().collect()
    }
    fn history_complete(&self) -> bool {
        self.derive().map(|v| v.complete).unwrap_or(false)
    }
    fn retain_roster(&mut self, r: Control) -> Result<()> {
        if self.history.contains_key(&r.id()) {
            return Ok(());
        }
        r.verify(&self.group().ok_or_else(bad)?)?;
        if self.history.len() >= MAX_RECORDS {
            return Err(Error::Profile(HISTORY_FULL));
        }
        self.history.insert(r.id(), r);
        self.fold_history()
    }
    fn derive(&self) -> Result<Authority> {
        let Some(g) = self
            .genesis
            .as_ref()
            .or(self.group_genesis.as_ref())
            .or(self.pending.as_ref().filter(|g| g.group.is_none()))
        else {
            return Ok(Authority::default());
        };
        let group = g.incarnation();
        let mut events = BTreeMap::new();
        for (id, r) in &self.history {
            if r.event()?.group == group {
                events.insert(*id, r.verify(&group)?);
            }
        }
        let initial: BTreeMap<_, _> = g
            .grants
            .iter()
            .zip(&g.computers)
            .map(|(id, c)| {
                (
                    *id,
                    Grant {
                        computer: c.clone(),
                        sponsor: None,
                        event: group,
                    },
                )
            })
            .collect();
        let mut accepted = std::collections::BTreeSet::new();
        let mut ancestry: BTreeMap<Digest32, std::collections::BTreeSet<Digest32>> =
            BTreeMap::new();
        let mut grants = initial.clone();
        let mut pending: std::collections::BTreeSet<_> = events.keys().copied().collect();
        loop {
            let before = pending.len();
            for id in pending.clone() {
                let e = &events[&id];
                if e.heads.iter().any(|h| *h != group && !accepted.contains(h)) {
                    continue;
                }
                let chain = if e.sequence == 1 {
                    e.previous == [0; 32]
                } else {
                    events.get(&e.previous).is_some_and(|p| {
                        p.author == e.author && p.sequence.checked_add(1) == Some(e.sequence)
                    })
                };
                if !chain {
                    return Err(bad());
                }
                let mut prefix = std::collections::BTreeSet::new();
                for h in &e.heads {
                    if *h != group {
                        prefix.insert(*h);
                        prefix.extend(ancestry[h].iter().copied());
                    }
                }
                let available: BTreeMap<_, _> = grants
                    .iter()
                    .filter(|(_, v)| v.event == group || prefix.contains(&v.event))
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                let (active, _) = exclude_forks(&events, &ancestry, &prefix, available)?;
                if active
                    .get(&e.grant)
                    .is_none_or(|a| a.computer.fingerprint().ok() != Some(e.author))
                {
                    return Err(Error::SignatureInvalid);
                }
                if let Some(add) = &e.addition {
                    let target = add.computers[1].fingerprint()?;
                    if active
                        .values()
                        .any(|a| a.computer.fingerprint().ok() == Some(target))
                    {
                        return Err(Error::Profile("computer is already enrolled in this group"));
                    }
                    let grant = Grant {
                        computer: add.computers[1].clone(),
                        sponsor: Some(e.grant),
                        event: id,
                    };
                    if grants.insert(add.grants[1], grant).is_some() {
                        return Err(bad());
                    }
                }
                if e.roster_revision > 0 {
                    let old = prefix
                        .iter()
                        .filter_map(|h| {
                            let p = &events[h];
                            (p.author == e.author && p.roster_revision > 0).then_some((*h, p))
                        })
                        .max_by_key(|(_, p)| p.sequence);
                    if old
                        .map(|(h, p)| (p.roster_revision + 1, h))
                        .unwrap_or((1, [0; 32]))
                        != (e.roster_revision, e.previous_roster)
                    {
                        return Err(bad());
                    }
                }
                ancestry.insert(id, prefix);
                accepted.insert(id);
                pending.remove(&id);
            }
            if pending.len() == before {
                break;
            }
        }
        let (mut members, mut quarantined) = exclude_forks(&events, &ancestry, &accepted, grants)?;
        // Closing an expired local intent cannot withdraw a signature elsewhere. Retain that
        // signed ADD and its ancestry, but its exact grant cannot activate on this installation.
        // A different fresh operation/grant is unaffected by replay of this local close.
        let mut retired: std::collections::BTreeSet<_> = self
            .cancelled
            .values()
            .filter(|intent| intent.group == Some(group))
            .map(|intent| intent.grants[1])
            .collect();
        loop {
            let before = retired.len();
            for (id, grant) in &members {
                if grant
                    .sponsor
                    .is_some_and(|sponsor| retired.contains(&sponsor))
                {
                    retired.insert(*id);
                }
            }
            if retired.len() == before {
                break;
            }
        }
        members.retain(|id, _| !retired.contains(id));
        let active: std::collections::BTreeSet<_> = members
            .values()
            .filter_map(|g| g.computer.fingerprint().ok())
            .collect();
        let mut rosters = BTreeMap::new();
        let mut reaches = BTreeMap::new();
        for id in &accepted {
            let e = &events[id];
            if !active.contains(&e.author) {
                continue;
            }
            if e.roster_revision > 0
                && rosters
                    .get(&e.author)
                    .is_none_or(|old| events[old].sequence < e.sequence)
            {
                rosters.insert(e.author, *id);
            }
            if e.reach.is_some()
                && reaches
                    .get(&e.author)
                    .is_none_or(|old| events[old].sequence < e.sequence)
            {
                reaches.insert(e.author, *id);
            }
        }
        let mut managers = BTreeMap::new();
        for (manager, id) in &rosters {
            for b in &events[id].bindings {
                let node = b.verify(manager, &group)?;
                if let Some(other) = managers.insert(node, *manager) {
                    if other != *manager {
                        quarantined.insert(other);
                        quarantined.insert(*manager);
                    }
                }
            }
        }
        Ok(Authority {
            members,
            quarantined,
            rosters: rosters
                .into_iter()
                .map(|(k, id)| (k, self.history[&id].clone()))
                .collect(),
            reaches: reaches
                .into_iter()
                .filter_map(|(k, id)| events[&id].reach.clone().map(|reach| (k, reach)))
                .collect(),
            complete: pending.is_empty(),
        })
    }
    fn fold_history(&mut self) -> Result<()> {
        let next = self.derive()?;
        if self.members != next.members
            || self.rosters != next.rosters
            || self.quarantined != next.quarantined
            || self.reaches != next.reaches
        {
            self.members = next.members;
            self.rosters = next.rosters;
            self.quarantined = next.quarantined;
            self.reaches = next.reaches;
            self.revision = self.revision.checked_add(1).ok_or_else(bad)?;
            self.receipts.clear();
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut e = Encoder::for_secrets();
        e.array(17)
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
                .map(Enrollment::encode)
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
                .map(Enrollment::encode)
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
        e.bytes(
            &self
                .group_genesis
                .as_ref()
                .map(Enrollment::encode)
                .unwrap_or_default(),
        )
        .array(self.links.len());
        for link in &self.links {
            e.text(link);
        }
        e.finish()
    }
    fn read(vault: Vec<u8>, body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        arity(&mut d, 17)?;
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
            let g = Enrollment::decode(b)?;
            g.verify(true)?;
            if g.group.is_some() {
                return Err(bad());
            }
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
                    Control {
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
            Some(Enrollment::decode(b)?)
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
            let r = Control {
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
            let g = Enrollment::decode(d.bytes()?)?;
            if id != g.operation() || cancelled.insert(id, g).is_some() {
                return Err(bad());
            }
        }
        let n = count(&mut d)?;
        let mut cancelled_links = Vec::with_capacity(n);
        for _ in 0..n {
            cancelled_links.push(Zeroizing::new(d.text()?.to_owned()));
        }
        let bytes = d.bytes()?;
        let group_genesis = if bytes.is_empty() {
            None
        } else {
            let g = Enrollment::decode(bytes)?;
            g.verify(true)?;
            if g.group.is_some() {
                return Err(bad());
            }
            Some(g)
        };
        let mut links = Vec::new();
        for _ in 0..count(&mut d)? {
            links.push(Zeroizing::new(d.text()?.to_owned()));
        }
        d.finish()?;
        let mut s = Self {
            links,
            group_genesis,
            members: BTreeMap::new(),
            reaches: BTreeMap::new(),
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
        // Recompute authority from retained signed bytes, checking the saved effective roster.
        for r in s.history.values() {
            let e = r.event()?;
            let group = s
                .group()
                .filter(|g| *g == e.group)
                .or_else(|| {
                    s.cancelled
                        .values()
                        .find(|g| g.incarnation() == e.group)
                        .map(Enrollment::incarnation)
                })
                .ok_or_else(bad)?;
            r.verify(&group)?;
        }
        if s.genesis.is_some() || s.group_genesis.is_some() || s.pending.is_some() {
            let derived = s.derive()?;
            if derived.rosters != s.rosters || derived.quarantined != s.quarantined {
                return Err(bad());
            }
            s.members = derived.members;
            s.reaches = derived.reaches;
        } else if !s.rosters.is_empty() {
            return Err(bad());
        }
        Ok(s)
    }
}

#[derive(Default)]
struct Authority {
    members: BTreeMap<Digest32, Grant>,
    rosters: BTreeMap<Digest32, Control>,
    reaches: BTreeMap<Digest32, Reach>,
    quarantined: std::collections::BTreeSet<Digest32>,
    complete: bool,
}
/// Fork exclusion follows sponsor edges, preserving additions on the shared safe prefix.
fn exclude_forks(
    events: &BTreeMap<Digest32, ControlEvent>,
    ancestry: &BTreeMap<Digest32, std::collections::BTreeSet<Digest32>>,
    selected: &std::collections::BTreeSet<Digest32>,
    mut grants: BTreeMap<Digest32, Grant>,
) -> Result<(
    BTreeMap<Digest32, Grant>,
    std::collections::BTreeSet<Digest32>,
)> {
    let mut forks = BTreeMap::new();
    let mut seqs = BTreeMap::new();
    for id in selected {
        let e = &events[id];
        if let Some(old) = seqs.insert((e.author, e.sequence), *id) {
            let p = &events[&old];
            if p.previous == e.previous {
                forks
                    .entry(e.author)
                    .and_modify(|v: &mut (u64, Digest32)| {
                        if e.sequence < v.0 {
                            *v = (e.sequence, e.previous);
                        }
                    })
                    .or_insert((e.sequence, e.previous));
            }
        }
    }
    let mut denied = std::collections::BTreeSet::new();
    for (author, (_, previous)) in &forks {
        let mut safe = ancestry.get(previous).cloned().unwrap_or_default();
        safe.insert(*previous);
        let mut invalid: std::collections::BTreeSet<_> = grants
            .iter()
            .filter_map(|(id, g)| (g.computer.fingerprint().ok() == Some(*author)).then_some(*id))
            .collect();
        loop {
            let before = invalid.len();
            for (id, g) in &grants {
                if g.sponsor.is_some_and(|s| invalid.contains(&s)) && !safe.contains(&g.event) {
                    invalid.insert(*id);
                }
            }
            if before == invalid.len() {
                break;
            }
        }
        denied.extend(invalid);
    }
    grants.retain(|id, _| !denied.contains(id));
    Ok((grants, forks.into_keys().collect()))
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
    storage_failed: std::sync::atomic::AtomicBool,
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

    /// A failed policy write invalidates current grants even when the durable revision did not
    /// advance. Restart revalidates the retained state and its ability to be saved before attach.
    pub(crate) fn policy_current(&self, applied: u64) -> bool {
        let s = lock(&self.state);
        s.genesis.is_none() || (self.storage_ready().is_ok() && s.revision == applied)
    }

    pub(crate) fn storage_ready(&self) -> Result<()> {
        if self
            .storage_failed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Err(Error::Profile(STORAGE_FAILED))
        } else {
            Ok(())
        }
    }

    fn invalidate_reachers(&self) {
        lock(&self.reachers).retain(|weak| {
            if let Some(gate) = weak.upgrade() {
                crate::node::tunnel::publish_reachers(&gate, Default::default());
                true
            } else {
                false
            }
        });
    }

    fn storage_failure(&self) {
        self.storage_failed
            .store(true, std::sync::atomic::Ordering::Release);
        self.invalidate_reachers();
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
                                && e.roster_revision > 0
                                && Some(e.group)
                                    == s.genesis
                                        .as_ref()
                                        .or(s.pending.as_ref())
                                        .map(Enrollment::incarnation)
                        })
                    })
                {
                    return Ok(());
                }
                let r = Control::create(s, &[], None, self.signer.as_ref())?;
                s.retain_roster(r)?;
            }
            Ok(())
        })
    }

    /// The signed group whose local operator has approved management bindings.
    pub fn binding_group(&self) -> Option<Digest32> {
        let s = lock(&self.state);
        let local = self.signer.fingerprint();
        if s.genesis.is_some() && s.grant(&local).is_some() {
            return s.group();
        }
        let g = s.pending.as_ref()?;
        if g.group.is_some() {
            return None;
        }
        let at = g
            .computers
            .iter()
            .position(|d| d.fingerprint().ok() == Some(local))?;
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
                let r = Control::create(s, &bindings, selection, self.signer.as_ref())?;
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
        self.storage_ready()?;
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
            if state.history.len() >= MAX_RECORDS {
                return Err(Error::Profile(HISTORY_FULL));
            }
            let c = Arc::new(Self {
                path,
                storage_failed: std::sync::atomic::AtomicBool::new(false),
                signer,
                state: Mutex::new(state),
                reachers: Mutex::new(Vec::new()),
            });
            // Validate present storage before any endpoint or managed node can resume authority.
            // If a failed prior write could not persist its fault, the retained signed state is
            // still the only durable boundary; we never fabricate the missing transaction.
            c.save(&lock(&c.state))?;
            return Ok(c);
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
            links: Vec::new(),
            group_genesis: None,
            members: BTreeMap::new(),
            reaches: BTreeMap::new(),
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
            storage_failed: std::sync::atomic::AtomicBool::new(false),
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
        self.storage_ready()?;
        let mut next = held.clone();
        let value = match f(&mut next) {
            Ok(value) => value,
            Err(Error::Profile(HISTORY_FULL)) => {
                self.storage_failure();
                return Err(Error::Profile(HISTORY_FULL));
            }
            Err(error) => return Err(error),
        };
        if held.body() != next.body() {
            if let Err(error) = self.save(&next) {
                self.storage_failure();
                return Err(error);
            }
            if held.revision != next.revision {
                self.invalidate_reachers();
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
            if state.genesis.is_none()
                || (self.storage_ready().is_ok() && applied == state.revision)
            {
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
