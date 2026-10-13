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
        e.array(7)
            .uint(PROTOCOL)
            .bytes(&self.nonce)
            .bytes(&Self::policy_digest())
            .bytes(&self.computers[0].encode())
            .bytes(&self.computers[1].encode())
            .bytes(&self.grants[0])
            .bytes(&self.grants[1]);
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
        arity(&mut body, 7)?;
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
    /// Produce a roster only from bindings the daemon has obtained from its own node actors.
    pub fn create(
        group: Digest32,
        revision: u64,
        bindings: &[Binding],
        personal: Option<Digest32>,
        signer: &dyn RootSigner,
    ) -> Result<Self> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(PROTOCOL)
            .bytes(&group)
            .uint(revision)
            .bytes(personal.as_ref().map(|v| v.as_slice()).unwrap_or_default())
            .array(bindings.len());
        for b in bindings {
            b.verify(&signer.fingerprint(), &group)?;
            e.bytes(&b.encode());
        }
        Ok(Self {
            signed: Signed::create(b"vox/computer-roster/v1\0", e.finish(), signer)?,
        })
    }
    /// Verify before obtaining authority from any node or personal selection it names.
    pub fn read(
        &self,
        manager: &Digest32,
        group: &Digest32,
    ) -> Result<(u64, Option<Digest32>, Vec<Binding>)> {
        self.signed.verify(b"vox/computer-roster/v1\0", manager)?;
        let mut d = Decoder::new(&self.signed.body);
        arity(&mut d, 5)?;
        if d.uint()? != PROTOCOL || digest(&mut d)? != *group {
            return Err(bad());
        }
        let revision = d.uint()?;
        let p = d.bytes()?;
        let personal = if p.is_empty() {
            None
        } else {
            Some(p.try_into().map_err(|_| bad())?)
        };
        let n = count(&mut d)?;
        let mut bindings = Vec::with_capacity(n);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..n {
            let b = Binding::decode(d.bytes()?)?;
            if !seen.insert(b.verify(manager, group)?) {
                return Err(bad());
            }
            bindings.push(b);
        }
        d.finish()?;
        if personal.is_some_and(|p| !seen.contains(&p)) {
            return Err(bad());
        }
        Ok((revision, personal, bindings))
    }
}

#[derive(Clone)]
pub(crate) struct Invitation {
    pub id: Digest32,
    pub secret: Zeroizing<[u8; 16]>,
    pub expires: u64,
    pub nonce: Digest32,
    pub grants: [Digest32; 2],
    pub cancelled: bool,
    pub target: Option<Digest32>,
}
impl Invitation {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::for_secrets();
        e.array(8)
            .bytes(&self.id)
            .bytes(self.secret.as_ref())
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
        arity(&mut d, 8)?;
        let id = digest(&mut d)?;
        let secret = Zeroizing::new(d.bytes()?.try_into().map_err(|_| bad())?);
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
            expires,
            nonce,
            grants,
            cancelled,
            target,
        })
    }
}

#[derive(Clone)]
pub(crate) struct State {
    pub vault: Vec<u8>,
    pub description: Description,
    pub revision: u64,
    pub invitations: Vec<Invitation>,
    pub genesis: Option<Genesis>,
    pub rosters: BTreeMap<Digest32, Roster>,
    /// A pending intent, including approvals already made, survives a crash before both arrive.
    pub pending: Option<Genesis>,
    /// Exact local policy application revision for each attached node; never a distributed clock.
    pub applied: BTreeMap<Digest32, u64>,
}
impl State {
    fn body(&self) -> Vec<u8> {
        let mut e = Encoder::for_secrets();
        e.array(8)
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
            e.array(2).bytes(id).uint(*r);
        }
        e.uint(PROTOCOL);
        e.finish()
    }
    fn read(vault: Vec<u8>, body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        arity(&mut d, 8)?;
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
            arity(&mut d, 2)?;
            let id = digest(&mut d)?;
            if applied.insert(id, d.uint()?).is_some() {
                return Err(bad());
            }
        }
        if d.uint()? != PROTOCOL {
            return Err(bad());
        }
        d.finish()?;
        let s = Self {
            vault,
            description,
            revision,
            invitations,
            genesis,
            rosters,
            pending,
            applied,
        };
        if let Some(g) = s.genesis.as_ref().or(s.pending.as_ref()) {
            let mut nodes = std::collections::BTreeSet::new();
            for (id, r) in &s.rosters {
                if !g
                    .computers
                    .iter()
                    .any(|c| c.fingerprint().ok() == Some(*id))
                {
                    return Err(bad());
                }
                for b in r.read(id, &g.incarnation())?.2 {
                    if !nodes.insert(b.verify(id, &g.incarnation())?) {
                        return Err(Error::Profile(
                            "conflicting node management claims: both computers are quarantined",
                        ));
                    }
                }
            }
        } else if !s.rosters.is_empty() {
            return Err(bad());
        }
        Ok(s)
    }
}

/// One persistent management identity and transaction domain, owned by its account daemon.
pub struct Computer {
    path: PathBuf,
    pub(crate) signer: Arc<dyn RootSigner + Send + Sync>,
    pub(crate) state: Mutex<State>,
}
impl Computer {
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
        next.revision = next.revision.checked_add(1).ok_or_else(bad)?;
        self.save(&next)?;
        *held = next;
        Ok(value)
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
