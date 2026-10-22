//! Daemon-owned computer identity and the signed records of explicit computer trust (ADR-035).
//! This is separate from node identities, rooms, and their passphrases. The account daemon is
//! the sole writer; one atomic file contains its vault and retained management transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::atrest::{Argon2Profile, IdentityVault};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, sha256_concat, Digest32};
use crate::identity::backup::{IdentityBackup, SelfSeed};
use crate::identity::composite::{
    CompositePublicKey, CompositeSignature, RootSigner, SoftwareRootSigner,
};
use crate::identity::rng::random_array;
use crate::node::paths::{
    create_private_dir, write_private_file, write_private_file_checked, Account,
};
use zeroize::Zeroizing;

mod pairing;
pub use pairing::{
    ComputerApplication, ComputerBindingAction, ComputerIdentity, ComputerNode, ComputerStatus,
    ExchangeRecord, Management, PairingPreview, COMPUTER_PAIR_WITHIN,
};

/// A trust change must either be applied by an attached node or make that node visibly no longer
/// attached within this long (ADR-038 FX-28).
pub const COMPUTER_CHANGE_SHOWN_WITHIN: Duration = Duration::from_secs(5);

/// A reachable enrolled computer must show a trust change within this long, including after a
/// failed path becomes reachable again (ADR-038 FX-28).
pub const COMPUTER_RETURN_SHOWN_WITHIN: Duration = Duration::from_secs(60);
/// Backoff before retrying the `failures`th consecutive failed computer exchange. Proofs use the
/// same exported calculation to stage recovery between a causal deadline and an ordinary retry;
/// they never duplicate a count or delay.
pub fn computer_exchange_backoff(failures: u32) -> Duration {
    Duration::from_secs(2).saturating_mul(1u32 << failures.saturating_sub(1).min(6))
}

/// A confirmed computer with no state to settle is not exchanged before this fallback cadence.
pub const COMPUTER_QUIET_EXCHANGE_AFTER: Duration = Duration::from_secs(60);

/// Test-knob build only: select one deliberately faulty FX-28 behavior. The release binary does
/// not contain the variable or mode names; each mode is run separately so one red cannot satisfy
/// another claim's mutant.
#[cfg(feature = "test-knobs")]
pub(crate) fn fx28_mutant(named: &str) -> bool {
    std::env::var("VOX_TEST_FX28_MUTANT").as_deref() == Ok(named)
}

/// Publish a populated proof marker in one namespace operation, without replacing an existing
/// marker. Test-knob call sites use this only for causal staging; shipped builds compile every
/// caller out.
#[cfg(feature = "test-knobs")]
pub(crate) fn publish_proof_marker(
    path: &std::path::Path,
    bytes: &[u8],
) -> core::result::Result<(), String> {
    use std::io::Write as _;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    let staged = path.with_file_name(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|e| format!("could not create {}: {e}", staged.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let cleanup = std::fs::remove_file(&staged).err();
        return Err(format!(
            "could not populate {}: {error}; cleanup: {cleanup:?}",
            staged.display()
        ));
    }
    drop(file);
    if let Err(error) = rustix::fs::renameat_with(
        rustix::fs::CWD,
        &staged,
        rustix::fs::CWD,
        path,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        let cleanup = std::fs::remove_file(&staged).err();
        return Err(format!(
            "could not publish {} without replacement: {error}; cleanup: {cleanup:?}",
            path.display()
        ));
    }
    Ok(())
}

/// Make a hook setup failure causally visible to the shipped-binary journey. If even the fault
/// marker cannot be published, process termination is the journey's independent apparatus signal.
#[cfg(feature = "test-knobs")]
pub(crate) fn publish_proof_fault(path: &std::path::Path, detail: &str) {
    if let Err(error) = publish_proof_marker(path, detail.as_bytes()) {
        eprintln!(
            "APPARATUS: could not publish proof fault {}: {error}",
            path.display()
        );
        std::process::exit(70);
    }
}

/// One durable policy revision and the absolute ends of the two user-visible contracts its
/// cause began. A remote merge may shorten the local apply deadline, but never restarts the
/// outer return deadline shared by exchange and reconciliation.
#[derive(Clone, Copy, Debug)]
pub struct ComputerChange {
    revision: u64,
    apply_deadline: std::time::Instant,
    return_deadline: std::time::Instant,
}

impl ComputerChange {
    /// A local cause gets the apply-or-detach contract from the instant it is observed.
    #[must_use]
    pub fn now(revision: u64) -> Self {
        let now = std::time::Instant::now();
        Self {
            revision,
            apply_deadline: now + COMPUTER_CHANGE_SHOWN_WITHIN,
            return_deadline: now + COMPUTER_RETURN_SHOWN_WITHIN,
        }
    }

    /// Construct a change with already-owned absolute deadlines. Used when a lagged follower
    /// must carry the current exact revision without granting it a fresh convergence window.
    #[must_use]
    pub fn at(
        revision: u64,
        apply_deadline: std::time::Instant,
        return_deadline: std::time::Instant,
    ) -> Self {
        Self {
            revision,
            apply_deadline,
            return_deadline,
        }
    }

    /// The durable policy revision carried by this event.
    #[must_use]
    pub fn revision(self) -> u64 {
        self.revision
    }

    /// The absolute end of this event's apply-or-detach contract.
    #[must_use]
    pub fn apply_deadline(self) -> std::time::Instant {
        self.apply_deadline
    }

    /// The absolute end of this event's reachable-peer return contract.
    #[must_use]
    pub fn return_deadline(self) -> std::time::Instant {
        self.return_deadline
    }
}

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
    fn id(&self) -> Digest32 {
        sha256_concat(&[&self.node.encode(), &self.computer.encode()])
    }
    fn approval(&self) -> Result<Option<BindingApproval>> {
        let mut d = Decoder::new(&self.node.body);
        arity(&mut d, 6)?;
        d.uint()?;
        d.bytes()?;
        d.bytes()?;
        d.bytes()?;
        d.bytes()?;
        let bytes = d.bytes()?;
        let result = if bytes.is_empty() {
            None
        } else {
            Some(BindingApproval::decode(bytes)?)
        };
        d.finish()?;
        Ok(result)
    }

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
        let previous = d.bytes()?;
        if !previous.is_empty() {
            BindingApproval::decode(previous)?;
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

/// A destination operator's exact approved causal transfer/recovery context. The node signs
/// this context only when its ordinary protected vault is successfully unlocked locally.
#[derive(Clone)]
struct BindingApproval {
    kind: u64, // 1: signed source release; 2: explicit recovery after removal/fault.
    previous: Digest32,
    proof: Digest32,
    heads: Vec<Digest32>,
}
impl BindingApproval {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(self.kind)
            .bytes(&self.previous)
            .bytes(&self.proof)
            .array(self.heads.len());
        for head in &self.heads {
            e.bytes(head);
        }
        e.finish()
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        arity(&mut d, 4)?;
        let kind = d.uint()?;
        let previous = digest(&mut d)?;
        let proof = digest(&mut d)?;
        let mut heads = Vec::new();
        for _ in 0..count(&mut d)? {
            heads.push(digest(&mut d)?);
        }
        d.finish()?;
        if !matches!(kind, 1 | 2)
            || previous == [0; 32]
            || heads.is_empty()
            || heads.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(bad());
        }
        Ok(Self {
            kind,
            previous,
            proof,
            heads,
        })
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
        let previous = s
            .history
            .values()
            .filter(|r| {
                r.event().ok().is_some_and(|e| {
                    e.author == author && Some(e.group) == s.group() && e.roster_revision > 0
                })
            })
            .max_by_key(|r| r.event().map(|e| e.sequence).unwrap_or(0));
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
        let mut removal = None;
        let mut release = None;
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
            "release" => {
                arity(&mut body, 4)?;
                release = Some(Release {
                    node: digest(&mut body)?,
                    previous: digest(&mut body)?,
                    destination: digest(&mut body)?,
                    nonce: digest(&mut body)?,
                });
            }
            "remove" => {
                arity(&mut body, 3)?;
                let target = digest(&mut body)?;
                let mut grants = Vec::new();
                for _ in 0..count(&mut body)? {
                    grants.push(digest(&mut body)?);
                }
                if grants.is_empty() || grants.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(bad());
                }
                let roster = digest(&mut body)?;
                removal = Some(Removal {
                    target,
                    grants,
                    roster,
                });
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
            removal,
            release,
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
    removal: Option<Removal>,
    release: Option<Release>,
    reach: Option<Reach>,
}
#[derive(Clone)]
struct Release {
    node: Digest32,
    previous: Digest32,
    destination: Digest32,
    nonce: Digest32,
}
#[derive(Clone)]
struct Removal {
    target: Digest32,
    grants: Vec<Digest32>,
    roster: Digest32,
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
struct MembershipInterval {
    activation: u64,
    retirement: Option<u64>,
    grants: BTreeSet<Digest32>,
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
    /// Journal revision of the last effective operator-policy change. Reachability and other
    /// transport records may advance `revision`, but only a later policy cause replaces a missed
    /// policy contract.
    pub policy_revision: u64,
    pub revision: u64,
    pub invitations: Vec<Invitation>,
    pub genesis: Option<Enrollment>,
    pub rosters: BTreeMap<Digest32, Control>,
    /// A pending intent, including approvals already made, survives a crash before both arrive.
    pub pending: Option<Enrollment>,
    /// Exact local policy application revision for each attached node; never a distributed clock.
    pub applied: BTreeMap<Digest32, AppliedPolicy>,
    /// Exact policy-covered grants durably prepared before a node keyring commit. Application
    /// moves these into `applied`; crash recovery includes them in fail-closed revocation.
    prepared: BTreeMap<Digest32, AppliedPolicy>,
    /// Per node of this computer, the revision its binding was last derived at and when
    /// (ADR-038 FX-28): a binding is derived once per revision, across restarts too, and a node
    /// whose record names the current revision is left alone.
    pub derived: BTreeMap<Digest32, DerivedBinding>,
    /// Peers for which this exact local revision was repaired only after its causal deadline.
    /// This operational truth is durable so restart cannot turn a missed contract into success.
    pub missed_exchanges: BTreeMap<Digest32, (u64, bool)>,
    /// A causal exchange obligation is recorded before any network work begins. A timely merge
    /// removes it in the same durable transaction; after a crash an unresolved obligation is a
    /// miss, never permission to manufacture a fresh convergence clock.
    pub pending_exchanges: BTreeMap<Digest32, u64>,
    intervals: BTreeMap<Digest32, Vec<MembershipInterval>>,
    retired_nodes: BTreeMap<Digest32, u64>,
    individual: BTreeMap<Digest32, BTreeMap<Digest32, u64>>,
    aliases: BTreeMap<Digest32, BTreeMap<Digest32, String>>,
    selected: Option<Digest32>,
    selected_name: String,
    binding_approvals: BTreeMap<Digest32, BindingApproval>,
    retired_groups: BTreeMap<Digest32, Enrollment>,
}
impl State {
    /// Advance the durable journal for a management fact which is exchanged but is not yet an
    /// operator-policy fact. The later activation/fold owns `policy_revision`; preview and one-
    /// sided approval still need their own crash-recoverable exchange obligation.
    fn advance_journal(&mut self) -> Result<()> {
        self.revision = self.revision.checked_add(1).ok_or_else(bad)?;
        self.receipts.clear();
        Ok(())
    }

    /// Every identity which can be affected by the current management transaction. A pending
    /// enrollment precedes membership, so `descriptions` alone loses exactly the peer which must
    /// learn a preview or one-sided approval.
    fn exchange_peers(&self) -> Result<BTreeSet<Digest32>> {
        let mut peers: BTreeSet<_> = self.descriptions().into_keys().collect();
        if let Some(pending) = &self.pending {
            for computer in &pending.computers {
                peers.insert(computer.fingerprint()?);
            }
        }
        Ok(peers)
    }

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
    fn was_enrolled(&self, peer: &Digest32) -> bool {
        if self.genesis.as_ref().is_some_and(|g| {
            g.computers
                .iter()
                .any(|c| c.fingerprint().ok() == Some(*peer))
        }) {
            return true;
        }
        self.derive().is_ok_and(|authority| {
            authority.accepted.iter().any(|id| {
                self.history[id]
                    .event()
                    .ok()
                    .and_then(|e| e.addition)
                    .is_some_and(|a| a.computers[1].fingerprint().ok() == Some(*peer))
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
    fn accepted_history(&self) -> Result<BTreeSet<Digest32>> {
        let mut accepted = if self.genesis.is_some() {
            self.derive()?.accepted
        } else {
            BTreeSet::new()
        };
        for genesis in self.retired_groups.values() {
            let mut retired = self.clone();
            retired.genesis = Some(genesis.clone());
            retired.group_genesis = None;
            retired.pending = None;
            accepted.extend(retired.derive()?.accepted);
        }
        Ok(accepted)
    }
    fn terminal_bindings(&self) -> Result<Vec<(Digest32, Binding)>> {
        let authority = self.derive()?;
        let mut bindings = BTreeMap::new();
        let mut previous = BTreeSet::new();
        for id in &authority.binding_records {
            let event = self.history[id].event()?;
            for binding in event.bindings {
                if let Some(approval) = binding.approval()? {
                    previous.insert(approval.previous);
                }
                bindings.insert(binding.id(), (event.author, binding));
            }
        }
        Ok(bindings
            .into_iter()
            .filter_map(|(id, binding)| (!previous.contains(&id)).then_some(binding))
            .collect())
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
        let before = self.revision;
        self.fold_history()?;
        if self.revision == before {
            self.revision = self.revision.checked_add(1).ok_or_else(bad)?;
            self.receipts.clear();
        }
        Ok(())
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
        let initial: Vec<_> = g
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
                let available: Vec<_> = grants
                    .iter()
                    .filter(|(_, v)| v.event == group || prefix.contains(&v.event))
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                let (active, _) = exclude_retired(&events, &ancestry, &prefix, available)?;
                if let Some(release) = &e.release {
                    let prior = prefix
                        .iter()
                        .filter_map(|h| {
                            let record = &events[h];
                            (record.author == e.author && record.roster_revision > 0)
                                .then_some(record)
                        })
                        .max_by_key(|record| record.sequence)
                        .and_then(|record| {
                            record.bindings.iter().find(|b| b.id() == release.previous)
                        });
                    if release.nonce == [0; 32]
                        || release.destination == e.author
                        || !active.iter().any(|(_, g)| {
                            g.computer.fingerprint().ok() == Some(release.destination)
                        })
                        || prior
                            .is_none_or(|b| b.verify(&e.author, &group).ok() != Some(release.node))
                    {
                        return Err(Error::SignatureInvalid);
                    }
                }
                for binding in &e.bindings {
                    verify_binding_context(binding, e, &prefix, &events, &ancestry, &grants)?;
                }
                if !active.iter().any(|(id, a)| {
                    *id == e.grant && a.computer.fingerprint().ok() == Some(e.author)
                }) {
                    return Err(Error::SignatureInvalid);
                }
                if let Some(remove) = &e.removal {
                    let mut observed: Vec<_> = active
                        .iter()
                        .filter_map(|(id, grant)| {
                            (grant.computer.fingerprint().ok() == Some(remove.target))
                                .then_some(*id)
                        })
                        .collect();
                    observed.sort();
                    observed.dedup();
                    let roster = prefix
                        .iter()
                        .filter(|h| {
                            let p = &events[*h];
                            p.author == remove.target && p.roster_revision > 0
                        })
                        .max_by_key(|h| events[*h].sequence)
                        .copied()
                        .unwrap_or([0; 32]);
                    if observed != remove.grants || roster != remove.roster {
                        return Err(Error::SignatureInvalid);
                    }
                }
                if let Some(add) = &e.addition {
                    let target = add.computers[1].fingerprint()?;
                    if active
                        .iter()
                        .any(|(_, a)| a.computer.fingerprint().ok() == Some(target))
                    {
                        return Err(Error::Profile("computer is already enrolled in this group"));
                    }
                    let grant = Grant {
                        computer: add.computers[1].clone(),
                        sponsor: Some(e.grant),
                        event: id,
                    };
                    // Retain grants by ADD event until fork exclusion. Two independently
                    // valid branches can carry the same approved intent/grant: neither branch
                    // may discard the other's transferable fork evidence at insertion.
                    grants.push((add.grants[1], grant));
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
        let (mut members, mut quarantined) =
            exclude_retired(&events, &ancestry, &accepted, grants)?;
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
        members.retain(|(id, _)| !retired.contains(id));
        let mut unique = BTreeMap::new();
        for (id, grant) in members {
            if unique.insert(id, grant).is_some() {
                return Err(bad());
            }
        }
        let members = unique;
        let active: std::collections::BTreeSet<_> = members
            .values()
            .filter_map(|g| g.computer.fingerprint().ok())
            .collect();
        let all_grants: EventGrants = initial
            .into_iter()
            .chain(
                events
                    .iter()
                    .filter(|(id, _)| accepted.contains(*id))
                    .filter_map(|(id, e)| {
                        e.addition.as_ref().map(|add| {
                            (
                                add.grants[1],
                                Grant {
                                    computer: add.computers[1].clone(),
                                    sponsor: Some(e.grant),
                                    event: *id,
                                },
                            )
                        })
                    }),
            )
            .collect();
        let positive = |id: &Digest32| -> Result<bool> {
            let remaining: BTreeSet<_> = accepted
                .iter()
                .filter(|other| !ancestry[*other].contains(id))
                .copied()
                .collect();
            Ok(
                exclude_retired(&events, &ancestry, &remaining, all_grants.clone())?
                    .0
                    .iter()
                    .any(|(grant, _)| *grant == events[id].grant),
            )
        };
        let mut rosters = BTreeMap::new();
        let mut reaches = BTreeMap::new();
        for id in &accepted {
            let e = &events[id];
            if !active.contains(&e.author) || !positive(id)? {
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
        let mut bindings: BTreeMap<Digest32, (Digest32, Digest32, Binding)> = BTreeMap::new();
        let mut successors: BTreeMap<(Digest32, Digest32), BTreeSet<Digest32>> = BTreeMap::new();
        let mut releases: BTreeMap<Digest32, Vec<(Digest32, Release)>> = BTreeMap::new();
        let mut released = BTreeSet::new();
        let mut valid_releases = BTreeSet::new();
        let mut binding_records = BTreeSet::new();
        for id in &accepted {
            let event = &events[id];
            if let Some(release) = &event.release {
                if positive(id)? {
                    released.insert(release.previous);
                    valid_releases.insert(*id);
                    releases
                        .entry(release.previous)
                        .or_default()
                        .push((*id, release.clone()));
                }
            }
            if !positive(id)? {
                continue;
            }
            binding_records.insert(*id);
            for binding in &event.bindings {
                let node = binding.verify(&event.author, &group)?;
                let approval = binding.approval()?;
                let previous = approval.as_ref().map(|a| a.previous).unwrap_or([0; 32]);
                if let Some(approval) = &approval {
                    if approval.kind == 1 && !positive(&approval.proof)? {
                        quarantined.insert(event.author);
                    }
                }
                successors
                    .entry((node, previous))
                    .or_default()
                    .insert(binding.id());
                bindings.insert(binding.id(), (node, event.author, binding.clone()));
            }
        }
        for children in successors.values().filter(|v| v.len() > 1) {
            for id in children {
                quarantined.insert(bindings[id].1);
            }
        }
        for (previous, values) in &releases {
            if values.len() > 1 {
                if let Some((_, manager, _)) = bindings.get(previous) {
                    quarantined.insert(*manager);
                }
                for (_, release) in values {
                    quarantined.insert(release.destination);
                }
            }
        }
        let mut binding_owners = BTreeMap::new();
        for (id, (node, manager, _)) in &bindings {
            if !released.contains(id)
                && !successors.contains_key(&(*node, *id))
                && !quarantined.contains(manager)
            {
                if let Some(old) = binding_owners.insert(*node, *id) {
                    quarantined.insert(bindings[&old].1);
                    quarantined.insert(*manager);
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
            accepted,
            binding_owners,
            valid_releases,
            binding_records,
        })
    }
    fn fold_history(&mut self) -> Result<()> {
        let next = self.derive()?;
        let first_activation = self.genesis.as_ref().is_some_and(|g| {
            g.grants.iter().any(|grant| {
                !self
                    .intervals
                    .values()
                    .flatten()
                    .any(|interval| interval.grants.contains(grant))
            })
        });
        let policy_changed = first_activation
            || self.members != next.members
            || self.rosters != next.rosters
            || self.quarantined != next.quarantined;
        if policy_changed || self.reaches != next.reaches {
            let revision = self.revision.checked_add(1).ok_or_else(bad)?;
            if self.genesis.is_some() {
                let mut active: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
                for (id, grant) in &next.members {
                    let manager = grant.computer.fingerprint()?;
                    if !next.quarantined.contains(&manager) {
                        active.entry(manager).or_default().insert(*id);
                    }
                }
                // A retirement boundary is local and immutable. Replayed or concurrent negative
                // evidence cannot move it over a later deliberate individual trust decision.
                for (manager, intervals) in &mut self.intervals {
                    if let Some(last) = intervals.last_mut().filter(|i| i.retirement.is_none()) {
                        if let Some(grants) = active.get(manager) {
                            last.grants.extend(grants.iter().copied());
                        } else {
                            last.retirement = Some(revision);
                        }
                    }
                }
                for (manager, grants) in active {
                    let intervals = self.intervals.entry(manager).or_default();
                    if intervals.last().is_none_or(|i| i.retirement.is_some()) {
                        intervals.push(MembershipInterval {
                            activation: revision,
                            retirement: None,
                            grants,
                        });
                    }
                }
                // A removed member may first be learned together with its removal. Retain a
                // retirement boundary even when this installation never activated its grants;
                // later binding evidence then uses this boundary, not the later arrival revision.
                let mut known: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
                if let Some(g) = self
                    .genesis
                    .as_ref()
                    .or(self.group_genesis.as_ref())
                    .or(self.pending.as_ref())
                {
                    for (grant, description) in g.grants.iter().zip(&g.computers) {
                        known
                            .entry(description.fingerprint()?)
                            .or_default()
                            .insert(*grant);
                    }
                    for (id, record) in &self.history {
                        if !next.accepted.contains(id) {
                            continue;
                        }
                        let e = record.event()?;
                        if e.group == g.incarnation() {
                            if let Some(add) = e.addition {
                                known
                                    .entry(add.computers[1].fingerprint()?)
                                    .or_default()
                                    .insert(add.grants[1]);
                            }
                        }
                    }
                }
                for (manager, grants) in known {
                    self.intervals.entry(manager).or_insert_with(|| {
                        vec![MembershipInterval {
                            activation: revision,
                            retirement: Some(revision),
                            grants,
                        }]
                    });
                }
                let nodes = |rosters: &BTreeMap<Digest32, Control>| -> Result<BTreeSet<Digest32>> {
                    let mut ids = BTreeSet::new();
                    for roster in rosters.values() {
                        let e = roster.event()?;
                        for b in e.bindings {
                            ids.insert(b.verify(&e.author, &e.group)?);
                        }
                    }
                    Ok(ids)
                };
                for node in nodes(&self.rosters)?.difference(&nodes(&next.rosters)?) {
                    self.retired_nodes.insert(*node, revision);
                }
            }
            self.members = next.members;
            self.rosters = next.rosters;
            self.quarantined = next.quarantined;
            self.reaches = next.reaches;
            self.revision = revision;
            if policy_changed {
                self.policy_revision = revision;
            }
            self.receipts.clear();
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut e = Encoder::for_secrets();
        e.array(30)
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
        e.array(self.intervals.len());
        for (manager, intervals) in &self.intervals {
            e.array(2).bytes(manager).array(intervals.len());
            for interval in intervals {
                e.array(3)
                    .uint(interval.activation)
                    .uint(interval.retirement.unwrap_or(0))
                    .array(interval.grants.len());
                for grant in &interval.grants {
                    e.bytes(grant);
                }
            }
        }
        e.array(self.retired_nodes.len());
        for (node, revision) in &self.retired_nodes {
            e.array(2).bytes(node).uint(*revision);
        }
        e.array(self.individual.len());
        for (node, peers) in &self.individual {
            e.array(2).bytes(node).array(peers.len());
            for (peer, revision) in peers {
                e.array(2).bytes(peer).uint(*revision);
            }
        }
        e.array(self.aliases.len());
        for (node, peers) in &self.aliases {
            e.array(2).bytes(node).array(peers.len());
            for (peer, name) in peers {
                e.array(2).bytes(peer).text(name);
            }
        }
        e.bytes(
            self.selected
                .as_ref()
                .map(|v| v.as_slice())
                .unwrap_or_default(),
        )
        .text(&self.selected_name);
        e.array(self.binding_approvals.len());
        for (node, approval) in &self.binding_approvals {
            e.array(2).bytes(node).bytes(&approval.encode());
        }
        e.array(self.retired_groups.len());
        for (group, genesis) in &self.retired_groups {
            e.array(2).bytes(group).bytes(&genesis.encode());
        }
        e.array(self.derived.len());
        for (node, d) in &self.derived {
            e.array(3).bytes(node).uint(d.revision).uint(d.at_ms);
        }
        e.array(self.missed_exchanges.len());
        for (peer, (revision, repaired)) in &self.missed_exchanges {
            e.array(3)
                .bytes(peer)
                .uint(*revision)
                .uint(u64::from(*repaired));
        }
        e.array(self.pending_exchanges.len());
        for (peer, revision) in &self.pending_exchanges {
            e.array(2).bytes(peer).uint(*revision);
        }
        e.uint(self.policy_revision).array(self.prepared.len());
        for (id, prepared) in &self.prepared {
            e.array(4)
                .bytes(id)
                .uint(prepared.revision)
                .bytes(&prepared.interval)
                .array(prepared.grants.len());
            for (peer, created) in &prepared.grants {
                e.array(2).bytes(peer).uint(*created);
            }
        }
        e.finish()
    }
    fn read(vault: Vec<u8>, body: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(body);
        // 30 elements; older current-version states have no distinct operator-policy revision or
        // durable pre-keyring application record.
        let fields = count(&mut d)?;
        if !(25..=30).contains(&fields) {
            return Err(bad());
        }
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
        let mut intervals = BTreeMap::new();
        for _ in 0..count(&mut d)? {
            arity(&mut d, 2)?;
            let manager = digest(&mut d)?;
            let mut values = Vec::new();
            for _ in 0..count(&mut d)? {
                arity(&mut d, 3)?;
                let activation = d.uint()?;
                let retirement = d.uint()?;
                let mut grants = BTreeSet::new();
                for _ in 0..count(&mut d)? {
                    if !grants.insert(digest(&mut d)?) {
                        return Err(bad());
                    }
                }
                if activation == 0
                    || activation > revision
                    || retirement > revision
                    || (retirement != 0 && retirement < activation)
                    || grants.is_empty()
                    || values.last().is_some_and(|v: &MembershipInterval| {
                        v.retirement.is_none_or(|r| r >= activation)
                    })
                {
                    return Err(bad());
                }
                values.push(MembershipInterval {
                    activation,
                    retirement: (retirement != 0).then_some(retirement),
                    grants,
                });
            }
            if intervals.insert(manager, values).is_some() {
                return Err(bad());
            }
        }
        let mut retired_nodes = BTreeMap::new();
        for _ in 0..count(&mut d)? {
            arity(&mut d, 2)?;
            let node = digest(&mut d)?;
            let at = d.uint()?;
            if at == 0 || at > revision || retired_nodes.insert(node, at).is_some() {
                return Err(bad());
            }
        }
        let mut individual = BTreeMap::new();
        for _ in 0..count(&mut d)? {
            arity(&mut d, 2)?;
            let node = digest(&mut d)?;
            let mut peers = BTreeMap::new();
            for _ in 0..count(&mut d)? {
                arity(&mut d, 2)?;
                let peer = digest(&mut d)?;
                let at = d.uint()?;
                if at == 0 || at > revision || peers.insert(peer, at).is_some() {
                    return Err(bad());
                }
            }
            if individual.insert(node, peers).is_some() {
                return Err(bad());
            }
        }
        let mut aliases = BTreeMap::new();
        for _ in 0..count(&mut d)? {
            arity(&mut d, 2)?;
            let node = digest(&mut d)?;
            let mut peers = BTreeMap::new();
            for _ in 0..count(&mut d)? {
                arity(&mut d, 2)?;
                let peer = digest(&mut d)?;
                let name = d.text()?.to_owned();
                if !super::presentation::safe_name(&name) || peers.insert(peer, name).is_some() {
                    return Err(bad());
                }
            }
            if aliases.insert(node, peers).is_some() {
                return Err(bad());
            }
        }
        let bytes = d.bytes()?;
        let selected = if bytes.is_empty() {
            None
        } else {
            Some(bytes.try_into().map_err(|_| bad())?)
        };
        let selected_name = d.text()?.to_owned();
        if selected.is_some() && !super::presentation::safe_name(&selected_name) {
            return Err(bad());
        }
        let mut binding_approvals = BTreeMap::new();
        for _ in 0..count(&mut d)? {
            arity(&mut d, 2)?;
            let node = digest(&mut d)?;
            let approval = BindingApproval::decode(d.bytes()?)?;
            if binding_approvals.insert(node, approval).is_some() {
                return Err(bad());
            }
        }
        let mut retired_groups = BTreeMap::new();
        for _ in 0..count(&mut d)? {
            arity(&mut d, 2)?;
            let group = digest(&mut d)?;
            let genesis = Enrollment::decode(d.bytes()?)?;
            genesis.verify(true)?;
            if genesis.group.is_some()
                || group != genesis.incarnation()
                || retired_groups.insert(group, genesis).is_some()
            {
                return Err(bad());
            }
        }
        let mut derived = BTreeMap::new();
        if fields >= 26 {
            for _ in 0..count(&mut d)? {
                arity(&mut d, 3)?;
                let node = digest(&mut d)?;
                let at = d.uint()?;
                let at_ms = d.uint()?;
                if at > revision
                    || derived
                        .insert(
                            node,
                            DerivedBinding {
                                revision: at,
                                at_ms,
                            },
                        )
                        .is_some()
                {
                    return Err(bad());
                }
            }
        }
        let mut missed_exchanges = BTreeMap::new();
        if fields >= 27 {
            for _ in 0..count(&mut d)? {
                arity(&mut d, 3)?;
                let peer = digest(&mut d)?;
                let at = d.uint()?;
                let repaired = match d.uint()? {
                    0 => false,
                    1 => true,
                    _ => return Err(bad()),
                };
                if at > revision || missed_exchanges.insert(peer, (at, repaired)).is_some() {
                    return Err(bad());
                }
            }
        }
        let mut pending_exchanges = BTreeMap::new();
        if fields >= 28 {
            for _ in 0..count(&mut d)? {
                arity(&mut d, 2)?;
                let peer = digest(&mut d)?;
                let at = d.uint()?;
                if at > revision || pending_exchanges.insert(peer, at).is_some() {
                    return Err(bad());
                }
            }
        }
        let policy_revision = if fields >= 29 { d.uint()? } else { revision };
        if policy_revision > revision {
            return Err(bad());
        }
        let mut prepared = BTreeMap::new();
        if fields >= 30 {
            for _ in 0..count(&mut d)? {
                arity(&mut d, 4)?;
                let id = digest(&mut d)?;
                let prepared_revision = d.uint()?;
                let interval = digest(&mut d)?;
                let mut grants = BTreeMap::new();
                for _ in 0..count(&mut d)? {
                    arity(&mut d, 2)?;
                    let peer = digest(&mut d)?;
                    let created = d.uint()?;
                    if created == 0
                        || created > prepared_revision
                        || grants.insert(peer, created).is_some()
                    {
                        return Err(bad());
                    }
                }
                if prepared_revision == 0
                    || prepared_revision > revision
                    || prepared
                        .insert(
                            id,
                            AppliedPolicy {
                                revision: prepared_revision,
                                interval,
                                grants,
                            },
                        )
                        .is_some()
                {
                    return Err(bad());
                }
            }
        }
        d.finish()?;
        let mut s = Self {
            prepared,
            pending_exchanges,
            missed_exchanges,
            derived,
            retired_groups,
            binding_approvals,
            intervals,
            retired_nodes,
            individual,
            aliases,
            selected,
            selected_name,
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
            policy_revision,
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
                .or_else(|| s.retired_groups.contains_key(&e.group).then_some(e.group))
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
        s.accepted_history()?;
        Ok(s)
    }
}

fn verify_binding_context(
    binding: &Binding,
    event: &ControlEvent,
    prefix: &BTreeSet<Digest32>,
    events: &BTreeMap<Digest32, ControlEvent>,
    ancestry: &BTreeMap<Digest32, BTreeSet<Digest32>>,
    grants: &EventGrants,
) -> Result<()> {
    let Some(approval) = binding.approval()? else {
        return Ok(());
    };
    let prior = prefix
        .iter()
        .flat_map(|id| events[id].bindings.iter().map(move |b| (&events[id], b)))
        .find(|(_, b)| b.id() == approval.previous)
        .ok_or(Error::SignatureInvalid)?;
    let node = binding.verify(&event.author, &event.group)?;
    if prior.1.verify(&prior.0.author, &event.group)? != node || prior.0.author == event.author {
        return Err(Error::SignatureInvalid);
    }
    let mut context = BTreeSet::new();
    for head in &approval.heads {
        if *head == event.group {
            continue;
        }
        if !prefix.contains(head) {
            return Err(Error::SignatureInvalid);
        }
        context.insert(*head);
        context.extend(ancestry[head].iter().copied());
    }
    match approval.kind {
        1 => {
            let release = events
                .get(&approval.proof)
                .filter(|_| context.contains(&approval.proof))
                .and_then(|e| e.release.as_ref())
                .ok_or(Error::SignatureInvalid)?;
            if release.previous != approval.previous
                || release.node != node
                || release.destination != event.author
            {
                return Err(Error::SignatureInvalid);
            }
        }
        2 => {
            let available = grants
                .iter()
                .filter(|(_, g)| g.event == event.group || context.contains(&g.event))
                .cloned()
                .collect();
            let (active, faults) = exclude_retired(events, ancestry, &context, available)?;
            if active
                .iter()
                .any(|(_, g)| g.computer.fingerprint().ok() == Some(prior.0.author))
                && !faults.contains(&prior.0.author)
            {
                return Err(Error::SignatureInvalid);
            }
            if approval.proof != [0; 32] {
                return Err(bad());
            }
        }
        _ => return Err(bad()),
    }
    Ok(())
}

#[derive(Default)]
struct Authority {
    members: BTreeMap<Digest32, Grant>,
    rosters: BTreeMap<Digest32, Control>,
    reaches: BTreeMap<Digest32, Reach>,
    quarantined: std::collections::BTreeSet<Digest32>,
    complete: bool,
    accepted: BTreeSet<Digest32>,
    binding_owners: BTreeMap<Digest32, Digest32>,
    valid_releases: BTreeSet<Digest32>,
    binding_records: BTreeSet<Digest32>,
}
type EventGrants = Vec<(Digest32, Grant)>;

/// Fork exclusion follows sponsor edges, preserving additions on the shared safe prefix.
fn exclude_retired(
    events: &BTreeMap<Digest32, ControlEvent>,
    ancestry: &BTreeMap<Digest32, std::collections::BTreeSet<Digest32>>,
    selected: &std::collections::BTreeSet<Digest32>,
    mut grants: EventGrants,
) -> Result<(EventGrants, std::collections::BTreeSet<Digest32>)> {
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
    // Each authorized REMOVE is permanent negative evidence. Its causal cutoff preserves
    // independently enrolled descendants from before removal, never concurrent descendants.
    for removal_id in selected {
        let Some(removal) = &events[removal_id].removal else {
            continue;
        };
        let mut invalid: BTreeSet<_> = grants
            .iter()
            .filter_map(|(id, grant)| {
                (grant.computer.fingerprint().ok() == Some(removal.target)
                    && !ancestry
                        .get(&grant.event)
                        .is_some_and(|a| a.contains(removal_id)))
                .then_some(*id)
            })
            .collect();
        loop {
            let before = invalid.len();
            for (id, grant) in &grants {
                if grant.sponsor.is_some_and(|s| invalid.contains(&s))
                    && !ancestry[removal_id].contains(&grant.event)
                {
                    invalid.insert(*id);
                }
            }
            if before == invalid.len() {
                break;
            }
        }
        denied.extend(invalid);
    }
    grants.retain(|(id, _)| !denied.contains(id));
    Ok((grants, forks.into_keys().collect()))
}

/// A complete replacement for the covered part of one node's keyring.
/// `denied` includes retained bindings: a fault cannot reveal an older manual grant.
#[derive(Clone)]
pub struct PolicyPlan {
    /// Exact durable local policy journal revision.
    pub revision: u64,
    /// Effective fixed-policy grants.
    pub grants: Vec<(Digest32, String, crate::node::trust::Capability)>,
    /// Covered grants that must be purged before networking.
    pub denied: Vec<Digest32>,
    /// This revision missed its causal convergence boundary. The plan is revocation-only and
    /// must never be recorded as an ordinary applied policy.
    pub(crate) expired: bool,
}

/// Whether a node-keyring write still belongs to the durable policy observed before that write.
/// The node store and Computer journal cannot share one atomic rename, so the actor must repeat
/// reconciliation when an authenticated policy change wins between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApplicationReceipt {
    Current,
    Reconcile,
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
    /// The policy revision, sent whenever a change moves it: a local change or a merged
    /// exchange alike (ADR-038 FX-28). The daemon reconciles its nodes on this, and on no timer.
    changed: tokio::sync::broadcast::Sender<ComputerChange>,
    /// Each node's plan at the revision it was derived at: the app's polling and every trust
    /// command answer from it while the revision stands, instead of verifying the history again.
    plans: Mutex<BTreeMap<Digest32, (u64, PolicyPlan)>>,
}

/// When a node's management binding was last derived, and at which policy revision (ADR-038
/// FX-28): what `vox computer status` shows, so a person can tell a stale binding from a
/// current one. Part of the signed state, so a restart derives nothing again at the same
/// revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedBinding {
    /// The policy revision the binding was derived at.
    pub revision: u64,
    /// When, Unix milliseconds.
    pub at_ms: u64,
}
impl Computer {
    /// Journal revision of the last effective operator-policy change. Transport-only journal
    /// movement cannot replace a missed policy contract.
    pub fn policy_revision(&self) -> u64 {
        lock(&self.state).policy_revision
    }

    /// Follow the policy revision: `changed()` resolves when a change moved it, whether the
    /// change was made here or arrived in an exchange (ADR-038 FX-28).
    pub fn changes(&self) -> tokio::sync::broadcast::Receiver<ComputerChange> {
        self.changed.subscribe()
    }

    /// Whether `node`'s binding was derived at the current policy revision.
    pub fn binding_current(&self, node: &Digest32) -> bool {
        let s = lock(&self.state);
        !Self::revision_expired(&s)
            && s.derived
                .get(node)
                .is_some_and(|d| d.revision == s.policy_revision)
    }

    /// A failed policy write invalidates current grants even when the durable revision did not
    /// advance. Restart revalidates the retained state and its ability to be saved before attach.
    pub(crate) fn policy_current(&self, applied: u64) -> bool {
        let s = lock(&self.state);
        (s.genesis.is_none() && s.intervals.is_empty())
            || (self.storage_ready().is_ok()
                && !Self::revision_expired(&s)
                && s.policy_revision == applied)
    }

    /// Execute one synchronous irreversible publication only while `node`'s actor projection is
    /// current. The policy-state lock stays held through `publish`, so a durable revocation cannot
    /// land between the final revision/binding check and the room-log or delivery-queue write.
    /// Callers must complete every await (connection, prekey, channel lock) before entering.
    pub(crate) fn publish_with_current_authority<T>(
        &self,
        applied: u64,
        node: Digest32,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        let state = lock(&self.state);
        let unmanaged = state.genesis.is_none() && state.intervals.is_empty();
        let current = unmanaged
            || (self.storage_ready().is_ok()
                && !Self::revision_expired(&state)
                && state.policy_revision == applied
                && state
                    .derived
                    .get(&node)
                    .is_some_and(|derived| derived.revision == state.policy_revision));
        current.then(publish)
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

    pub(crate) fn invalidate_reachers(&self) {
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
                if s.grant(&local).is_none() {
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
    pub fn bind_node(&self, signer: &dyn RootSigner, name: &str) -> Result<()> {
        self.bind_node_until(
            signer,
            name,
            std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN,
        )
    }
    pub(crate) fn bind_node_until(
        &self,
        signer: &dyn RootSigner,
        name: &str,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let Some(group) = self.binding_group() else {
            return Ok(());
        };
        let local = self.signer.fingerprint();
        let key = signer.fingerprint();
        // Derived once per revision (ADR-038 FX-28): the history is verified again only when
        // the policy moved, by a change here or by a merged exchange.
        if self.binding_current(&key) {
            return Ok(());
        }
        self.change_until(deadline, |s| {
            if s.quarantined.contains(&local) {
                return Ok(());
            }
            let (_old_revision, old_personal, mut bindings) = match s.rosters.get(&local) {
                Some(r) => r.read(&local, &group)?,
                None => (0, None, Vec::new()),
            };
            let authority = s.derive()?;
            let approval = s.binding_approvals.get(&key).cloned();
            let mut retained = None;
            let mut was_local = false;
            let mut known = false;
            for id in &authority.accepted {
                let e = s.history[id].event()?;
                for binding in e.bindings {
                    if binding.verify(&e.author, &group)? != key { continue; }
                    known = true;
                    was_local |= e.author == local;
                    if e.author == local && authority.binding_owners.get(&key) == Some(&binding.id()) {
                        retained = Some(binding);
                    }
                }
            }
            if known && retained.is_none() && approval.is_none() {
                if was_local { return Ok(()); } // Released: never silently reclaim an old vault.
                return Err(Error::Profile("this node is bound to another computer; explicitly approve its signed transfer or recovery before unlocking it"));
            }
            if approval.is_some() { bindings.retain(|b| b.verify(&local, &group).ok() != Some(key)); }
            let mut changed = false;
            if let Some(binding) = bindings
                .iter_mut()
                .find(|b| b.verify(&local, &group).ok() == Some(key))
            {
                if binding.name != name {
                    binding.name = name.to_owned();
                    changed = true;
                }
            }
            if !bindings
                .iter()
                .any(|b| b.verify(&local, &group).ok() == Some(key))
            {
                // Reuse this node's own signed binding after local roster removal or rename.
                // A copied fingerprint file or name cannot construct this proof.
                let body = if let Some(approval) = &approval {
                    let mut body = Encoder::new();
                    body.array(6).uint(PROTOCOL).bytes(&signer.public_key().to_bytes())
                        .bytes(&self.signer.public_key().to_bytes()).bytes(&group)
                        .bytes(&random_array::<32>()?).bytes(&approval.encode());
                    body.finish()
                } else { Binding::body(&signer.public_key(), &self.signer.public_key(), &group, &random_array()?) };
                if approval.is_some() { retained = None; }
                let mut binding = if let Some(binding) = retained {
                    binding
                } else {
                    Binding {
                        node: Signed::create(b"vox/computer-binding/v1\0", body.clone(), signer)?,
                        computer: Signed::create(
                            b"vox/computer-binding/v1\0",
                            body,
                            self.signer.as_ref(),
                        )?,
                        name: name.to_owned(),
                    }
                };
                binding.name = name.to_owned();
                bindings.push(binding);
                changed = true;
            }
            if s.selected == Some(key) {
                s.selected_name = name.to_owned();
            }
            let selection = s.selected.filter(|selected| {
                bindings
                    .iter()
                    .any(|b| b.verify(&local, &group).ok() == Some(*selected))
            });
            changed |= selection != old_personal;
            if changed {
                bindings.sort_by_key(|b| sha256(&b.node.public));
                let r = Control::create(s, &bindings, selection, self.signer.as_ref())?;
                s.retain_roster(r)?;
                s.binding_approvals.remove(&key);
            }
            // The revision the binding now stands at: the one the roster event just made, or
            // the one it was found current at. Saved with the state, so a restart does not
            // derive it again.
            s.derived.insert(
                key,
                DerivedBinding {
                    revision: s.policy_revision,
                    at_ms: pairing::now(),
                },
            );
            Ok(())
        })
    }

    /// Exact policy for an attached node, from verified durable rosters. No roster grants room
    /// membership. The revision is the local operator-policy cause, not a distributed clock.
    pub fn plan(&self, node: Digest32) -> Result<Option<PolicyPlan>> {
        let s = lock(&self.state);
        if s.genesis.is_none() && s.intervals.is_empty() {
            return Ok(None);
        }
        self.storage_ready()?;
        if Self::revision_expired(&s) {
            // An expired operator policy is fail closed. Capability changes and grants from
            // earlier revisions are still computer-managed authority; so are grants prepared
            // durably before a node keyring commit whose applied receipt was interrupted by a
            // crash. Leaving either set effective would preserve the authority whose causal
            // application contract was missed.
            let mut denied = BTreeSet::new();
            if let Some(applied) = s.applied.get(&node) {
                denied.extend(applied.grants.keys().copied());
            }
            #[cfg(feature = "test-knobs")]
            let prepared = s
                .prepared
                .get(&node)
                .filter(|_| !fx28_mutant("expired-plan-drops-prepared"));
            #[cfg(not(feature = "test-knobs"))]
            let prepared = s.prepared.get(&node);
            if let Some(prepared) = prepared {
                denied.extend(prepared.grants.keys().copied());
            }
            return Ok(Some(PolicyPlan {
                revision: s.policy_revision,
                grants: Vec::new(),
                denied: denied.into_iter().collect(),
                expired: true,
            }));
        }
        // Derived once per operator-policy revision (ADR-038 FX-28). Reachability journal
        // records do not change trust and cannot make an expired policy current again.
        if let Some((revision, plan)) = lock(&self.plans).get(&node) {
            if *revision == s.policy_revision {
                return Ok(Some(plan.clone()));
            }
        }
        let plan = Self::derive_plan(&s, self.signer.fingerprint(), node)?;
        lock(&self.plans).insert(node, (s.policy_revision, plan.clone()));
        Ok(Some(plan))
    }

    pub(crate) fn current_revision_expired(&self) -> bool {
        let s = lock(&self.state);
        Self::revision_expired(&s)
    }

    fn revision_expired(s: &State) -> bool {
        s.missed_exchanges
            .values()
            .any(|(revision, _)| *revision == s.policy_revision)
    }

    /// The plan for `node` from the verified rosters of `s`, derived.
    fn derive_plan(s: &State, local: Digest32, node: Digest32) -> Result<PolicyPlan> {
        let group = s.genesis.as_ref().map(Enrollment::incarnation);
        let mut covered = BTreeMap::new();
        let mut owner = None;
        let authority = s.derive()?;
        let accepted = s.accepted_history()?;
        for (record_id, r) in &s.history {
            let e = r.event()?;
            if !accepted.contains(record_id) {
                continue;
            }
            for b in &e.bindings {
                let id = b.verify(&e.author, &e.group)?;
                covered
                    .entry(id)
                    .or_insert_with(BTreeSet::new)
                    .insert(e.author);
                if id == node && e.author == local {
                    owner = Some(e.author);
                }
            }
        }
        let owner = owner.ok_or(Error::Profile(
            "this managed node has no authenticated binding yet",
        ))?;
        let mut nodes = BTreeMap::new();
        for (manager, r) in s.rosters.iter().filter(|_| group.is_some()) {
            if s.quarantined.contains(manager) {
                continue;
            }
            let (_, personal, bindings) = r.read(manager, &group.ok_or_else(bad)?)?;
            for b in bindings {
                let id = b.verify(manager, &group.ok_or_else(bad)?)?;
                if authority.binding_owners.get(&id) != Some(&b.id()) {
                    continue;
                }
                if nodes
                    .insert(id, (b.name, personal == Some(id), *manager))
                    .is_some()
                {
                    return Err(bad());
                }
            }
        }
        let own_active = s.grant(&owner).is_some()
            && nodes
                .get(&node)
                .is_some_and(|(_, _, manager)| *manager == owner);
        let own_personal = nodes.get(&node).is_some_and(|(_, personal, _)| *personal);
        let grants: Vec<_> = nodes
            .into_iter()
            .filter(|(id, _)| *id != node && own_active && !s.quarantined.contains(&owner))
            .map(|(id, (name, personal, _))| {
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
        let boundary = |manager: &Digest32| {
            s.intervals
                .get(manager)
                .and_then(|v| v.last())
                .map(|i| i.retirement.unwrap_or(i.activation))
                .unwrap_or(s.revision)
        };
        let denied = covered
            .into_iter()
            .filter_map(|(peer, managers)| {
                let created = s
                    .individual
                    .get(&node)
                    .and_then(|v| v.get(&peer))
                    .copied()
                    .unwrap_or(0);
                let cutoff = managers
                    .iter()
                    .map(&boundary)
                    .chain([
                        boundary(&owner),
                        s.retired_nodes.get(&peer).copied().unwrap_or(0),
                        s.retired_nodes.get(&node).copied().unwrap_or(0),
                    ])
                    .max()
                    .unwrap_or(s.revision);
                (created <= cutoff
                    || s.quarantined.contains(&owner)
                    || managers.iter().any(|m| s.quarantined.contains(m)))
                .then_some(peer)
            })
            .collect();
        Ok(PolicyPlan {
            revision: s.policy_revision,
            grants,
            denied,
            expired: false,
        })
    }

    /// Is this exact local policy revision durably applied to this node's keyring?
    pub fn applied(&self, node: &Digest32, revision: u64) -> bool {
        let state = lock(&self.state);
        !Self::revision_expired(&state)
            && state
                .applied
                .get(node)
                .is_some_and(|a| a.revision == revision)
    }

    /// Record application only after the actor saved the complete keyring under the ordinary
    /// node store protection. A crash before this write repeats reconciliation before networking.
    pub fn mark_applied(&self, node: Digest32, revision: u64, covered: &[Digest32]) -> Result<()> {
        self.mark_applied_until(
            node,
            revision,
            covered,
            std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN,
        )
        .map(|_| ())
    }

    /// Persist the exact revocation set before committing the node's keyring. This is not an
    /// applied receipt: the actor must still save the keyring and call `mark_applied_until`.
    /// If the process ends between those writes, startup expiry can revoke everything that the
    /// interrupted commit may have made effective.
    pub(crate) fn prepare_application_until(
        &self,
        node: Digest32,
        revision: u64,
        covered: &[Digest32],
        deadline: std::time::Instant,
    ) -> Result<()> {
        self.change_until(deadline, |state| {
            if state.policy_revision != revision || Self::revision_expired(state) {
                return Err(Error::Profile(
                    "computer policy changed before its keyring application was prepared",
                ));
            }
            let interval = state
                .genesis
                .as_ref()
                .map(Enrollment::incarnation)
                .unwrap_or([0; 32]);
            state.prepared.insert(
                node,
                AppliedPolicy {
                    revision,
                    interval,
                    grants: covered.iter().map(|peer| (*peer, revision)).collect(),
                },
            );
            Ok(())
        })
    }

    pub(crate) fn mark_applied_until(
        &self,
        node: Digest32,
        revision: u64,
        covered: &[Digest32],
        _deadline: std::time::Instant,
    ) -> Result<ApplicationReceipt> {
        let mut receipt = ApplicationReceipt::Current;
        // The node-keyring commit is already irreversible. Its receipt or rollback decision is
        // safety recovery, not fresh authorization, and must not be abandoned merely because the
        // initiating convergence deadline ended between the two durable stores.
        self.change_durable(|s| {
            if revision > s.policy_revision {
                return Err(bad());
            }
            // The node keyring was prepared while this revision was live, but an authenticated
            // missed-exchange marker may have expired it during the node-store rename. Preserve
            // the durable prepared rollback set and make the actor revoke the just-written grant
            // before it publishes the projection or starts networking. This check deliberately
            // shares the policy-state transaction with the receipt below.
            if revision == s.policy_revision && Self::revision_expired(s) {
                receipt = ApplicationReceipt::Reconcile;
                return Ok(());
            }
            // Another authenticated roster may have arrived during the node store write.
            // Record the exact revision actually applied; the actor retries before authorizing.
            if revision != s.policy_revision {
                receipt = ApplicationReceipt::Reconcile;
            }

            let interval = s
                .genesis
                .as_ref()
                .map(Enrollment::incarnation)
                .unwrap_or([0; 32]);
            let applied = s.applied.entry(node).or_insert_with(|| AppliedPolicy {
                revision,
                interval,
                grants: BTreeMap::new(),
            });
            applied.interval = interval;
            for peer in covered {
                applied.grants.entry(*peer).or_insert(revision);
            }
            applied.revision = revision;
            if s.prepared
                .get(&node)
                .is_some_and(|prepared| prepared.revision == revision)
            {
                s.prepared.remove(&node);
            }
            Ok(())
        })?;
        Ok(receipt)
    }

    /// Record that all computer-managed grants for an expired revision were removed. The miss
    /// itself remains durable; an old applied receipt can therefore never resurrect them.
    pub(crate) fn mark_expired_until(
        &self,
        node: Digest32,
        revision: u64,
        _deadline: std::time::Instant,
    ) -> Result<ApplicationReceipt> {
        let mut receipt = ApplicationReceipt::Current;
        // As with the applied receipt, the keyring write already happened. Completing or
        // superseding its recovery journal cannot be cut off by the earlier apply deadline.
        self.change_durable(|state| {
            if revision > state.policy_revision {
                return Err(bad());
            }
            // A newer authenticated policy can arrive during the revocation keyring rename.
            // The stale revocation is safe but is not current: retain its recovery records and
            // immediately derive the newer policy instead of failing or claiming convergence.
            if state.policy_revision != revision || !Self::revision_expired(state) {
                receipt = ApplicationReceipt::Reconcile;
                return Ok(());
            }
            if let Some(applied) = state.applied.get_mut(&node) {
                applied.grants.clear();
            }
            state.prepared.remove(&node);
            // Receipts are statements by computers, not by their managed nodes.
            state.receipts.remove(&self.signer.fingerprint());
            Ok(())
        })?;
        Ok(receipt)
    }

    /// Whether the durable Computer journal proves this exact node projection is complete.
    /// Expiry is complete only after its prepared rollback set is gone and its recorded
    /// computer-managed grants are empty; observing the expiry marker alone is not settlement.
    pub(crate) fn application_settled(&self, node: &Digest32, revision: u64) -> bool {
        let state = lock(&self.state);
        Self::application_settled_in(&state, node, revision)
    }

    fn application_settled_in(state: &State, node: &Digest32, revision: u64) -> bool {
        // No computer group has policy to apply. Keep this decision under the same state lock as
        // the grouped checks below, so establishing a group cannot race Ready publication.
        if state.genesis.is_none() && state.intervals.is_empty() {
            return true;
        }
        if state.policy_revision != revision || state.prepared.contains_key(node) {
            return false;
        }
        if Self::revision_expired(state) {
            state
                .applied
                .get(node)
                .is_none_or(|applied| applied.grants.is_empty())
        } else {
            state
                .applied
                .get(node)
                .is_some_and(|applied| applied.revision == revision)
        }
    }

    /// Publish one synchronous startup boundary only while the durable application journal is
    /// exactly settled. The state lock stays held through `publish`, so policy movement after the
    /// actor's applied receipt cannot land between this final check and the daemon's Ready
    /// transition.
    pub(crate) fn with_application_settled<T>(
        &self,
        node: &Digest32,
        revision: u64,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        let state = lock(&self.state);
        #[cfg(feature = "test-knobs")]
        let settled = Self::application_settled_in(&state, node, revision)
            || fx28_mutant("ready-fence-accepts-unsettled");
        #[cfg(not(feature = "test-knobs"))]
        let settled = Self::application_settled_in(&state, node, revision);
        settled.then(publish)
    }

    /// Test apparatus predicate for identifying the exact successful applied receipt. It exposes
    /// no authority and is compiled out of shipped builds.
    #[cfg(feature = "test-knobs")]
    pub(crate) fn application_recorded_grant(
        &self,
        node: &Digest32,
        revision: u64,
        peer: &Digest32,
    ) -> bool {
        let state = lock(&self.state);
        state.policy_revision == revision
            && !state.prepared.contains_key(node)
            && state.applied.get(node).is_some_and(|applied| {
                applied.revision == revision && applied.grants.contains_key(peer)
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
        if plan.denied.contains(peer) && !self.individual_permitted(node, peer)? {
            return Err(Error::Profile("this computer authority is quarantined"));
        }
        Ok(plan
            .grants
            .into_iter()
            .find(|(id, _, _)| id == peer)
            .map(|(_, _, c)| c))
    }
    /// Save an explicit local selection, identified by an already-unlocked actor's identity.
    pub fn select_personal(&self, node: Option<Digest32>, name: &str) -> Result<()> {
        let local = self.signer.fingerprint();
        self.change(|s| {
            s.selected = node;
            s.selected_name = name.to_owned();
            if let (Some(group), Some(roster)) = (s.group(), s.rosters.get(&local)) {
                if s.grant(&local).is_some() {
                    let (_, old, bindings) = roster.read(&local, &group)?;
                    if node.is_some_and(|n| !bindings.iter().any(|b| b.verify(&local, &group).ok() == Some(n))) {
                        return Err(Error::Profile("make the selected node Ready so its management binding can be authenticated"));
                    }
                    if old != node {
                        let event = Control::create(s, &bindings, node, self.signer.as_ref())?;
                        s.retain_roster(event)?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Remove only bindings whose local directories no longer exist. Names never create a binding.
    pub fn retain_local_nodes(&self, names: &BTreeSet<String>) -> Result<()> {
        let local = self.signer.fingerprint();
        self.change(|s| {
            let Some(group) = s.group() else {
                return Ok(());
            };
            if s.grant(&local).is_none() {
                return Ok(());
            }
            let Some(roster) = s.rosters.get(&local) else {
                return Ok(());
            };
            let (_, personal, mut bindings) = roster.read(&local, &group)?;
            let was = bindings.len();
            bindings.retain(|b| names.contains(&b.name));
            let selected = personal.filter(|id| {
                bindings
                    .iter()
                    .any(|b| b.verify(&local, &group).ok() == Some(*id))
            });
            if was != bindings.len() {
                let event = Control::create(s, &bindings, selected, self.signer.as_ref())?;
                s.retain_roster(event)?;
            }
            Ok(())
        })
    }

    /// Capture alias metadata before automatic grant consumption or removal.
    pub fn retain_aliases(&self, node: Digest32, aliases: &[(Digest32, String)]) -> Result<()> {
        self.retain_aliases_until(
            node,
            aliases,
            std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN,
        )
    }
    pub(crate) fn retain_aliases_until(
        &self,
        node: Digest32,
        aliases: &[(Digest32, String)],
        deadline: std::time::Instant,
    ) -> Result<()> {
        self.change_until(deadline, |s| {
            s.aliases
                .entry(node)
                .or_default()
                .extend(aliases.iter().cloned());
            Ok(())
        })
    }
    /// A local alias survives a revoked permission.
    pub fn alias(&self, node: &Digest32, peer: &Digest32) -> Option<String> {
        lock(&self.state)
            .aliases
            .get(node)
            .and_then(|m| m.get(peer))
            .cloned()
    }
    fn individual_permitted(&self, node: Digest32, peer: &Digest32) -> Result<bool> {
        let s = lock(&self.state);
        self.storage_ready()?;
        let Some(group) = s.group() else {
            return Ok(true);
        };
        let mut managers = BTreeSet::new();
        for record in s.history.values() {
            let e = record.event()?;
            if e.group != group {
                continue;
            }
            for binding in e.bindings {
                let id = binding.verify(&e.author, &group)?;
                if id == node || id == *peer {
                    managers.insert(e.author);
                }
            }
        }
        Ok(!managers.iter().any(|m| s.quarantined.contains(m)))
    }
    /// The ordinary explicit Trust command after retirement chooses individual mode. Journal
    /// that choice before its keyring write; a failed write grants nothing and can be retried.
    pub fn individual_choice(&self, node: Digest32, peer: Digest32) -> Result<()> {
        if self.capability(node, &peer)?.is_some() {
            return Ok(());
        }
        if !self.individual_permitted(node, &peer)? {
            return Err(Error::SignatureInvalid);
        }
        self.change(|s| {
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            s.policy_revision = s.revision;
            s.individual
                .entry(node)
                .or_default()
                .insert(peer, s.revision);
            s.receipts.clear();
            Ok(())
        })
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
                changed: tokio::sync::broadcast::channel(MAX_RECORDS).0,
                plans: Mutex::new(BTreeMap::new()),
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
            intervals: BTreeMap::new(),
            retired_nodes: BTreeMap::new(),
            individual: BTreeMap::new(),
            aliases: BTreeMap::new(),
            selected: None,
            selected_name: String::new(),
            binding_approvals: BTreeMap::new(),
            retired_groups: BTreeMap::new(),
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
            policy_revision: 0,
            revision: 0,
            invitations: Vec::new(),
            genesis: None,
            rosters: BTreeMap::new(),
            pending: None,
            applied: BTreeMap::new(),
            prepared: BTreeMap::new(),
            derived: BTreeMap::new(),
            missed_exchanges: BTreeMap::new(),
            pending_exchanges: BTreeMap::new(),
        };
        let c = Arc::new(Self {
            path,
            storage_failed: std::sync::atomic::AtomicBool::new(false),
            signer: Arc::new(root),
            state: Mutex::new(state),
            reachers: Mutex::new(Vec::new()),
            changed: tokio::sync::broadcast::channel(MAX_RECORDS).0,
            plans: Mutex::new(BTreeMap::new()),
        });
        c.save(&lock(&c.state))?;
        Ok(c)
    }
    fn save(&self, s: &State) -> Result<()> {
        self.save_before(s, None)
    }
    fn save_before(&self, s: &State, deadline: Option<std::time::Instant>) -> Result<()> {
        #[cfg(feature = "test-knobs")]
        let mutant_snapshot = if fx28_mutant("preview-approval-not-durable") {
            let mut snapshot = s.clone();
            // Save every surrounding transaction but never the authenticated preview or
            // approval-bearing enrollment. Even a later background bookkeeping save cannot
            // accidentally make the deliberately ephemeral fields durable before the crash.
            snapshot.pending = None;
            snapshot.pending_expires = 0;
            snapshot.pair_link = None;
            Some(snapshot)
        } else {
            None
        };
        #[cfg(feature = "test-knobs")]
        let s = mutant_snapshot.as_ref().unwrap_or(s);
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
        if let Some(deadline) = deadline {
            write_private_file_checked(&self.path, &bytes, || {
                if std::time::Instant::now() >= deadline {
                    Err(Error::Profile(
                        "the computer change reached its causal convergence deadline before its atomic commit",
                    ))
                } else {
                    Ok(())
                }
            })
        } else {
            write_private_file(&self.path, &bytes)
        }
    }
    /// Commit a complete management transaction before publishing it to live authorization.
    pub(crate) fn change<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        self.change_until(std::time::Instant::now() + COMPUTER_RETURN_SHOWN_WITHIN, f)
    }

    /// Commit a transaction whose causal event already owns `deadline`. A merge and the
    /// attached-node reconciliation it wakes share this one clock.
    pub(crate) fn change_until<T>(
        &self,
        deadline: std::time::Instant,
        f: impl FnOnce(&mut State) -> Result<T>,
    ) -> Result<T> {
        let mut held = lock(&self.state);
        self.storage_ready()?;
        if std::time::Instant::now() >= deadline {
            return Err(Error::Profile(
                "the computer change reached its causal convergence deadline before its transaction began",
            ));
        }
        let mut next = held.clone();
        let value = match f(&mut next) {
            Ok(value) => value,
            Err(Error::Profile(HISTORY_FULL)) => {
                self.storage_failure();
                return Err(Error::Profile(HISTORY_FULL));
            }
            Err(error) => return Err(error),
        };
        // The obligation is part of the same durable transaction as its exchanged cause. This
        // includes authenticated preview and one-sided approval, before activation makes either
        // one operator policy. A crash after this save therefore recovers the exact unfinished
        // journal cause; it can never manufacture a fresh clock after restart.
        if held.revision != next.revision {
            let local = self.signer.fingerprint();
            let policy_moved = held.policy_revision != next.policy_revision;
            for peer in next
                .exchange_peers()?
                .into_iter()
                .filter(|peer| *peer != local)
            {
                // A transport-only journal movement cannot overwrite an unfinished policy
                // cause: after a crash that would turn a real policy miss into an irrelevant
                // reach revision. A newer operator policy does replace the durable cause (and
                // `mark_retry` independently keeps the earlier absolute deadline in memory).
                match next.pending_exchanges.entry(peer) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(if policy_moved {
                            next.policy_revision
                        } else {
                            next.revision
                        });
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) if policy_moved => {
                        entry.insert(next.policy_revision);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
            }
        }
        if held.body() != next.body() {
            if std::time::Instant::now() >= deadline {
                return Err(Error::Profile(
                    "the computer change reached its causal convergence deadline before it could be saved",
                ));
            }
            if let Err(error) = self.save_before(&next, Some(deadline)) {
                self.storage_failure();
                return Err(error);
            }
            let committed_late = std::time::Instant::now() >= deadline;
            let moved = held.revision != next.revision;
            let authorization_changed = held.policy_revision != next.policy_revision
                || Self::revision_expired(&held) != Self::revision_expired(&next);
            if authorization_changed {
                self.invalidate_reachers();
            }
            *held = next;
            if committed_late {
                self.invalidate_reachers();
                // The atomic rename happened. Publish an already-expired reconciliation event so
                // actors revoke/detach instead of leaving the durable new policy live but unseen.
                if moved || authorization_changed {
                    let now = std::time::Instant::now();
                    let _ = self.changed.send(ComputerChange {
                        revision: held.policy_revision,
                        apply_deadline: now,
                        return_deadline: deadline,
                    });
                }
                return Err(Error::Profile(
                    "the computer change committed at its causal boundary and was published as expired",
                ));
            }
            if moved || authorization_changed {
                // A change here, or a merged exchange that moved this daemon's revision: either
                // is a change here (ADR-038 FX-28), and the daemon reconciles its nodes on it.
                // The local apply contract may shorten an outer return deadline, never extend it.
                let _ = self.changed.send(ComputerChange {
                    revision: held.policy_revision,
                    apply_deadline: deadline
                        .min(std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN),
                    return_deadline: deadline,
                });
            }
        }
        Ok(value)
    }

    pub(crate) fn missed_exchanges(&self) -> (u64, BTreeMap<Digest32, (u64, bool)>) {
        let state = lock(&self.state);
        (state.policy_revision, state.missed_exchanges.clone())
    }

    pub(crate) fn record_missed_exchange(
        &self,
        peer: Digest32,
        revision: u64,
        repaired: bool,
    ) -> Result<u64> {
        self.change_durable(|state| {
            // A superseded older flight cannot consume or expire the newer operator cause which
            // replaced its obligation before the scheduler cut it.
            let pending = state
                .pending_exchanges
                .get(&peer)
                .copied()
                .filter(|cause| *cause <= revision);
            let retained = state
                .missed_exchanges
                .get(&peer)
                .map(|(cause, _)| *cause)
                .filter(|cause| *cause == state.policy_revision);
            let cause = pending.or(retained).unwrap_or(revision);
            // A failed fallback or reachability-only journal exchange is transport evidence, not
            // an expired operator policy. Policy causes are always atomically pending; equality
            // retains the conservative migration behavior for a pre-amendment state.
            if pending.is_none() && retained.is_none() && revision != state.policy_revision {
                return Ok(revision);
            }
            let held = state
                .missed_exchanges
                .entry(peer)
                .or_insert((cause, repaired));
            if cause > held.0 || (cause == held.0 && repaired) {
                *held = (cause, repaired);
            }
            if pending.is_some() {
                state.pending_exchanges.remove(&peer);
            }
            Ok(cause)
        })
    }

    /// Own the consequence of a causal exchange before opening a socket. This write has no
    /// elapsed product verdict: it either commits, or the exchange is not allowed to start.
    pub(crate) fn record_pending_exchange(&self, peer: Digest32, revision: u64) -> Result<bool> {
        self.change_durable(|state| {
            if state.revision != revision {
                return Ok(false);
            }
            // An atomically recorded policy obligation is older and stronger than later
            // reachability/journal movement carried by this exchange.
            state.pending_exchanges.entry(peer).or_insert(revision);
            Ok(true)
        })
    }

    /// Clear a precommitted obligation only after the complete exchange returned within its
    /// causal boundary. A crash before this durable acknowledgement leaves the conservative
    /// unresolved record for startup to expire; it can never erase a real miss.
    pub(crate) fn record_timely_exchange(&self, peer: Digest32, revision: u64) -> Result<()> {
        self.change_durable(|state| {
            // The completed flight may acknowledge only the state it actually sent. A newer
            // obligation which appeared while it was in flight remains pending.
            if state
                .pending_exchanges
                .get(&peer)
                .is_some_and(|cause| *cause <= revision)
            {
                state.pending_exchanges.remove(&peer);
            }
            Ok(())
        })
    }

    /// A process exit cannot reset a causal clock. An exchange that was durably in progress has
    /// no proof of timely completion after restart, so recovery promotes it to an exact miss.
    pub(crate) fn recover_pending_exchanges(&self) -> Result<()> {
        self.change_durable(|state| {
            for (peer, revision) in std::mem::take(&mut state.pending_exchanges) {
                let held = state
                    .missed_exchanges
                    .entry(peer)
                    .or_insert((revision, false));
                if revision > held.0 {
                    *held = (revision, false);
                }
            }
            Ok(())
        })
    }

    /// Persistence used by convergence bookkeeping whose truth must survive a crash and which
    /// has no wall-clock success criterion of its own.
    fn change_durable<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut held = lock(&self.state);
        self.storage_ready()?;
        let mut next = held.clone();
        let value = f(&mut next)?;
        if held.body() != next.body() {
            if let Err(error) = self.save_before(&next, None) {
                self.storage_failure();
                return Err(error);
            }
            let authorization_changed =
                Self::revision_expired(&held) != Self::revision_expired(&next);
            if authorization_changed {
                self.invalidate_reachers();
            }
            *held = next;
            if authorization_changed {
                let _ = self.changed.send(ComputerChange {
                    revision: held.policy_revision,
                    apply_deadline: std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN,
                    return_deadline: std::time::Instant::now() + COMPUTER_RETURN_SHOWN_WITHIN,
                });
            }
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
            if (state.genesis.is_none() && state.intervals.is_empty())
                || (self.storage_ready().is_ok()
                    && !Self::revision_expired(&state)
                    && applied == state.policy_revision)
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
        let s = lock(&self.state);
        s.genesis.is_some() || !s.intervals.is_empty()
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
    if [
        "VOX_SESSION",
        "CLAUDE_CODE_SESSION_ID",
        "CODEX_THREAD_ID",
        "OPENCODE_SESSION_ID",
    ]
    .iter()
    .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
    {
        return Err(Error::Profile("computer pairing is the person's action: use your own terminal or Vox.app outside the agent session"));
    }
    Ok(())
}
