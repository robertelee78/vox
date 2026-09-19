//! Per-channel state for the single-device node (ADR-016 M13.3): create a
//! channel, open it from the store, append and render messages, and persist
//! every step as sealed segments.
//!
//! ## What a channel is, at rest
//! Under the channel's SEK (ADR-010), sealed segments in the profile store:
//! - `KeyMaterial 0` — the **manifest**: `[1, genesis_wire, local_name, created,
//!   epoch]`. The genesis is the trust anchor (ADR-007); `local_name` is this
//!   device's label, never protocol state.
//! - `KeyMaterial 1` — this identity's **sender chain** state
//!   ([`SenderChain::to_state`]), advanced and re-sealed on every append.
//! - `LogDb n` (`n ≥ 1`, arrival order) — one ADR-008 log entry's wire bytes.
//! - `PlaintextCache n` — the rendered form of entry `n`: `[1, entry_hash,
//!   author_id, created_secs, text]` (ADR-010 permits a plaintext cache only
//!   inside a sealed segment; on open, each cache row is accepted only if its
//!   `entry_hash` is in the rebuilt DAG).
//!
//! The SEK wrap itself lives in the store's `sek_wraps` table.
//!
//! ## Invariants
//! - The DAG is rebuilt from the log segments on every open through the full
//!   ADR-008 acceptance predicate (`Dag::accept`): the store is a cache of
//!   *verified* entries, never trusted as such.
//! - An append is atomic: entry, plaintext cache and the advanced chain state
//!   commit in one [`crate::node::store::Batch`]. If the commit fails the channel
//!   is marked **poisoned** and refuses further appends until reopened — the
//!   in-memory chain has already advanced, and re-using a sender-key iteration for
//!   a different plaintext would be a key/nonce reuse (ADR-006), so the only safe
//!   continuation is the on-disk state.
//! - Double-lock (ADR-010): opening needs the unlocked identity (the identity
//!   factor) *and* the channel passphrase; there is no path to the SEK without both.
//!
//! M13 is single-device: the only author is this identity, membership is
//! `{self}`, and the channel's governance evaluator is built over the genesis
//! alone. M14 adds other authors' entries, SKDMs, consent and sync on top of the
//! same layout.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::atrest::idfactor::SignatureIdentityFactor;
use crate::atrest::sek::{Argon2Profile, Sek};
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::consent::ConsentGrant;
use crate::governance::entry::GovEntry;
use crate::governance::evaluator::Evaluator;
use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use crate::governance::membership::{issue_consent_grant, MembershipView};
use crate::group::skdm::Skdm;
use crate::group::state::SenderChain;
use crate::group::wire::GROUP_MSG_SIGN_DOMAIN;
use crate::hash::{sha256, Digest32};
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::log::dag::{AdmissionPolicy, Dag};
use crate::log::entry::{Entry, EntryKind, EntrySkeleton, ZERO_HASH};
use crate::log::feed::lipmaa;
use crate::node::content::Content;
use crate::node::profile::Profile;
use crate::suite::{algo, SuiteFloor};

/// Segment id of the manifest in `KeyMaterial`.
const SEG_MANIFEST: u64 = 0;
/// The admitted-authors segment id within [`SegmentKind::KeyMaterial`] (M14.5): the
/// composite keys of every identity whose entries this node accepts into the log.
const SEG_AUTHORS: u64 = 2;
/// Segment id of this identity's sender chain in `KeyMaterial`.
const SEG_SENDER: u64 = 1;
/// Manifest encoding version.
const MANIFEST_VERSION: u64 = 1;
/// Plaintext-cache row encoding version.
const CACHE_VERSION: u64 = 1;

/// At-rest version of the admitted-authors segment.
const AUTHORS_VERSION: u64 = 1;

/// Hard cap on admitted authors per channel, so a hostile or corrupt segment cannot
/// force an unbounded allocation on open.
pub const MAX_AUTHORS: usize = 1024;
/// Cap on a local channel name.
pub const MAX_LOCAL_NAME_LEN: usize = 128;

/// What [`ChannelState::accept_entry`] did with a peer's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// A governance entry: verified, stored, and folded into the evaluator.
    Governance,
    /// A content entry: verified and stored, but not readable — this node holds no
    /// sender key for that author yet (ADR-007: consent, not credentials, grants
    /// reading).
    ContentNotReadable,
}

/// A rendered (decrypted, render-gated) message in the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The ADR-008 entry hash this rendering belongs to.
    pub entry_hash: Digest32,
    /// The author's identity fingerprint.
    pub author: Digest32,
    /// The author's recorded send time (seconds).
    pub created_secs: u64,
    /// The text.
    pub text: String,
}

/// An open (SEK-unlocked) channel on this device.
pub struct ChannelState {
    channel_id: Digest32,
    genesis: Genesis,
    local_name: String,
    created: u64,
    epoch: u64,
    sek: Sek,
    /// Author fingerprint → composite root key (M13: the creator only).
    authors: BTreeMap<Digest32, CompositePublicKey>,
    admission: AdmissionPolicy,
    dag: Dag,
    evaluator: Evaluator,
    sender: SenderChain,
    /// The next `LogDb` / `PlaintextCache` segment id.
    next_log_id: u64,
    timeline: Vec<Rendered>,
    /// Accepted governance entries (consent grants and the rest) in acceptance
    /// order — the evaluator's input, rebuilt from the log on open (M14.5).
    gov_entries: Vec<GovEntry>,
    poisoned: bool,
}

impl std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelState")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("local_name", &self.local_name)
            .field("epoch", &self.epoch)
            .field("entries", &self.dag.len())
            .field("authors", &self.authors.len())
            .field("governance", &self.gov_entries.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn manifest_bytes(genesis: &Genesis, local_name: &str, created: u64, epoch: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(MANIFEST_VERSION)
        .bytes(&genesis.to_wire())
        .text(local_name)
        .uint(created)
        .uint(epoch);
    e.finish()
}

fn parse_manifest(bytes: &[u8]) -> Result<(Genesis, String, u64, u64)> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("channel manifest arity"));
    }
    if d.uint()? != MANIFEST_VERSION {
        return Err(Error::MalformedAtRest("channel manifest version"));
    }
    let genesis = Genesis::from_wire(d.bytes()?)?;
    let name = d.text()?;
    if name.len() > MAX_LOCAL_NAME_LEN {
        return Err(Error::SizeLimitExceeded("channel local name"));
    }
    let name = name.to_owned();
    let created = d.uint()?;
    let epoch = d.uint()?;
    d.finish()?;
    Ok((genesis, name, created, epoch))
}

/// The admitted-authors segment: `[version, [[fingerprint, composite_pubkey], …]]`
/// in fingerprint order (a `BTreeMap`, so the bytes are canonical).
fn authors_bytes(authors: &BTreeMap<Digest32, CompositePublicKey>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(AUTHORS_VERSION).array(authors.len());
    for (fp, key) in authors {
        e.array(2).bytes(fp).bytes(&key.to_bytes());
    }
    e.finish()
}

fn parse_authors(bytes: &[u8]) -> Result<BTreeMap<Digest32, CompositePublicKey>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("channel authors arity"));
    }
    if d.uint()? != AUTHORS_VERSION {
        return Err(Error::MalformedAtRest("channel authors version"));
    }
    let n = d.array()?;
    if n > MAX_AUTHORS {
        return Err(Error::SizeLimitExceeded("channel authors"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("channel author tuple arity"));
        }
        let fp: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("channel author fingerprint"))?;
        let key_bytes: [u8; crate::hash::COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("channel author key length"))?;
        let key = CompositePublicKey::from_bytes(&key_bytes)?;
        // The stored fingerprint must be the key's own: a swapped pair would admit
        // an identity under another's name.
        if key.fingerprint() != fp {
            return Err(Error::MalformedAtRest("channel author key/fingerprint"));
        }
        out.insert(fp, key);
    }
    d.finish()?;
    Ok(out)
}

/// Classify a log entry by its payload — the discriminator ADR-008's `kind_for`
/// lacked (it defaulted every entry to `Content`).
///
/// The two payload families are self-describing and disjoint: a governance payload
/// is a struct-tagged ADR-008 frame, while a sender-key message is domain-prefixed
/// with `vox/group-msg/v1`. Anything else is neither, and is refused rather than
/// optimistically treated as content.
fn classify_payload(payload: &[u8]) -> Result<EntryKind> {
    if payload.starts_with(GROUP_MSG_SIGN_DOMAIN.as_bytes()) {
        return Ok(EntryKind::Content);
    }
    if crate::wire::parse_frame(payload).is_ok() {
        return Ok(EntryKind::Governance);
    }
    Err(Error::MalformedAtRest(
        "entry payload is neither a group message nor a governance struct",
    ))
}

fn cache_bytes(r: &Rendered) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(CACHE_VERSION)
        .bytes(&r.entry_hash)
        .bytes(&r.author)
        .uint(r.created_secs)
        .text(&r.text);
    e.finish()
}

fn parse_cache(bytes: &[u8]) -> Result<Rendered> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("plaintext cache arity"));
    }
    if d.uint()? != CACHE_VERSION {
        return Err(Error::MalformedAtRest("plaintext cache version"));
    }
    let entry_hash: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache entry hash"))?;
    let author: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache author"))?;
    let created_secs = d.uint()?;
    let text = d.text()?.to_owned();
    d.finish()?;
    Ok(Rendered {
        entry_hash,
        author,
        created_secs,
        text,
    })
}

impl ChannelState {
    /// Create a new channel on this device: genesis at the day-one suite floor
    /// with the default policy (forward-only history, attributable content, no
    /// TTL), a fresh SEK double-locked under (identity factor, `channel_passphrase`)
    /// with the production Argon2id profile, and this identity's first sender
    /// chain. Persists the wrap, manifest and chain atomically.
    pub fn create(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        Self::create_with_profile(
            profile,
            local_name,
            channel_passphrase,
            now_secs,
            Argon2Profile::default(),
        )
    }

    /// [`ChannelState::create`] with an explicit Argon2id profile (tests).
    pub fn create_with_profile(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        if local_name.len() > MAX_LOCAL_NAME_LEN {
            return Err(Error::SizeLimitExceeded("channel local name"));
        }
        let signer = profile.signer()?;
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: SuiteFloor::DAY_ONE.id(),
        };
        let genesis = Genesis::create(signer, now_secs, policy)?;
        let channel_id = genesis.channel_id();
        let epoch = 0u64;
        let me = signer.fingerprint();

        let sek = Sek::generate()?;
        let factor = SignatureIdentityFactor::new(signer);
        let wrap = sek.seal(&factor, &channel_id, channel_passphrase, argon2)?;
        let sender = SenderChain::new(&channel_id, epoch, &me, 0, now_secs)?;

        let manifest = manifest_bytes(&genesis, local_name, now_secs, epoch);
        let manifest_seg = seal_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest)?;
        let sender_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender.to_state(),
        )?;
        let mut authors = BTreeMap::new();
        authors.insert(me, signer.public_key());
        let authors_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&authors),
        )?;

        let mut batch = profile.store().batch()?;
        batch.put_sek_wrap(&channel_id, &wrap)?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_seg,
        )?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_MANIFEST,
            &manifest_seg,
        )?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender_seg,
        )?;
        batch.commit()?;

        let mut admission = AdmissionPolicy::new();
        admission.admit(channel_id, epoch, me);
        let evaluator = Self::build_evaluator(&genesis, &authors, &[], now_secs)?;
        Ok(Self {
            channel_id,
            genesis,
            local_name: local_name.to_owned(),
            created: now_secs,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::new(),
            evaluator,
            sender,
            next_log_id: 1,
            timeline: Vec::new(),
            gov_entries: Vec::new(),
            poisoned: false,
        })
    }

    /// Open a channel from the store: double-lock unwrap of the SEK, then rebuild
    /// the DAG from the log segments through the full acceptance predicate, load
    /// the timeline from the plaintext cache (rows whose entry is not in the DAG
    /// are dropped), and restore the sender chain.
    pub fn open(
        profile: &Profile,
        channel_id: &Digest32,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        let signer = profile.signer()?;
        let store = profile.store();
        let wrap = store
            .get_sek_wrap(channel_id)?
            .ok_or(Error::Profile("no such channel in this profile"))?;
        let factor = SignatureIdentityFactor::new(signer);
        let sek = wrap.unwrap_sek(&factor, channel_id, channel_passphrase)?;

        let manifest_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_MANIFEST)?
            .ok_or(Error::MalformedAtRest("channel manifest missing"))?;
        let manifest = open_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest_seg)?;
        let (genesis, local_name, created, epoch) = parse_manifest(&manifest)?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedAtRest("channel manifest genesis mismatch"));
        }

        // The admitted authors (M14.5). A channel created before this segment
        // existed has only its creator, which is exactly what it had.
        let mut authors =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_AUTHORS)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_AUTHORS, &seg)?;
                    parse_authors(&bytes)?
                }
                None => BTreeMap::new(),
            };
        // The creator is always an author: it signed the genesis whose hash is the
        // channelID, so it cannot be excluded by a tampered segment.
        authors.insert(
            genesis.body.creator_pubkey.fingerprint(),
            genesis.body.creator_pubkey.clone(),
        );
        let mut admission = AdmissionPolicy::new();
        for author in authors.keys() {
            admission.admit(*channel_id, epoch, *author);
        }

        // Rebuild the DAG: every stored entry re-passes the acceptance predicate,
        // classified by its payload so governance entries are not re-admitted as
        // content.
        let mut dag = Dag::new();
        let mut next_log_id = 1u64;
        let mut gov_entries = Vec::new();
        for (id, seg) in store.segments(channel_id, SegmentKind::LogDb)? {
            let wire = open_segment(&sek, SegmentKind::LogDb, id, &seg)?;
            let entry = Entry::from_wire(&wire)?;
            let key = authors
                .get(&entry.skeleton.author_id)
                .ok_or(Error::MalformedAtRest("stored entry from unknown author"))?
                .clone();
            let payload = entry
                .payload
                .as_deref()
                .ok_or(Error::MalformedAtRest("stored entry payload pruned"))?;
            let kind = classify_payload(payload)?;
            if kind == EntryKind::Governance {
                gov_entries.push(GovEntry::from_verified_log_entry(
                    &entry,
                    &key,
                    channel_id,
                    Default::default(),
                )?);
            }
            dag.accept(entry, kind, &key, &admission, now_secs)
                .map_err(|_| Error::MalformedAtRest("stored entry failed acceptance"))?;
            next_log_id = id.saturating_add(1);
        }

        // Timeline from the sealed plaintext cache, render-gated by the DAG.
        let mut timeline = Vec::new();
        for (id, seg) in store.segments(channel_id, SegmentKind::PlaintextCache)? {
            let row = open_segment(&sek, SegmentKind::PlaintextCache, id, &seg)?;
            let rendered = parse_cache(&row)?;
            if dag.contains(&rendered.entry_hash) {
                timeline.push(rendered);
            }
        }

        let sender_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_SENDER)?
            .ok_or(Error::MalformedAtRest("sender chain missing"))?;
        let sender_state = open_segment(&sek, SegmentKind::KeyMaterial, SEG_SENDER, &sender_seg)?;
        let sender = SenderChain::from_state(&sender_state)?;
        drop(sender_state);

        let evaluator = Self::build_evaluator(&genesis, &authors, &gov_entries, now_secs)?;
        Ok(Self {
            channel_id: *channel_id,
            genesis,
            local_name,
            created,
            epoch,
            sek,
            authors,
            admission,
            dag,
            evaluator,
            sender,
            next_log_id,
            timeline,
            gov_entries,
            poisoned: false,
        })
    }

    fn build_evaluator(
        genesis: &Genesis,
        authors: &BTreeMap<Digest32, CompositePublicKey>,
        gov_entries: &[GovEntry],
        now_secs: u64,
    ) -> Result<Evaluator> {
        Evaluator::build(genesis, gov_entries, now_secs, |id| {
            authors.get(id).cloned()
        })
    }

    /// Create the local state for a channel this identity **joined** (ADR-007
    /// §"Join and per-sender consent flow", step 1) rather than created.
    ///
    /// `genesis` comes from the rendezvous board and is accepted **only if its hash
    /// equals `channel_id`** (ADR-007: that check, not any roster, is what makes a
    /// cold-fetched genesis trustworthy). The joiner gets its own local SEK (the
    /// at-rest double-lock is per device, ADR-010) and its own sender chain at
    /// `chain_id` 0 — holding channel credentials releases **no** sender keys, so it
    /// can read nothing until members consent (step 3); its own messages are
    /// readable by others only once it distributes its SKDM (step 2).
    ///
    /// The creator is admitted as an author immediately (its key is in the verified
    /// genesis); every other member is admitted as its verified key arrives.
    pub fn join_channel(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        Self::join_channel_with_profile(
            profile,
            genesis,
            channel_id,
            local_name,
            channel_passphrase,
            now_secs,
            Argon2Profile::default(),
        )
    }

    /// [`ChannelState::join_channel`] with an explicit Argon2id profile (tests use
    /// the reduced one).
    pub fn join_channel_with_profile(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        if local_name.len() > MAX_LOCAL_NAME_LEN {
            return Err(Error::SizeLimitExceeded("channel local name"));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedGovernance(
                "genesis hash is not the channelID joined with",
            ));
        }
        if profile.store().get_sek_wrap(channel_id)?.is_some() {
            return Err(Error::Profile("this channel is already in the profile"));
        }
        let epoch = 0u64;
        let sek = Sek::generate()?;
        let factor = SignatureIdentityFactor::new(signer);
        let wrap = sek.seal(&factor, channel_id, channel_passphrase, argon2)?;
        let sender = SenderChain::new(channel_id, epoch, &me, 0, now_secs)?;

        let creator = genesis.body.creator_pubkey.fingerprint();
        let mut authors = BTreeMap::new();
        authors.insert(creator, genesis.body.creator_pubkey.clone());
        authors.insert(me, signer.public_key());

        let manifest = manifest_bytes(genesis, local_name, now_secs, epoch);
        let manifest_seg = seal_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest)?;
        let sender_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender.to_state(),
        )?;
        let authors_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&authors),
        )?;
        let mut batch = profile.store().batch()?;
        batch.put_sek_wrap(channel_id, &wrap)?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_MANIFEST,
            &manifest_seg,
        )?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender_seg,
        )?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_seg,
        )?;
        batch.commit()?;

        let mut admission = AdmissionPolicy::new();
        for author in authors.keys() {
            admission.admit(*channel_id, epoch, *author);
        }
        let evaluator = Self::build_evaluator(genesis, &authors, &[], now_secs)?;
        Ok(Self {
            channel_id: *channel_id,
            genesis: genesis.clone(),
            local_name: local_name.to_owned(),
            created: now_secs,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::new(),
            evaluator,
            sender,
            next_log_id: 1,
            timeline: Vec::new(),
            gov_entries: Vec::new(),
            poisoned: false,
        })
    }

    /// Admit `key` as a log author for this channel: its entries are accepted into
    /// the DAG and its governance entries are evaluated (ADR-007 — admission is a
    /// *log* fact, not a read grant; reading still requires that author's SKDM and
    /// this node's consent view).
    ///
    /// The key must hash to `fingerprint` (ADR-016: author keys come from the
    /// verified genesis, admin certificates, or the board's records, each of which
    /// carries the full composite key). Idempotent: re-admitting the same key is a
    /// no-op that still succeeds.
    pub fn admit_author(
        &mut self,
        profile: &Profile,
        key: &CompositePublicKey,
        now_secs: u64,
    ) -> Result<bool> {
        let fingerprint = key.fingerprint();
        if let Some(existing) = self.authors.get(&fingerprint) {
            if existing.to_bytes() == key.to_bytes() {
                return Ok(false);
            }
            // Two different keys claiming one fingerprint is a SHA-256 collision or
            // a bug; either way, never silently replace an admitted author.
            return Err(Error::MalformedGovernance(
                "another key is already admitted for this fingerprint",
            ));
        }
        if self.authors.len() >= MAX_AUTHORS {
            return Err(Error::SizeLimitExceeded("channel authors"));
        }
        self.authors.insert(fingerprint, key.clone());
        self.admission
            .admit(self.channel_id, self.epoch, fingerprint);
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&self.authors),
        )?;
        if let Err(e) = profile.store().put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        self.evaluator =
            Self::build_evaluator(&self.genesis, &self.authors, &self.gov_entries, now_secs)?;
        Ok(true)
    }

    /// Whether `fingerprint` is an admitted log author.
    #[must_use]
    pub fn is_author(&self, fingerprint: &Digest32) -> bool {
        self.authors.contains_key(fingerprint)
    }

    /// The admitted authors' keys, in fingerprint order.
    #[must_use]
    pub fn author_keys(&self) -> Vec<CompositePublicKey> {
        self.authors.values().cloned().collect()
    }

    /// Issue a **consent grant** to `target`: the ADR-007 log fact that this
    /// identity released its sender key to `target`, carrying the `skdm_ref` of the
    /// SKDM actually delivered over the pairwise session and the history mode in
    /// force. Appends it as a governance entry and folds it into the evaluator, so
    /// `target` immediately reads as consented in this node's view.
    ///
    /// The SKDM delivery itself is the caller's (M14.5b); this records the consent.
    pub fn issue_consent(
        &mut self,
        profile: &Profile,
        target: Digest32,
        delivered_skdm: &Skdm,
        now_secs: u64,
    ) -> Result<ConsentGrant> {
        let signer = profile.signer()?;
        let grant = issue_consent_grant(
            signer,
            &self.channel_id,
            self.epoch,
            target,
            delivered_skdm,
            self.genesis.body.policy.history_mode,
        )?;
        self.append_governance(profile, &grant.to_wire(), now_secs)?;
        Ok(grant)
    }

    /// Append an already-built governance struct as a signed log entry.
    fn append_governance(
        &mut self,
        profile: &Profile,
        payload: &[u8],
        now_secs: u64,
    ) -> Result<Digest32> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile(
                "this identity is not an author of the channel",
            ));
        }
        let skeleton = self.next_skeleton(&me, payload);
        let entry = Entry::build_signed(signer, skeleton, payload.to_vec())?;
        let hash = entry.entry_hash();
        let wire = entry.to_wire();
        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let key = signer.public_key();
        let gov =
            GovEntry::from_verified_log_entry(&entry, &key, &self.channel_id, self.gov_heads())?;
        self.dag
            .accept(
                entry,
                EntryKind::Governance,
                &key,
                &self.admission,
                now_secs,
            )
            .map_err(|_| Error::Profile("authored entry failed the acceptance predicate"))?;
        if let Err(e) =
            profile
                .store()
                .put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)
        {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        self.gov_entries.push(gov);
        self.evaluator =
            Self::build_evaluator(&self.genesis, &self.authors, &self.gov_entries, now_secs)?;
        Ok(hash)
    }

    /// The governance entries a newly authored governance entry happens-after: the
    /// hashes accepted so far (ADR-007's causal relation is only ever *followed*,
    /// never trusted for authority).
    fn gov_heads(&self) -> std::collections::BTreeSet<Digest32> {
        self.gov_entries.iter().map(|g| g.entry_hash).collect()
    }

    /// Accept an entry authored by **another** member (M14.5; the bytes arrive from
    /// the join stream now and from ADR-008 sync in M14.6).
    ///
    /// The author must already be admitted ([`ChannelState::admit_author`]), the
    /// entry must pass the ADR-008 acceptance predicate under that author's key, and
    /// its payload decides its kind. A content entry is stored but **not rendered**:
    /// rendering needs that author's sender key, which only arrives with its SKDM,
    /// and this node's consent view (ADR-007 — the newcomer sees ciphertext until a
    /// member consents).
    pub fn accept_entry(
        &mut self,
        profile: &Profile,
        entry: Entry,
        now_secs: u64,
    ) -> Result<Accepted> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        if entry.skeleton.channel_id != self.channel_id {
            return Err(Error::MalformedGovernance("entry binds another channel"));
        }
        if entry.skeleton.epoch != self.epoch {
            return Err(Error::MalformedGovernance("entry binds another epoch"));
        }
        let author = entry.skeleton.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::MalformedGovernance(
                "entry from an unadmitted author",
            ))?
            .clone();
        let payload = entry
            .payload
            .as_deref()
            .ok_or(Error::MalformedGovernance("entry payload pruned"))?;
        let kind = classify_payload(payload)?;
        let gov = if kind == EntryKind::Governance {
            Some(GovEntry::from_verified_log_entry(
                &entry,
                &key,
                &self.channel_id,
                self.gov_heads(),
            )?)
        } else {
            None
        };
        let wire = entry.to_wire();
        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        self.dag
            .accept(entry, kind, &key, &self.admission, now_secs)
            .map_err(|_| Error::MalformedGovernance("entry failed the acceptance predicate"))?;
        if let Err(e) =
            profile
                .store()
                .put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)
        {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        match gov {
            Some(g) => {
                self.gov_entries.push(g);
                self.evaluator = Self::build_evaluator(
                    &self.genesis,
                    &self.authors,
                    &self.gov_entries,
                    now_secs,
                )?;
                Ok(Accepted::Governance)
            }
            // Stored as ciphertext: no sender key for this author yet, so there is
            // nothing to render (ADR-007 step 3).
            None => Ok(Accepted::ContentNotReadable),
        }
    }

    /// Whether this node may read `author`'s messages: `author` has consented to
    /// this identity on the log (ADR-007 per-sender consent). Reading also needs the
    /// sender key itself (the SKDM).
    #[must_use]
    pub fn may_read(&self, author: &Digest32, me: &Digest32) -> bool {
        MembershipView::new(&self.evaluator).can_read(me, author)
    }

    /// Author a text message: encrypt under this identity's sender chain, wrap in
    /// a signed ADR-008 log entry, accept it into the DAG, and persist entry +
    /// rendering + advanced chain state atomically. Returns the rendered message.
    pub fn append_text(
        &mut self,
        profile: &Profile,
        text: &str,
        now_secs: u64,
    ) -> Result<&Rendered> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile(
                "this identity is not an author of the channel",
            ));
        }
        let content = Content::text(now_secs, text)?;
        let plaintext = Zeroizing::new(content.to_canonical_vec());
        let msg = self.sender.encrypt(&plaintext)?;
        let payload = msg.to_wire();

        let skeleton = self.next_skeleton(&me, &payload);
        let entry = Entry::build_signed(signer, skeleton, payload)?;
        let entry_hash = entry.entry_hash();
        let wire = entry.to_wire();
        let rendered = Rendered {
            entry_hash,
            author: me,
            created_secs: now_secs,
            text: content.text,
        };

        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let cache_seg = seal_segment(
            &self.sek,
            SegmentKind::PlaintextCache,
            id,
            &cache_bytes(&rendered),
        )?;
        let sender_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &self.sender.to_state(),
        )?;

        // Validate against the DAG first (structural), then persist, then commit
        // to memory. A persist failure poisons the channel (see module docs).
        let key = signer.public_key();
        self.dag
            .accept(entry, EntryKind::Content, &key, &self.admission, now_secs)
            .map_err(|_| Error::Profile("authored entry failed the acceptance predicate"))?;
        let persisted = (|| -> Result<()> {
            let mut batch = profile.store().batch()?;
            batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::PlaintextCache,
                id,
                &cache_seg,
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_SENDER,
                &sender_seg,
            )?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        self.timeline.push(rendered);
        self.timeline
            .last()
            .ok_or(Error::Profile("timeline empty after push"))
    }

    /// The next entry skeleton for `author`'s feed in this DAG.
    fn next_skeleton(&self, author: &Digest32, payload: &[u8]) -> EntrySkeleton {
        let feed = self.dag.feed(author);
        let max = feed.map_or(0, |f| f.max_seq());
        let seq = max + 1;
        let hash_of = |s: u64| -> Digest32 {
            feed.and_then(|f| f.get(s))
                .map_or(ZERO_HASH, |e| e.entry_hash())
        };
        let prev_hash = if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(seq - 1)
        };
        let lipmaa_backlink = if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(lipmaa(seq))
        };
        EntrySkeleton {
            author_id: *author,
            seq,
            prev_hash,
            lipmaa_backlink,
            channel_id: self.channel_id,
            epoch: self.epoch,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        }
    }

    /// The channelID.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The local (device-only) channel name.
    #[must_use]
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Creation time recorded in the manifest.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.created
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The genesis record.
    #[must_use]
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// The render-gated timeline, oldest first.
    #[must_use]
    pub fn timeline(&self) -> &[Rendered] {
        &self.timeline
    }

    /// Known authors (M13: the creator), in fingerprint order.
    #[must_use]
    pub fn members(&self) -> Vec<Digest32> {
        self.authors.keys().copied().collect()
    }

    /// Number of accepted log entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.dag.len()
    }

    /// The governance evaluator over this channel's log.
    #[must_use]
    pub fn evaluator(&self) -> &Evaluator {
        &self.evaluator
    }

    /// Whether a failed persist has poisoned this channel (reopen to continue).
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whether this channel's SEK is `mlock`ed (ADR-010 best-effort; surfaced to
    /// the UI as the memory-protection honesty flag).
    #[must_use]
    pub fn mlock_active(&self) -> bool {
        self.sek.is_mlocked()
    }

    /// App-lock this channel: wipe the SEK now. The state should be dropped
    /// afterwards; any further seal/open fails with [`Error::AtRestLocked`].
    pub fn lock_now(&mut self) {
        self.sek.lock_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::paths::Paths;

    fn profile(tmp: &tempfile::TempDir, name: &str) -> Profile {
        let p = Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        Profile::create_with_profile(p, b"identity-pp", 1_700_000_000, Argon2Profile::REDUCED)
            .unwrap()
    }

    #[test]
    fn create_append_render_and_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch = ChannelState::create_with_profile(
            &prof,
            "family",
            b"channel-pp",
            1_700_000_100,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        let cid = ch.channel_id();
        assert_eq!(ch.local_name(), "family");
        assert_eq!(ch.epoch(), 0);
        assert_eq!(ch.members(), vec![prof.fingerprint()]);
        assert!(ch.evaluator().is_admin(&prof.fingerprint()));
        assert!(ch.timeline().is_empty());

        let r1 = ch
            .append_text(&prof, "hello", 1_700_000_200)
            .unwrap()
            .clone();
        let r2 = ch
            .append_text(&prof, "world", 1_700_000_300)
            .unwrap()
            .clone();
        assert_eq!(ch.entry_count(), 2);
        assert_eq!(ch.timeline().len(), 2);
        assert_eq!(r1.text, "hello");
        assert_eq!(r2.text, "world");
        assert_eq!(r1.author, prof.fingerprint());
        assert_ne!(r1.entry_hash, r2.entry_hash);
        drop(ch);

        // Reopen from the store with the right channel passphrase.
        let ch = ChannelState::open(&prof, &cid, b"channel-pp", 1_700_000_400).unwrap();
        assert_eq!(ch.local_name(), "family");
        assert_eq!(ch.entry_count(), 2);
        assert_eq!(ch.timeline(), &[r1.clone(), r2.clone()]);
        // The restored sender chain continues where it left off (iteration 2).
        let mut ch = ch;
        let r3 = ch
            .append_text(&prof, "again", 1_700_000_500)
            .unwrap()
            .clone();
        assert_eq!(ch.entry_count(), 3);
        drop(ch);
        let ch = ChannelState::open(&prof, &cid, b"channel-pp", 1_700_000_600).unwrap();
        assert_eq!(ch.timeline(), &[r1, r2, r3]);
        assert_eq!(ch.entry_count(), 3);
    }

    #[test]
    fn double_lock_needs_both_factors() {
        let tmp = tempfile::tempdir().unwrap();
        let mut prof = profile(&tmp, "alice");
        let ch =
            ChannelState::create_with_profile(&prof, "c", b"channel-pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let cid = ch.channel_id();
        drop(ch);
        // Wrong channel passphrase.
        assert!(matches!(
            ChannelState::open(&prof, &cid, b"wrong", 2),
            Err(Error::AtRestUnlockFailed)
        ));
        // Locked identity: no identity factor, no SEK.
        prof.lock();
        assert!(matches!(
            ChannelState::open(&prof, &cid, b"channel-pp", 2),
            Err(Error::Profile("locked"))
        ));
        prof.unlock(b"identity-pp").unwrap();
        // Another identity with the right channel passphrase: wrong identity factor.
        let other = profile(&tmp, "mallory");
        // Copy the wrap into mallory's store to simulate file theft.
        let wrap = prof.store().get_sek_wrap(&cid).unwrap().unwrap();
        other.store().put_sek_wrap(&cid, &wrap).unwrap();
        for (id, seg) in prof
            .store()
            .segments(&cid, SegmentKind::KeyMaterial)
            .unwrap()
        {
            other
                .store()
                .put_segment(&cid, SegmentKind::KeyMaterial, id, &seg)
                .unwrap();
        }
        assert!(matches!(
            ChannelState::open(&other, &cid, b"channel-pp", 2),
            Err(Error::AtRestUnlockFailed)
        ));
        // Unknown channel.
        assert!(matches!(
            ChannelState::open(&prof, &[0u8; 32], b"channel-pp", 2),
            Err(Error::Profile("no such channel in this profile"))
        ));
    }

    #[test]
    fn stored_entries_are_re_verified_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let cid = ch.channel_id();
        ch.append_text(&prof, "one", 2).unwrap();
        ch.append_text(&prof, "two", 3).unwrap();
        // Corrupt entry 2's sealed segment: the SEK open fails, so the open fails
        // (never silently drops or trusts a bad entry).
        let (id, mut seg) = prof
            .store()
            .segments(&cid, SegmentKind::LogDb)
            .unwrap()
            .pop()
            .unwrap();
        let last = seg.ciphertext.len() - 1;
        seg.ciphertext[last] ^= 1;
        prof.store()
            .put_segment(&cid, SegmentKind::LogDb, id, &seg)
            .unwrap();
        drop(ch);
        assert!(matches!(
            ChannelState::open(&prof, &cid, b"pp", 4),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn cache_rows_without_a_dag_entry_are_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let cid = ch.channel_id();
        ch.append_text(&prof, "one", 2).unwrap();
        // Delete the log entry but keep the cache row: the row must not render.
        assert!(prof
            .store()
            .delete_segment(&cid, SegmentKind::LogDb, 1)
            .unwrap());
        drop(ch);
        let ch = ChannelState::open(&prof, &cid, b"pp", 3).unwrap();
        assert_eq!(ch.entry_count(), 0);
        assert!(ch.timeline().is_empty());
    }

    #[test]
    fn local_name_and_text_are_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let long = "n".repeat(MAX_LOCAL_NAME_LEN + 1);
        assert!(matches!(
            ChannelState::create_with_profile(&prof, &long, b"pp", 1, Argon2Profile::REDUCED),
            Err(Error::SizeLimitExceeded(_))
        ));
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        let big = "x".repeat(crate::node::content::MAX_TEXT_LEN + 1);
        assert!(matches!(
            ch.append_text(&prof, &big, 2),
            Err(Error::SizeLimitExceeded(_))
        ));
        assert_eq!(
            ch.entry_count(),
            0,
            "a rejected message must not advance anything"
        );
    }

    #[test]
    fn locked_channel_refuses_to_seal() {
        let tmp = tempfile::tempdir().unwrap();
        let prof = profile(&tmp, "alice");
        let mut ch =
            ChannelState::create_with_profile(&prof, "c", b"pp", 1, Argon2Profile::REDUCED)
                .unwrap();
        ch.lock_now();
        assert!(matches!(
            ch.append_text(&prof, "after lock", 2),
            Err(Error::AtRestLocked)
        ));
    }
    /// Both halves of ADR-007's join flow that do not need SKDM delivery (M14.5a):
    /// a joiner builds local state from the board's genesis, each side admits the
    /// other as a log author, a message crosses and is **stored but unreadable**,
    /// and a consent grant becomes a governance fact both sides evaluate.
    #[test]
    fn a_joiner_admits_authors_stores_unreadable_content_and_records_consent() {
        let tmp = tempfile::tempdir().unwrap();
        let alice = profile(&tmp, "alice");
        let bob = profile(&tmp, "bob");
        let t = 1_700_000_000;

        let mut a = ChannelState::create_with_profile(
            &alice,
            "team",
            b"channel-pp",
            t,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        let cid = a.channel_id();
        let a_fp = RootSigner::public_key(alice.signer().unwrap()).fingerprint();
        let b_fp = RootSigner::public_key(bob.signer().unwrap()).fingerprint();

        // Bob joins with the genesis he fetched from the board. A genesis whose hash
        // is not the channelID he joined with is refused (ADR-007).
        assert!(matches!(
            ChannelState::join_channel_with_profile(
                &bob,
                a.genesis(),
                &[0xAB; 32],
                "team",
                b"channel-pp",
                t,
                Argon2Profile::REDUCED,
            ),
            Err(Error::MalformedGovernance(
                "genesis hash is not the channelID joined with"
            ))
        ));
        let mut b = ChannelState::join_channel_with_profile(
            &bob,
            a.genesis(),
            &cid,
            "team",
            b"channel-pp",
            t,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        // Joining admits the creator (from the verified genesis) and himself — and
        // releases no sender keys.
        assert!(b.is_author(&a_fp) && b.is_author(&b_fp));
        assert_eq!(b.timeline().len(), 0);
        // The same channel cannot be joined twice into one profile.
        assert!(ChannelState::join_channel_with_profile(
            &bob,
            a.genesis(),
            &cid,
            "team",
            b"channel-pp",
            t,
            Argon2Profile::REDUCED,
        )
        .is_err());

        // Alice has not yet admitted Bob: his entries are refused.
        let bob_key = RootSigner::public_key(bob.signer().unwrap());
        let alice_key = RootSigner::public_key(alice.signer().unwrap());
        assert!(!a.is_author(&b_fp));
        assert!(a.admit_author(&alice, &bob_key, t).unwrap());
        assert!(
            !a.admit_author(&alice, &bob_key, t).unwrap(),
            "admission is idempotent"
        );
        assert!(a.is_author(&b_fp));

        // Alice authors a message; the entry bytes reach Bob (sync is M14.6).
        let rendered = a.append_text(&alice, "hello team", t).unwrap().clone();
        let wire = {
            let entry = a.dag.get_by_hash(&rendered.entry_hash).unwrap();
            entry.to_wire()
        };
        let entry = Entry::from_wire(&wire).unwrap();
        // Bob stores it, cannot read it, and it does not appear in his timeline —
        // credentials released no keys (ADR-007 step 1).
        assert_eq!(
            b.accept_entry(&bob, entry, t).unwrap(),
            Accepted::ContentNotReadable
        );
        assert_eq!(b.entry_count(), 1);
        assert!(b.timeline().is_empty());
        assert!(!b.may_read(&a_fp, &b_fp), "no consent yet");

        // Alice consents to Bob: a real SKDM for her current position, then the
        // grant on the log.
        let (iteration, key) = a.sender.current_position();
        let skdm = a
            .sender
            .skdm_for(alice.signer().unwrap(), iteration, key)
            .unwrap();
        let grant = a.issue_consent(&alice, b_fp, &skdm, t).unwrap();
        assert_eq!(grant.body.target_id, b_fp);
        assert!(
            a.may_read(&a_fp, &b_fp),
            "Alice's own view now has the grant"
        );

        // The grant crosses as a governance entry; Bob evaluates it and now knows
        // Alice consented to him (he still needs the SKDM to actually read).
        let grant_entry = {
            let hash = a
                .gov_entries
                .last()
                .expect("the grant was appended")
                .entry_hash;
            Entry::from_wire(&a.dag.get_by_hash(&hash).unwrap().to_wire()).unwrap()
        };
        assert_eq!(
            b.accept_entry(&bob, grant_entry, t).unwrap(),
            Accepted::Governance
        );
        assert!(b.may_read(&a_fp, &b_fp), "consent is on Bob's log too");
        assert!(
            !b.may_read(&b_fp, &a_fp),
            "consent is per-sender, not mutual"
        );

        // A payload that is neither a group message nor a governance struct is
        // refused rather than optimistically accepted as content.
        assert!(classify_payload(b"not a vox payload").is_err());
        assert_eq!(
            classify_payload(&grant.to_wire()).unwrap(),
            EntryKind::Governance
        );

        // Everything survives a reopen: admitted authors, the stored ciphertext
        // entry, and the consent grant's effect.
        drop(b);
        let b = ChannelState::open(&bob, &cid, b"channel-pp", t).unwrap();
        assert!(b.is_author(&a_fp) && b.is_author(&b_fp));
        assert_eq!(b.entry_count(), 2);
        assert!(b.timeline().is_empty());
        assert!(b.may_read(&a_fp, &b_fp), "consent survived the reopen");
        assert_eq!(a.author_keys().len(), 2);
        assert_eq!(alice_key.fingerprint(), a_fp);
    }
}
