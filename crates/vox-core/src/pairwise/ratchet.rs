//! The Double Ratchet (ADR-004 §Decision + §Wire): the X25519 DH ratchet plus
//! the symmetric KDF-chain ratchet, with AEAD envelopes, bounded skipped-key
//! handling, and replay rejection.
//!
//! ## KDF constructions (Signal Double Ratchet spec, confirmed)
//! - **Root KDF** (`KDF_RK`): `HKDF-SHA-256` with the current root key as the
//!   salt, the new DH output as the IKM, and a constant info label; the 64-byte
//!   output splits into the next root key (32 B) and a fresh chain key (32 B).
//! - **Chain KDF** (`KDF_CK`): `HMAC-SHA-256` keyed by the chain key — the
//!   message key is `HMAC(CK, 0x01)` and the next chain key is `HMAC(CK, 0x02)`.
//!   A bare-SHA256 chain KDF is explicitly rejected (ADR-004; the spec recommends
//!   the keyed HMAC so only a holder of `CK` can derive the message key).
//!
//! ## Bounded skipped keys & replay (ADR-004 §Wire)
//! Out-of-order messages are handled by deriving and caching skipped message keys
//! up to `MAX_SKIP` per chain, with a total per-session cap and a wall-clock
//! expiry. A gap larger than `MAX_SKIP` is **rejected** (it would force unbounded
//! derivation — a DoS) rather than skipped. A consumed `(ratchet_pubkey, N)` is
//! deleted after use, so a replay cannot re-derive the plaintext, and a replayed
//! header whose key is already gone simply fails to open.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::identity::keyagreement::{X25519IdentityKey, X25519_PUB_LEN};
use crate::pairwise::header::RatchetHeader;
use crate::suite::algo;

type HmacSha256 = Hmac<Sha256>;

/// Default maximum skipped message keys derived in a single chain (ADR-004).
pub const MAX_SKIP: u64 = 1000;
/// Default total skipped-key cache size per session (ADR-004).
pub const MAX_CACHE: usize = 2000;
/// Default skipped-key expiry in seconds (7 days, ADR-004).
pub const SKIP_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

/// HKDF info label for the root KDF (domain-separated, ADR-004).
const ROOT_KDF_INFO: &[u8] = b"vox/ratchet-root/v1";

/// A 32-byte symmetric key that zeroizes on drop (root key, chain key, or
/// message key). Redacting `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Key32([u8; 32]);

impl core::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// Advance the root chain: `(rk, ck) = HKDF-SHA-256(salt=rk, ikm=dh_out, info)`.
fn kdf_rk(rk: &Key32, dh_out: &[u8; 32]) -> Result<(Key32, Key32)> {
    let hk = Hkdf::<Sha256>::new(Some(&rk.0), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(ROOT_KDF_INFO, &mut okm)
        .map_err(|_| Error::MalformedBundle("ratchet root kdf"))?;
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    new_ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((Key32(new_rk), Key32(new_ck)))
}

/// Advance the symmetric chain: returns `(next_ck, message_key)` where
/// `message_key = HMAC(CK, 0x01)` and `next_ck = HMAC(CK, 0x02)`.
fn kdf_ck(ck: &Key32) -> Result<(Key32, Key32)> {
    let mk = hmac_one(&ck.0, 0x01)?;
    let next = hmac_one(&ck.0, 0x02)?;
    Ok((Key32(next), Key32(mk)))
}

/// `HMAC-SHA-256(key=ck, data=[tag])`, returning the 32-byte tag.
fn hmac_one(ck: &[u8; 32], tag: u8) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck)
        .map_err(|_| Error::MalformedBundle("ratchet chain kdf"))?;
    mac.update(&[tag]);
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    Ok(k)
}

/// AEAD-encrypt `plaintext` under `mk` with associated data `ad` (AES-256-GCM).
/// A fresh 96-bit nonce is derived per message key, so it is unique per
/// invocation (each message key is used exactly once).
fn aead_seal(mk: &Key32, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(&mk.0).map_err(|_| Error::MalformedBundle("aead key"))?;
    let nonce = message_nonce(mk);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| Error::MalformedBundle("aead seal"))
}

/// AEAD-decrypt `ciphertext` under `mk` with associated data `ad`. Returns
/// [`Error::SignatureInvalid`] on any authentication failure (wrong key, tampered
/// AD/ciphertext, replay against a deleted key) — never a panic.
fn aead_open(mk: &Key32, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(&mk.0).map_err(|_| Error::MalformedBundle("aead key"))?;
    let nonce = message_nonce(mk);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| Error::SignatureInvalid)
}

/// Derive a deterministic 96-bit AEAD nonce from the (single-use) message key.
/// Because each message key is derived once and deleted after use, a fixed
/// nonce-per-key is safe (the GCM (key, nonce) pair never repeats).
fn message_nonce(mk: &Key32) -> [u8; 12] {
    let tag = hmac_one(&mk.0, 0x03).unwrap_or([0u8; 32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&tag[..12]);
    nonce
}

/// A cached skipped message key, keyed by `(ratchet_pubkey, N)`, with an
/// insertion timestamp for expiry.
struct SkippedKey {
    mk: Key32,
    inserted_at: u64,
}

/// The skipped-message-key store: a bounded, expiring map from
/// `(ratchet_pubkey, N)` to the derived message key (ADR-004 §Wire).
#[derive(Default)]
struct SkippedStore {
    map: HashMap<([u8; X25519_PUB_LEN], u64), SkippedKey>,
}

impl SkippedStore {
    fn insert(&mut self, pubkey: [u8; X25519_PUB_LEN], n: u64, mk: Key32, now: u64) -> Result<()> {
        if self.map.len() >= MAX_CACHE {
            return Err(Error::MalformedBundle("skipped-key cache full"));
        }
        self.map.insert(
            (pubkey, n),
            SkippedKey {
                mk,
                inserted_at: now,
            },
        );
        Ok(())
    }

    /// Borrow a cached key if present **and unexpired**, performing the expiry
    /// check **read-only** (an expired entry is treated as absent but is NOT
    /// removed here). Borrowing — not taking — and not mutating lets the caller
    /// authenticate the packet (AEAD open) BEFORE any state change, so a forgery
    /// or replay at a cached `(pubkey, N)` can neither evict a legitimately-skipped
    /// key nor (via expiry pruning) mutate the store at all (M2-review HIGH fixes).
    /// Actual eviction of expired entries happens in [`prune_expired`](Self::prune_expired),
    /// called only on the post-authentication commit path.
    fn peek(&self, pubkey: &[u8; X25519_PUB_LEN], n: u64, now: u64) -> Option<&Key32> {
        let entry = self.map.get(&(*pubkey, n))?;
        if now.saturating_sub(entry.inserted_at) > SKIP_EXPIRY_SECS {
            return None; // expired: treated as absent, not removed
        }
        Some(&entry.mk)
    }

    /// Remove a cached key after it has been successfully consumed (so replay of
    /// that `(pubkey, N)` can no longer re-derive the plaintext).
    fn remove(&mut self, pubkey: &[u8; X25519_PUB_LEN], n: u64) {
        self.map.remove(&(*pubkey, n));
    }

    /// Number of cached *unexpired* skipped keys at `now` (for the total-cache
    /// bound check). Counts read-only — expired entries are excluded but not
    /// removed, so the plan phase never mutates the store.
    fn live_len(&self, now: u64) -> usize {
        self.map
            .values()
            .filter(|e| now.saturating_sub(e.inserted_at) <= SKIP_EXPIRY_SECS)
            .count()
    }

    /// Total number of physically-stored entries (including not-yet-pruned
    /// expired ones). Used by tests to prove the read-only expiry path does not
    /// evict.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }

    /// Drop every expired entry. Called only on the committed (post-AEAD-success)
    /// path, so an unauthenticated packet can never trigger this mutation.
    fn prune_expired(&mut self, now: u64) {
        self.map
            .retain(|_, e| now.saturating_sub(e.inserted_at) <= SKIP_EXPIRY_SECS);
    }
}

/// One end of a Double Ratchet session's symmetric+DH state.
///
/// Holds the root key, the sending/receiving chain keys and counters, the local
/// DH ratchet keypair and the remote ratchet public key, and the bounded
/// skipped-key store. Created by [`Ratchet::init_initiator`] /
/// [`Ratchet::init_responder`] from the PQXDH `SK`.
pub struct Ratchet {
    root: Key32,
    /// Local DH ratchet keypair (secret + cached public).
    dh_self_secret: [u8; 32],
    dh_self_public: [u8; X25519_PUB_LEN],
    /// Remote ratchet public key (None until the first inbound message for the
    /// initiator; always set for the responder).
    dh_remote: Option<[u8; X25519_PUB_LEN]>,
    send_chain: Option<Key32>,
    recv_chain: Option<Key32>,
    /// Message number in the current sending chain.
    n_send: u64,
    /// Message number in the current receiving chain.
    n_recv: u64,
    /// Length of the previous sending chain (for the header `PN`).
    pn: u64,
    skipped: SkippedStore,
    aead_algo: u16,
}

impl Zeroize for Ratchet {
    fn zeroize(&mut self) {
        self.root.zeroize();
        self.dh_self_secret.zeroize();
        if let Some(c) = self.send_chain.as_mut() {
            c.zeroize();
        }
        if let Some(c) = self.recv_chain.as_mut() {
            c.zeroize();
        }
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Ratchet {
    /// The local ratchet public key (for the message header).
    #[must_use]
    pub fn self_public(&self) -> [u8; X25519_PUB_LEN] {
        self.dh_self_public
    }

    /// Initialise the **initiator** side from the PQXDH `SK`.
    ///
    /// Per the Double Ratchet spec, the initiator (Alice) seeds the root key with
    /// `SK`, sets the remote ratchet key to the responder's signed-prekey X25519
    /// public, and performs the first DH ratchet step immediately so it has a
    /// sending chain for message 0.
    pub fn init_initiator(
        sk: &[u8; 32],
        remote_ratchet_pub: [u8; X25519_PUB_LEN],
        aead_algo: u16,
    ) -> Result<Self> {
        let dh_self = X25519IdentityKey::generate()?;
        let dh_self_secret = dh_self.secret_bytes();
        let dh_self_public = dh_self.public_bytes();

        let dh_out = Zeroizing::new(dh(&dh_self_secret, &remote_ratchet_pub));
        let (root, send_ck) = kdf_rk(&Key32(*sk), &dh_out)?;

        Ok(Self {
            root,
            dh_self_secret,
            dh_self_public,
            dh_remote: Some(remote_ratchet_pub),
            send_chain: Some(send_ck),
            recv_chain: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: SkippedStore::default(),
            aead_algo,
        })
    }

    /// Initialise the **responder** side from the PQXDH `SK`.
    ///
    /// The responder (Bob) seeds the root key with `SK` and installs the
    /// signed-prekey X25519 keypair as its initial DH ratchet keypair (the key the
    /// initiator already ratcheted against), with no chains yet — they are
    /// established when the first inbound message triggers a DH ratchet step.
    pub fn init_responder(
        sk: &[u8; 32],
        signed_prekey_secret: [u8; 32],
        signed_prekey_public: [u8; X25519_PUB_LEN],
        aead_algo: u16,
    ) -> Self {
        Self {
            root: Key32(*sk),
            dh_self_secret: signed_prekey_secret,
            dh_self_public: signed_prekey_public,
            dh_remote: None,
            send_chain: None,
            recv_chain: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: SkippedStore::default(),
            aead_algo,
        }
    }

    /// Produce the header + message key for the next outbound message, advancing
    /// the sending chain by one.
    ///
    /// `pub(crate)`: only [`crate::pairwise::session::Session`] may drive the
    /// ratchet, so the one-message-key-per-AEAD-nonce invariant (each derived
    /// message key is sealed exactly once) cannot be violated by external callers.
    pub(crate) fn next_send(&mut self) -> Result<(RatchetHeader, Key32Sealed)> {
        let ck = self
            .send_chain
            .as_ref()
            .ok_or(Error::MalformedBundle("no sending chain"))?;
        let (next_ck, mk) = kdf_ck(ck)?;
        let header = RatchetHeader {
            ratchet_pubkey: self.dh_self_public,
            pn: self.pn,
            n: self.n_send,
            curve_algo: algo::X25519,
            aead_algo: self.aead_algo,
        };
        self.send_chain = Some(next_ck);
        self.n_send += 1;
        Ok((header, Key32Sealed(mk)))
    }

    /// Seal `plaintext` under a message key obtained from
    /// [`next_send`](Ratchet::next_send).
    ///
    /// Consumes `mk` **by value** so a single derived message key can be sealed at
    /// most once — the deterministic per-key AEAD nonce is then provably never
    /// reused. `pub(crate)` for the same reason as [`next_send`](Ratchet::next_send).
    pub(crate) fn seal(mk: Key32Sealed, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        aead_seal(&mk.0, ad, plaintext)
    }

    /// Decrypt an inbound message described by `header` whose associated data is
    /// `ad`. Handles DH ratchet steps, bounded skipped-key derivation, and replay
    /// rejection, then opens the AEAD.
    ///
    /// **Transactional (ADR-004; the M2-review HIGH fix).** An unauthenticated
    /// packet must not be able to mutate ratchet/session state. This method
    /// computes every candidate mutation — DH-ratchet step, skipped-key
    /// derivations, chain advance, counter and `(pubkey, N)` consumption — into
    /// *temporary* values, derives the message key, and attempts the AEAD open
    /// FIRST. Only on a successful open are the mutations committed (chains/roots
    /// advanced, skipped keys inserted, the consumed key deleted). On any failure
    /// nothing is committed and `self` is left exactly as it was, so a forged or
    /// replayed packet can neither poison state nor brick the session.
    ///
    /// `pub(crate)`: only [`crate::pairwise::session::Session`] drives the ratchet.
    pub(crate) fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ad: &[u8],
        ciphertext: &[u8],
        now: u64,
    ) -> Result<Vec<u8>> {
        // No pre-authentication mutation whatsoever: NOTHING below the AEAD open
        // (including expiry pruning) touches `self`. Expiry is checked read-only
        // via `peek`/`live_len`; the actual eviction (`prune_expired`) runs only
        // in the committed path. So a forged/replayed packet leaves `self`
        // byte-for-byte unchanged (M2-review residual HIGH fix).

        // Path 1: replay/out-of-order against a cached, unexpired skipped key.
        // Open BEFORE removing it, so a forged packet at a cached (pubkey, N) can
        // neither evict a legitimately-skipped key nor mutate the store.
        if let Some(mk) = self.skipped.peek(&header.ratchet_pubkey, header.n, now) {
            let plaintext = aead_open(mk, ad, ciphertext)?;
            // Authenticated: consume the key and run expiry housekeeping.
            self.skipped.remove(&header.ratchet_pubkey, header.n);
            self.skipped.prune_expired(now);
            return Ok(plaintext);
        }

        // Paths 2/3: build a candidate transition without touching `self`.
        let plan = self.plan_decrypt(header, now)?;
        // Derive the message key + attempt AEAD open against the CANDIDATE state.
        let plaintext = aead_open(&plan.message_key, ad, ciphertext)?;
        // Authenticated: commit every mutation atomically (incl. expiry pruning).
        self.commit(plan, now)?;
        Ok(plaintext)
    }

    /// Compute the candidate state transition for an inbound `header` whose key is
    /// not already cached, WITHOUT mutating `self`. Rejects a gap > [`MAX_SKIP`]
    /// up front (DoS guard) before doing any derivation.
    fn plan_decrypt(&self, header: &RatchetHeader, now: u64) -> Result<DecryptPlan> {
        let mut skips: Vec<([u8; X25519_PUB_LEN], u64, Key32)> = Vec::new();

        if self.dh_remote == Some(header.ratchet_pubkey) {
            // Path 3: same remote ratchet key — advance the current receiving
            // chain. Requires an established receiving chain.
            let ck0 = self
                .recv_chain
                .as_ref()
                .ok_or(Error::MalformedBundle("no receiving chain"))?;
            let remote = header.ratchet_pubkey;
            let (recv_chain, n_recv, message_key) = plan_chain_advance(
                ck0,
                self.n_recv,
                header.n,
                remote,
                now,
                &mut skips,
                self.skipped.live_len(now),
            )?;
            Ok(DecryptPlan {
                skips,
                root: None,
                recv_chain: Some(recv_chain),
                send: None,
                n_recv,
                message_key,
            })
        } else {
            // Path 2: new remote ratchet key — a DH ratchet step. First drain the
            // OLD receiving chain up to header.pn (caching skipped keys), then
            // derive the new receiving/sending chains, then advance the new
            // receiving chain up to header.n.
            if let Some(old_ck) = self.recv_chain.as_ref() {
                if let Some(remote) = self.dh_remote {
                    let (_drained_ck, _n, ()) = plan_drain(
                        old_ck,
                        self.n_recv,
                        header.pn,
                        remote,
                        now,
                        &mut skips,
                        self.skipped.live_len(now),
                    )?;
                }
            }

            // DH ratchet step (Signal DR §5.1), all into candidate values.
            let dh_recv = Zeroizing::new(dh(&self.dh_self_secret, &header.ratchet_pubkey));
            let (root1, recv_ck) = kdf_rk(&self.root, &dh_recv)?;
            let new_self = X25519IdentityKey::generate()?;
            let new_self_secret = Zeroizing::new(new_self.secret_bytes());
            let new_self_public = new_self.public_bytes();
            let dh_send = Zeroizing::new(dh(&new_self_secret, &header.ratchet_pubkey));
            let (root2, send_ck) = kdf_rk(&root1, &dh_send)?;

            // Advance the NEW receiving chain up to header.n (from n_recv = 0).
            let remote = header.ratchet_pubkey;
            let (recv_chain, n_recv, message_key) = plan_chain_advance(
                &recv_ck,
                0,
                header.n,
                remote,
                now,
                &mut skips,
                self.skipped.live_len(now),
            )?;

            Ok(DecryptPlan {
                skips,
                root: Some(root2),
                recv_chain: Some(recv_chain),
                send: Some(SendCandidate {
                    self_secret: *new_self_secret,
                    self_public: new_self_public,
                    send_chain: send_ck,
                    pn: self.n_send,
                    remote,
                }),
                n_recv,
                message_key,
            })
        }
    }

    /// Apply a committed [`DecryptPlan`] to `self` (only after AEAD success).
    fn commit(&mut self, plan: DecryptPlan, now: u64) -> Result<()> {
        // Expiry housekeeping happens here, on the committed (post-AEAD-success)
        // path only — never from an unauthenticated packet. Pruning first frees
        // the space the plan already budgeted against (`live_len(now)` excluded
        // these expired entries), so the inserts below stay within MAX_CACHE.
        self.skipped.prune_expired(now);
        // Insert skipped keys (the total-cache bound is re-checked here; the plan
        // already accounted for it, so this cannot exceed MAX_CACHE).
        for (pubkey, n, mk) in plan.skips {
            self.skipped.insert(pubkey, n, mk, now)?;
        }
        if let Some(root) = plan.root {
            self.root = root;
        }
        if let Some(recv) = plan.recv_chain {
            self.recv_chain = Some(recv);
        }
        if let Some(send) = plan.send {
            self.dh_self_secret.zeroize();
            self.dh_self_secret = send.self_secret;
            self.dh_self_public = send.self_public;
            self.send_chain = Some(send.send_chain);
            self.dh_remote = Some(send.remote);
            self.pn = send.pn;
            self.n_send = 0;
        }
        self.n_recv = plan.n_recv;
        Ok(())
    }
}

/// The candidate `send`-side state produced by a DH ratchet step (committed only
/// on AEAD success).
struct SendCandidate {
    self_secret: [u8; 32],
    self_public: [u8; X25519_PUB_LEN],
    send_chain: Key32,
    pn: u64,
    remote: [u8; X25519_PUB_LEN],
}

/// A fully-computed inbound decrypt transition, held in temporaries until the
/// AEAD open authenticates the packet (see [`Ratchet::decrypt`]).
struct DecryptPlan {
    /// Skipped message keys to insert on commit: `(remote_pubkey, N, mk)`.
    skips: Vec<([u8; X25519_PUB_LEN], u64, Key32)>,
    /// New root key (only when a DH ratchet step occurred).
    root: Option<Key32>,
    /// New receiving chain key.
    recv_chain: Option<Key32>,
    /// New sending state (only on a DH ratchet step).
    send: Option<SendCandidate>,
    /// The receiving-chain message counter after this message.
    n_recv: u64,
    /// The message key for this packet (used to attempt the AEAD open).
    message_key: Key32,
}

/// Derive skipped keys in a chain from `n_from` up to (not including) `until`,
/// pushing each `(remote, n, mk)` into `skips`; return the advanced chain key and
/// counter. Rejects a gap > [`MAX_SKIP`] and a total cache overflow up front
/// (DoS guards) — pure, mutates nothing but `skips`.
#[allow(clippy::too_many_arguments)]
fn plan_drain(
    ck0: &Key32,
    n_from: u64,
    until: u64,
    remote: [u8; X25519_PUB_LEN],
    _now: u64,
    skips: &mut Vec<([u8; X25519_PUB_LEN], u64, Key32)>,
    cache_len: usize,
) -> Result<(Key32, u64, ())> {
    if until <= n_from {
        return Ok((ck0.clone(), n_from, ()));
    }
    let gap = until - n_from;
    if gap > MAX_SKIP {
        return Err(Error::MalformedBundle("skip gap exceeds MAX_SKIP"));
    }
    if cache_len + skips.len() + (gap as usize) > MAX_CACHE {
        return Err(Error::MalformedBundle("skipped-key cache full"));
    }
    let mut ck = ck0.clone();
    let mut n = n_from;
    while n < until {
        let (next_ck, mk) = kdf_ck(&ck)?;
        skips.push((remote, n, mk));
        ck = next_ck;
        n += 1;
    }
    Ok((ck, n, ()))
}

/// Like [`plan_drain`] but also derives the message key at `target` (the chain is
/// advanced one past the skipped range to produce it). Returns the chain key
/// after `target`, the counter `target + 1`, and the message key at `target`.
#[allow(clippy::too_many_arguments)]
fn plan_chain_advance(
    ck0: &Key32,
    n_from: u64,
    target: u64,
    remote: [u8; X25519_PUB_LEN],
    now: u64,
    skips: &mut Vec<([u8; X25519_PUB_LEN], u64, Key32)>,
    cache_len: usize,
) -> Result<(Key32, u64, Key32)> {
    if target < n_from {
        // The target predates the current chain head and was not cached — it has
        // already been consumed (or never existed): a replay/forgery. Reject.
        return Err(Error::MalformedBundle("message number before chain head"));
    }
    // Drain (cache) the keys strictly before `target`.
    let (ck_at_target, _n, ()) = plan_drain(ck0, n_from, target, remote, now, skips, cache_len)?;
    // Derive the message key at `target` and the chain key after it.
    let (next_ck, mk) = kdf_ck(&ck_at_target)?;
    Ok((next_ck, target + 1, mk))
}

/// A sealed-once message key handed back by [`Ratchet::next_send`]. Opaque to the
/// caller; pass it by value to [`Ratchet::seal`]. Zeroizes on drop.
pub(crate) struct Key32Sealed(Key32);

/// X25519 DH used by the ratchet (same primitive as PQXDH's DH legs).
fn dh(secret: &[u8; 32], public: &[u8; X25519_PUB_LEN]) -> [u8; 32] {
    let s = XSecret::from(*secret);
    let p = XPublic::from(*public);
    s.diffie_hellman(&p).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_ck_is_hmac_keyed_not_bare_hash() {
        let ck = Key32([0x42; 32]);
        let (next, mk) = kdf_ck(&ck).unwrap();
        // The two outputs differ (distinct HMAC constants).
        assert_ne!(next.0, mk.0);
        // The message key equals HMAC(CK, 0x01) — the keyed construction, not
        // SHA-256(CK ‖ 0x01).
        assert_eq!(mk.0, hmac_one(&ck.0, 0x01).unwrap());
        assert_eq!(next.0, hmac_one(&ck.0, 0x02).unwrap());
        // A bare SHA-256(CK ‖ 0x01) would differ.
        let bare = crate::hash::sha256_concat(&[&ck.0, &[0x01]]);
        assert_ne!(mk.0, bare);
    }

    #[test]
    fn kdf_rk_splits_64_bytes_deterministically() {
        let rk = Key32([0x11; 32]);
        let dh_out = [0x22u8; 32];
        let (r1, c1) = kdf_rk(&rk, &dh_out).unwrap();
        let (r2, c2) = kdf_rk(&rk, &dh_out).unwrap();
        assert_eq!(r1.0, r2.0);
        assert_eq!(c1.0, c2.0);
        assert_ne!(r1.0, c1.0);
    }

    #[test]
    fn aead_round_trips_and_detects_tamper() {
        // Use the low-level seal/open (which take &Key32) so the same key can be
        // re-used across assertions; the public `Ratchet::seal` consumes its key
        // by value (one-shot, nonce-reuse-safe) and is exercised end-to-end by
        // the session tests.
        let mk = Key32([0x33; 32]);
        let ad = b"associated";
        let ct = aead_seal(&mk, ad, b"hello").unwrap();
        assert_eq!(aead_open(&mk, ad, &ct).unwrap(), b"hello");
        // Wrong AD fails.
        assert!(matches!(
            aead_open(&mk, b"other", &ct),
            Err(Error::SignatureInvalid)
        ));
        // Tampered ciphertext fails.
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(matches!(
            aead_open(&mk, ad, &bad),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn aead_seal_consumes_key_by_value() {
        // `Ratchet::seal` takes Key32Sealed by value — one-shot use is type-
        // enforced, so the deterministic per-key nonce can never be reused.
        let mk = Key32Sealed(Key32([0x44; 32]));
        let ct = Ratchet::seal(mk, b"ad", b"once").unwrap();
        assert!(!ct.is_empty());
        // `mk` is moved; a second `Ratchet::seal(mk, ...)` would not compile.
    }

    #[test]
    fn skipped_store_peek_remove_and_expiry() {
        let mut s = SkippedStore::default();
        s.insert([1u8; 32], 0, Key32([9; 32]), 100).unwrap();
        // Peek (with `now`) does not remove.
        assert!(s.peek(&[1u8; 32], 0, 100).is_some());
        assert!(s.peek(&[1u8; 32], 0, 100).is_some());
        assert_eq!(s.live_len(100), 1);
        // Remove deletes.
        s.remove(&[1u8; 32], 0);
        assert!(s.peek(&[1u8; 32], 0, 100).is_none());
        // Expiry pruning drops stale entries.
        s.insert([1u8; 32], 1, Key32([9; 32]), 100).unwrap();
        s.prune_expired(100 + SKIP_EXPIRY_SECS + 1);
        assert!(s.peek(&[1u8; 32], 1, 100 + SKIP_EXPIRY_SECS + 1).is_none());
    }

    // Wire a real initiator/responder ratchet pair sharing the same SK; the
    // initiator's remote key is the responder's signed-prekey public.
    fn ratchet_pair() -> (Ratchet, Ratchet) {
        let sk = [0x5a; 32];
        let spk = X25519IdentityKey::generate().unwrap();
        let spk_secret = spk.secret_bytes();
        let spk_public = spk.public_bytes();
        let alice = Ratchet::init_initiator(&sk, spk_public, algo::AES_256_GCM).unwrap();
        let bob = Ratchet::init_responder(&sk, spk_secret, spk_public, algo::AES_256_GCM);
        (alice, bob)
    }

    // Seal an outbound message from `tx` with arbitrary AD (mirrors what Session
    // would do, but at the ratchet level for this unit test).
    fn send(tx: &mut Ratchet, ad: &[u8], pt: &[u8]) -> (RatchetHeader, Vec<u8>) {
        let (header, mk) = tx.next_send().unwrap();
        let ct = Ratchet::seal(mk, ad, pt).unwrap();
        (header, ct)
    }

    #[test]
    fn failed_decrypt_does_not_prune_or_mutate_skipped_store() {
        // M2-review residual HIGH: a FAILED (forged) decrypt while the skipped
        // store holds an expired entry must leave the store byte-for-byte
        // unchanged (expired entry still physically present, nothing pruned). A
        // subsequent SUCCESSFUL decrypt then performs the expiry housekeeping.
        let (mut alice, mut bob) = ratchet_pair();
        let ad = b"ad";

        // Establish Bob's receiving chain with one genuine message at t=100.
        let (h0, c0) = send(&mut alice, ad, b"m0");
        assert_eq!(bob.decrypt(&h0, ad, &c0, 100).unwrap(), b"m0");

        // Inject an expired skipped entry directly into Bob's store (inserted long
        // ago) to model a stale cached key awaiting pruning.
        bob.skipped
            .insert([0x77; 32], 5, Key32([0xAB; 32]), 1)
            .unwrap();
        let now = 1 + SKIP_EXPIRY_SECS + 1_000; // well past expiry
        assert_eq!(bob.skipped.len(), 1);
        assert_eq!(bob.skipped.live_len(now), 0); // already expired (read-only)

        // A forged packet (genuine next header, tampered ciphertext) must FAIL and
        // mutate nothing — the expired entry is still physically present.
        let (h1, c1) = send(&mut alice, ad, b"m1");
        let mut forged = c1.clone();
        forged[0] ^= 0xFF;
        assert!(bob.decrypt(&h1, ad, &forged, now).is_err());
        assert_eq!(bob.skipped.len(), 1, "forged decrypt must not prune");

        // A genuine decrypt now succeeds AND runs the commit-path expiry pruning,
        // evicting the stale entry.
        assert_eq!(bob.decrypt(&h1, ad, &c1, now).unwrap(), b"m1");
        assert_eq!(bob.skipped.len(), 0, "successful decrypt prunes expired");
    }

    #[test]
    fn peek_treats_expired_as_absent_without_removing() {
        // Read-only expiry: an expired entry is reported absent by peek/live_len
        // but is NOT evicted (only prune_expired, on the committed path, evicts).
        let mut s = SkippedStore::default();
        s.insert([1u8; 32], 0, Key32([9; 32]), 100).unwrap();
        let later = 100 + SKIP_EXPIRY_SECS + 1;
        assert!(s.peek(&[1u8; 32], 0, later).is_none()); // treated as absent
        assert_eq!(s.live_len(later), 0); // excluded from the live count
        assert_eq!(s.len(), 1); // ...but still physically present (not removed)
                                // prune_expired (commit path) is what actually evicts it.
        s.prune_expired(later);
        assert_eq!(s.len(), 0);
    }
}
