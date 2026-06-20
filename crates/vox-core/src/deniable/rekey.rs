//! Mid-epoch membership change — the incremental DSKE re-key (ADR-009
//! §"Mid-epoch membership change").
//!
//! A member who joins (and is newly consented to, ADR-007) **between**
//! passphrase-epochs must not reuse the prior epoch's (now-published, forgeable)
//! keys. The re-key is triggered by the consent-grant log entry naming the
//! newcomer. Each consenting member generates a **fresh** ephemeral signing
//! keypair `(esk', epk')`, then re-runs the DSKE bind + confirm (rounds 3–4)
//! against an **updated transcript `T'`** that includes the newcomer's `epk_new`,
//! and distributes the result to the newcomer. One incremental bind+confirm round
//! per join (the forward-secrecy window for the new verifiers is one re-key
//! interval).
//!
//! This module models the re-key as: build the new [`EpochContext`] (the prior
//! members with their **fresh** `epk'` + share', plus the newcomer), then have
//! each member produce a [`ReKey`] (its fresh `epk'`, its BD round-2 value, and its
//! DSKE bind over `T'`). The newcomer (and every member) verifies each `ReKey`'s
//! bind against `T'` and registers the fresh `epk'` for content verification. The
//! group key `K'` is re-derived over the new DH set (the join changes the ring).
//!
//! The re-key reuses the same primitives as the full DGKA ([`crate::deniable::dgka`]):
//! it is a one-shot bind+confirm over `T'`, not a fresh 4-round run, because the
//! prior members already trust each other — only the newcomer must be bound in and
//! the forgeable old keys retired.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::CompositeSignature;

use crate::deniable::dgka::DgkaMember;
use crate::deniable::epoch::{EphemeralSigningKey, EpochContext, MemberDescriptor, MemberEpk};
use crate::deniable::key::{EpochKey, CONFIRM_LEN};
use crate::deniable::rounds::{Confirm, NONCE_LEN};
use crate::deniable::share::{EphemeralShare, SHARE_LEN};

/// One member's contribution to an incremental re-key: its fresh ephemeral
/// verification key `epk'`, fresh DH share `z'`, its BD round-2 value `X'_i`, and
/// its DSKE bind signature over the updated transcript `T'`.
#[derive(Clone)]
pub struct ReKey {
    /// The member's static identity fingerprint.
    pub author_id: Digest32,
    /// The member's fresh ephemeral verification key `epk'`.
    pub epk: crate::identity::composite::CompositePublicKey,
    /// The member's fresh DH share `z'`.
    pub share: [u8; SHARE_LEN],
    /// The BD round-2 value `X'_i` over the new ring.
    pub round2: [u8; SHARE_LEN],
    /// The DSKE bind: composite signature by `esk'` over `T'`.
    pub bind_sig: CompositeSignature,
    /// The key-confirmation MAC over `T'` under the re-derived `K'`.
    pub confirm_mac: [u8; CONFIRM_LEN],
}

impl core::fmt::Debug for ReKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReKey")
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .finish_non_exhaustive()
    }
}

/// A member's freshly-generated re-key material, held until the re-key completes.
/// Produced by [`begin_rekey`]; its [`fresh_signing_key`](Self::fresh_signing_key)
/// is the new content-signing key for the re-keyed window.
pub struct ReKeyParticipant {
    member: DgkaMember,
}

impl ReKeyParticipant {
    /// This participant's fresh ephemeral verification key `epk'`.
    #[must_use]
    pub fn epk(&self) -> crate::identity::composite::CompositePublicKey {
        self.member.epk()
    }

    /// This participant's fresh DH share `z'`.
    #[must_use]
    pub fn share(&self) -> [u8; SHARE_LEN] {
        self.member.share()
    }

    /// This participant's static identity fingerprint.
    #[must_use]
    pub fn author_id(&self) -> Digest32 {
        self.member.author_id()
    }

    /// The fresh ephemeral signing key for the re-keyed window (content authored
    /// after this re-key is signed with this key).
    #[must_use]
    pub fn fresh_signing_key(&self) -> &EphemeralSigningKey {
        self.member.signing_key()
    }

    /// The descriptor for this participant in the new epoch context.
    #[must_use]
    pub fn descriptor(&self) -> MemberDescriptor {
        MemberDescriptor {
            author_pubkey: self.member.author_pubkey(),
            author_id: self.member.author_id(),
            epk: self.member.epk(),
            share: self.member.share(),
        }
    }

    /// This participant's BD round-2 value `X'_i` over the new ring `ctx`. Gathered
    /// by the driver (round 3) before any member derives `K'` (round 4).
    pub fn round2(&self, ctx: &EpochContext) -> Result<[u8; SHARE_LEN]> {
        self.member.own_round2(ctx)
    }
}

/// Begin an incremental re-key for `static_signer`'s identity in
/// `(channel_id, epoch)`: generate the fresh `(esk', x')`. The caller collects
/// every participant's [`ReKeyParticipant::descriptor`] (plus the newcomer's),
/// builds the new [`EpochContext`] with [`rekey_context`], and then each
/// participant calls [`finalize_rekey`]. `static_signer` is the member's static
/// identity — it signs the fresh `dgka-setup` reveal body (binding `epk'`/`z'`).
pub fn begin_rekey(
    channel_id: Digest32,
    epoch: u64,
    static_signer: &dyn crate::identity::composite::RootSigner,
) -> Result<ReKeyParticipant> {
    Ok(ReKeyParticipant {
        member: DgkaMember::from_parts(
            channel_id,
            epoch,
            static_signer,
            EphemeralSigningKey::generate()?,
            EphemeralShare::generate()?,
            [0u8; NONCE_LEN], // re-key has no commit round; nonce unused
        )?,
    })
}

/// Build the updated epoch context `T'` from the (re-keyed) prior members plus the
/// newcomer. All descriptors carry fresh `epk'`/`z'`; the newcomer is just another
/// member. The context canonicalizes order, so `T'` is identical for everyone.
pub fn rekey_context(
    channel_id: Digest32,
    epoch: u64,
    members: Vec<MemberDescriptor>,
) -> Result<EpochContext> {
    EpochContext::new(channel_id, epoch, members)
}

/// Finalize one participant's re-key against the new context `ctx` (`T'`): derive
/// `K'`, broadcast `X'_i`, sign `T'` (DSKE bind), and MAC `T'` (confirm). `round2`
/// maps each member's `author_id` to its broadcast `X'_j`. Returns the [`ReKey`]
/// for distribution and the re-derived [`EpochKey`] (`K'`) for verifying peers.
pub fn finalize_rekey(
    participant: &ReKeyParticipant,
    ctx: &EpochContext,
    round2: &BTreeMap<Digest32, [u8; SHARE_LEN]>,
) -> Result<(ReKey, EpochKey)> {
    let (confirm, key): (Confirm, EpochKey) = participant.member.finalize(ctx, round2)?;
    Ok((
        ReKey {
            author_id: confirm.author_id,
            epk: participant.member.epk(),
            share: participant.member.share(),
            round2: confirm.round2,
            bind_sig: confirm.bind_sig,
            confirm_mac: confirm.confirm_mac,
        },
        key,
    ))
}

/// Verify a peer's [`ReKey`] against the new bind transcript `T'_bind = SHA-256(T'
/// ‖ X'_*)`: the peer's broadcast `X'` matches the `round2` vector, the DSKE bind
/// signature over `T'_bind` verifies against the peer's fresh `epk'`, and the
/// confirmation MAC over `T'_bind` matches `our_key` = `K'`. On success, returns
/// the peer's fresh [`MemberEpk`] to register in the content verifier — this is how
/// the newcomer (and everyone) picks up the fresh verifiers and retires the old,
/// forgeable ones. `round2` is the full canonical `X'_*` map used to derive `K'`.
pub fn verify_rekey(
    ctx: &EpochContext,
    our_key: &EpochKey,
    round2: &BTreeMap<Digest32, [u8; SHARE_LEN]>,
    rekey: &ReKey,
) -> Result<MemberEpk> {
    // The peer's fresh epk must be the one in the new context (T' commits to it).
    let descriptor = ctx
        .members()
        .iter()
        .find(|m| m.author_id == rekey.author_id)
        .ok_or(Error::MalformedBundle("rekey from non-member"))?;
    if descriptor.epk != rekey.epk {
        return Err(Error::MalformedBundle("rekey epk not bound in T'"));
    }
    // The peer's broadcast X' must match the X' used to derive K' (no split view).
    match round2.get(&rekey.author_id) {
        Some(x) if *x == rekey.round2 => {}
        _ => return Err(Error::MalformedBundle("rekey round-2 value mismatch")),
    }
    let t_bind = crate::deniable::dgka::bind_transcript(ctx, round2)?;
    rekey
        .epk
        .verify(&t_bind, &rekey.bind_sig)
        .map_err(|_| Error::SignatureInvalid)?;
    let expect = our_key.confirm_mac_over(ctx, &t_bind)?;
    use subtle::ConstantTimeEq as _;
    if expect.ct_eq(&rekey.confirm_mac).into() {
        Ok(MemberEpk {
            author_id: rekey.author_id,
            epk: rekey.epk.clone(),
        })
    } else {
        Err(Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deniable::verifier::{build_deniable_content, EpochVerifier};
    use crate::hash::sha256;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::log::entry::{DeniableVerifier, EntrySkeleton, ZERO_HASH};
    use crate::suite::algo;

    const CHANNEL: Digest32 = [0xC1; 32];

    /// Run a full incremental re-key among `prior` existing members + 1 newcomer.
    /// Returns the new context, the participants (each with a fresh signing key),
    /// everyone's re-derived `K'`, and the shared `X'` map. Verifies that every
    /// member accepts every other member's [`ReKey`] (bind over `T'_bind` + confirm
    /// under `K'`).
    #[allow(clippy::type_complexity)]
    fn run_rekey(
        prior: usize,
    ) -> (
        EpochContext,
        Vec<ReKeyParticipant>,
        Vec<EpochKey>,
        BTreeMap<Digest32, [u8; SHARE_LEN]>,
    ) {
        let epoch = 9u64;
        let total = prior + 1;
        // Each existing member + the newcomer has a static identity and begins a
        // re-key with fresh ephemeral material.
        let signers: Vec<SoftwareRootSigner> = (0..total)
            .map(|k| {
                SoftwareRootSigner::from_component_seeds(&[k as u8 + 1; 32], &[k as u8 + 50; 32])
                    .unwrap()
            })
            .collect();
        let participants: Vec<ReKeyParticipant> = signers
            .iter()
            .map(|s| begin_rekey(CHANNEL, epoch, s).unwrap())
            .collect();
        // Build T' from all fresh descriptors (canonical ordering applied).
        let descriptors: Vec<MemberDescriptor> = participants
            .iter()
            .map(ReKeyParticipant::descriptor)
            .collect();
        let ctx = rekey_context(CHANNEL, epoch, descriptors).unwrap();

        // Round 3: gather every member's BD round-2 value X'_i over the new ring
        // BEFORE any member derives K' (round 4 needs the full X' vector).
        let mut x_map: BTreeMap<Digest32, [u8; SHARE_LEN]> = BTreeMap::new();
        for p in &participants {
            x_map.insert(p.author_id(), p.round2(&ctx).unwrap());
        }
        // Round 4: finalize everyone with the complete X' map.
        let mut keys = Vec::new();
        let mut rekeys = Vec::new();
        for p in &participants {
            let (rk, key) = finalize_rekey(p, &ctx, &x_map).unwrap();
            rekeys.push(rk);
            keys.push(key);
        }
        // Everyone verifies everyone else's ReKey under their own K' against T'_bind.
        for (idx, p) in participants.iter().enumerate() {
            for rk in &rekeys {
                if rk.author_id == p.author_id() {
                    continue;
                }
                verify_rekey(&ctx, &keys[idx], &x_map, rk).unwrap();
            }
        }
        (ctx, participants, keys, x_map)
    }

    #[test]
    fn rekey_three_plus_newcomer_all_agree() {
        let (ctx, participants, keys, _x) = run_rekey(3);
        // All four members derived the same K'.
        for k in &keys {
            assert!(k.equals(&keys[0]));
        }
        // The newcomer can verify content from a prior member under the fresh epk.
        let author = &participants[0];
        let sk = EntrySkeleton {
            author_id: author.author_id(),
            seq: 1,
            prev_hash: ZERO_HASH,
            lipmaa_backlink: ZERO_HASH,
            channel_id: CHANNEL,
            epoch: ctx.epoch(),
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(b"post-rekey"),
            payload_len: b"post-rekey".len() as u64,
            end_of_feed: false,
        };
        let entry =
            build_deniable_content(author.fresh_signing_key(), sk, b"post-rekey".to_vec()).unwrap();
        let mut newcomer_view = EpochVerifier::new();
        newcomer_view
            .release(
                CHANNEL,
                ctx.epoch(),
                &MemberEpk {
                    author_id: author.author_id(),
                    epk: author.epk(),
                },
            )
            .unwrap();
        assert!(newcomer_view
            .verify_deniable(&entry.skeleton, &entry.authenticator.to_bytes())
            .is_ok());
    }

    #[test]
    fn rekey_rejects_substituted_round2() {
        // [MED] a peer whose broadcast X' differs from the X' used to derive K' is
        // rejected (split-view detection), not silently divergent.
        let (ctx, _participants, keys, x_map) = run_rekey(2);
        // Re-finalize member 0 honestly, then corrupt its broadcast round2.
        let (ctx2, participants, keys2, x2) = run_rekey(2);
        let _ = (ctx, keys);
        let (mut rk, _k) = finalize_rekey(&participants[0], &ctx2, &x2).unwrap();
        rk.round2[0] ^= 0xff;
        // Another member verifies it under its own K' → mismatch.
        assert!(matches!(
            verify_rekey(&ctx2, &keys2[1], &x2, &rk),
            Err(Error::MalformedBundle("rekey round-2 value mismatch"))
        ));
        let _ = x_map;
    }
}
