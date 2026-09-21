//! The `dgka-setup` (`0x000B`) wire codec — ADR-009's setup and re-key rounds as log
//! entries.
//!
//! Until this existed the DGKA rounds could be driven **in-process only**: [`Reveal`],
//! [`Confirm`] and [`ReKey`] were types with no encoding, so deniable mode could not
//! run over an ADR-008 log at all. That was recorded as shipping blocker (2) in
//! ADR-009. This is that codec.
//!
//! ## One tag, four rounds
//! All four bodies share struct tag `0x000B` (`vox/dgka-setup/v1`) and are told apart
//! by a **leading round discriminant**, because they are stages of one protocol run and
//! a verifier reading the log needs to know which stage it is looking at before it can
//! interpret anything else. Each body is fixed-arity canonical CBOR per ADR-008, so a
//! given message has exactly one encoding:
//!
//! | round | body | arity |
//! |---|---|---|
//! | 1 `COMMIT` | `[1, author_id, commit]` | 3 |
//! | 2 `REVEAL` | `[2, author_id, author_pubkey, epk, share, nonce, reveal_sig]` | 7 |
//! | 3 `ROUND2` | `[3, author_id, x]` | 3 |
//! | 4 `CONFIRM` | `[4, author_id, round2, bind_sig, confirm_mac]` | 5 |
//! | 5 `REKEY` | `[5, author_id, epk, share, round2, bind_sig, confirm_mac]` | 7 |
//!
//! ## Why `ROUND2` is its own message
//! It was not, and the omission made the codec undriveable — found by independent review on
//! 2026-09-21, not by these tests. `DgkaMember::finalize` needs the **complete** `X_*` map
//! before it can produce a `Confirm`, so if `Confirm` were the only carrier of `X_i` then no
//! member could confirm until every member had confirmed. A deadlock, invisible to a test that
//! gathers `own_round2()` in process — which is exactly the shortcut this codec exists to
//! remove. `X_i` therefore broadcasts on its own, and `CONFIRM` still carries it so the value a
//! member confirms under is bound to the value it published.
//!
//! ## What this codec does and does not do
//! It moves bytes and rejects malformed ones. It does **not** verify a commitment
//! against its reveal, check a signature, or decide whether a round is in order —
//! those belong to [`crate::deniable::dgka::DgkaMember`], which holds the state a
//! decision needs. Decoding a message therefore proves only that it is well formed:
//! every caller must still hand it to the state machine.
//!
//! The round-2 `reveal_sig` is a **static** composite signature over the `dgka-setup`
//! signing input, not over these frame bytes. That is deliberate and load-bearing: the
//! signature binds `(channel, epoch, author_id, epk, share)`, so re-framing a reveal
//! cannot change what was signed, and a reveal lifted into another channel or epoch
//! does not verify.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature};
use crate::wire::{frame, parse_frame, StructTag};

use crate::deniable::key::CONFIRM_LEN;
use crate::deniable::rekey::ReKey;
use crate::deniable::rounds::{Confirm, Reveal, NONCE_LEN};
use crate::deniable::share::SHARE_LEN;

const ROUND_COMMIT: u64 = 1;
const ROUND_REVEAL: u64 = 2;
const ROUND_X: u64 = 3;
const ROUND_CONFIRM: u64 = 4;
const ROUND_REKEY: u64 = 5;

/// One `dgka-setup` log entry: a single round's broadcast from a single member.
#[derive(Debug, Clone)]
pub enum DgkaMessage {
    /// Round 1: the member's commitment to `(author_pubkey, epk, share, nonce)`,
    /// published before any of it is revealed so no member can choose its share after
    /// seeing another's.
    Commit {
        /// The committing member's static identity fingerprint.
        author_id: Digest32,
        /// [`crate::deniable::rounds::commitment`] over the values revealed next.
        commit: Digest32,
    },
    /// Round 2: the values the commitment covered, with the member's static signature.
    Reveal(Reveal),
    /// Round 3: the member's Burmester–Desmedt round-2 value `X_i`, broadcast on its own so
    /// every member can assemble the full `X_*` map that deriving `K` requires. Without this
    /// the protocol cannot run over a log at all.
    Round2 {
        /// The broadcasting member's static identity fingerprint.
        author_id: Digest32,
        /// `X_i = x_i·(z_{i+1} − z_{i−1})` over the canonical ring.
        x: [u8; SHARE_LEN],
    },
    /// Rounds 3–4: the Burmester–Desmedt value `X_i`, the DSKE bind, and the key
    /// confirmation MAC.
    Confirm(Confirm),
    /// A re-key broadcast: fresh `epk'` and share, the new ring's `X'_i`, and the bind
    /// and confirmation over the updated transcript.
    ReKey(ReKey),
}

fn pub_key(d: &mut Decoder<'_>, what: &'static str) -> Result<CompositePublicKey> {
    let bytes: [u8; COMPOSITE_PUB_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle(what))?;
    CompositePublicKey::from_bytes(&bytes)
}

fn signature(d: &mut Decoder<'_>, what: &'static str) -> Result<CompositeSignature> {
    let bytes: [u8; COMPOSITE_SIG_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle(what))?;
    CompositeSignature::from_bytes(&bytes)
}

fn digest(d: &mut Decoder<'_>, what: &'static str) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle(what))
}

fn share_of(d: &mut Decoder<'_>, what: &'static str) -> Result<[u8; SHARE_LEN]> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle(what))
}

impl DgkaMessage {
    /// The member this message is from — the only field every round shares, and what a
    /// reader needs to place the message before interpreting it.
    #[must_use]
    pub fn author_id(&self) -> Digest32 {
        match self {
            Self::Commit { author_id, .. } => *author_id,
            Self::Reveal(r) => r.author_id,
            Self::Round2 { author_id, .. } => *author_id,
            Self::Confirm(c) => c.author_id,
            Self::ReKey(r) => r.author_id,
        }
    }

    /// The canonical CBOR body, round discriminant first.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Commit { author_id, commit } => {
                e.array(3)
                    .uint(ROUND_COMMIT)
                    .bytes(author_id.as_slice())
                    .bytes(commit.as_slice());
            }
            Self::Reveal(r) => {
                e.array(7)
                    .uint(ROUND_REVEAL)
                    .bytes(r.author_id.as_slice())
                    .bytes(&r.author_pubkey.to_bytes())
                    .bytes(&r.epk.to_bytes())
                    .bytes(&r.share[..])
                    .bytes(&r.nonce[..])
                    .bytes(&r.reveal_sig.to_bytes());
            }
            Self::Round2 { author_id, x } => {
                e.array(3)
                    .uint(ROUND_X)
                    .bytes(author_id.as_slice())
                    .bytes(&x[..]);
            }
            Self::Confirm(c) => {
                e.array(5)
                    .uint(ROUND_CONFIRM)
                    .bytes(c.author_id.as_slice())
                    .bytes(&c.round2[..])
                    .bytes(&c.bind_sig.to_bytes())
                    .bytes(&c.confirm_mac[..]);
            }
            Self::ReKey(r) => {
                e.array(7)
                    .uint(ROUND_REKEY)
                    .bytes(r.author_id.as_slice())
                    .bytes(&r.epk.to_bytes())
                    .bytes(&r.share[..])
                    .bytes(&r.round2[..])
                    .bytes(&r.bind_sig.to_bytes())
                    .bytes(&r.confirm_mac[..]);
            }
        }
        e.finish()
    }

    /// Frame for the log payload: `tag(0x000B) ‖ version ‖ canonical_body`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        frame(StructTag::DgkaSetup, &self.canonical_body())
    }

    /// Parse a framed `dgka-setup` entry, validating the tag, version, round
    /// discriminant, arity and every field length.
    ///
    /// # Errors
    /// [`Error::MalformedBundle`] naming the field that failed. A wrong arity for a
    /// known round is rejected before any field is read, so a truncated or padded
    /// message cannot be read as a shorter round.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::DgkaSetup {
            return Err(Error::MalformedBundle("dgka-setup wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        let arity = d.array()?;
        let round = d.uint()?;
        let message = match (round, arity) {
            (ROUND_COMMIT, 3) => Self::Commit {
                author_id: digest(&mut d, "dgka-setup commit author_id length")?,
                commit: digest(&mut d, "dgka-setup commit length")?,
            },
            (ROUND_REVEAL, 7) => {
                let author_id = digest(&mut d, "dgka-setup reveal author_id length")?;
                let author_pubkey = pub_key(&mut d, "dgka-setup reveal author_pubkey length")?;
                let epk = pub_key(&mut d, "dgka-setup reveal epk length")?;
                let share = share_of(&mut d, "dgka-setup reveal share length")?;
                let nonce: [u8; NONCE_LEN] = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("dgka-setup reveal nonce length"))?;
                let reveal_sig = signature(&mut d, "dgka-setup reveal signature length")?;
                // The reveal's own rule, checked here because it is a property of the
                // message rather than of the protocol state: the ordering key must be
                // the key the fingerprint names, or a member could be ordered in the
                // ring under one identity while signing as another.
                if author_pubkey.fingerprint() != author_id {
                    return Err(Error::MalformedBundle(
                        "dgka-setup reveal author_pubkey does not match author_id",
                    ));
                }
                Self::Reveal(Reveal {
                    author_id,
                    author_pubkey,
                    epk,
                    share,
                    nonce,
                    reveal_sig,
                })
            }
            (ROUND_X, 3) => Self::Round2 {
                author_id: digest(&mut d, "dgka-setup round2 author_id length")?,
                x: share_of(&mut d, "dgka-setup round2 value length")?,
            },
            (ROUND_CONFIRM, 5) => Self::Confirm(Confirm {
                author_id: digest(&mut d, "dgka-setup confirm author_id length")?,
                round2: share_of(&mut d, "dgka-setup confirm round2 length")?,
                bind_sig: signature(&mut d, "dgka-setup confirm bind signature length")?,
                confirm_mac: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("dgka-setup confirm mac length"))?,
            }),
            (ROUND_REKEY, 7) => Self::ReKey(ReKey {
                author_id: digest(&mut d, "dgka-setup rekey author_id length")?,
                epk: pub_key(&mut d, "dgka-setup rekey epk length")?,
                share: share_of(&mut d, "dgka-setup rekey share length")?,
                round2: share_of(&mut d, "dgka-setup rekey round2 length")?,
                bind_sig: signature(&mut d, "dgka-setup rekey bind signature length")?,
                confirm_mac: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("dgka-setup rekey mac length"))?,
            }),
            _ => return Err(Error::MalformedBundle("dgka-setup round or arity")),
        };
        d.finish()?;
        let _ = CONFIRM_LEN;
        Ok(message)
    }
}
