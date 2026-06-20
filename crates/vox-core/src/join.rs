//! # Channel addressing and authenticated join (ADR-005)
//!
//! A Vox channel is addressed magnet-link style by a **channelID + passphrase**
//! shared out-of-band (ADR-001). Those two values do two *separate* jobs, and
//! this module keeps them separate (ADR-005 §"Separate rendezvous from
//! authentication"):
//!
//! - **Rendezvous** — *finding the swarm*. Driven by the high-entropy
//!   [`channelid`] (`SHA-256` of the canonical genesis record) through a plain,
//!   fast KDF ([`mod@rendezvous`]). The passphrase is **never** an input to
//!   rendezvous: a fast KDF is sufficient precisely because the channelID is
//!   already 256-bit high-entropy.
//! - **Authentication** — *proving you may join*. Two composed factors:
//!   1. **CPace** ([`cpace`]) — the CFRG-recommended *balanced* PAKE over
//!      Ristretto255 + SHA-512 (ADR-003 PAKE id `0x0701`). Symmetric (no server,
//!      no fixed roles), implicit mutual authentication, and provably one online
//!      guess per interaction against the low-entropy passphrase. CPace alone
//!      proves only "this party holds the passphrase", not *which identity*.
//!   2. **Identity proof-of-possession** ([`pop`]) — inside the CPace-protected
//!      session each party signs `sid ‖ transcript_hash` with its composite
//!      Ed25519+ML-DSA identity key (ADR-002) and the peer matches the derived
//!      fingerprint to the expected one (verified out-of-band, ADR-014). Naming
//!      an identity is not enough; possession is proven.
//!
//! On top of authentication, an anti-abuse layer:
//!
//! - **Equihash join proof-of-work** ([`pow`]) — an *asymmetric memory-hard* PoW
//!   (Equihash, Zcash's `n=200,k=9`), hard to *solve* yet cheap to *verify*, with
//!   the token bound to `(channelID, epoch, responder_nonce)` so it cannot be
//!   precomputed or replayed across channels/epochs. The advertised difficulty is
//!   carried in the **signed** responder nonce so the prover cannot lie about it.
//!
//! A successful CPace + PoP (+ valid PoW) run hands off to the M2 PQXDH session
//! ([`crate::pairwise::Session`]) to bootstrap the Double-Ratchet pairwise channel
//! ([`session`]). **Joining yields no readable content** — membership is emergent
//! (join + per-sender consent, ADR-007/M6); there is no admin admission step and
//! no membership certificate. That boundary is asserted in [`session`]'s docs.
//!
//! ## Deferred boundaries (documented, not stubbed — ADR mantra)
//! - **DHT key width** is ADR-012/M10. [`mod@rendezvous`] derives a full 32-byte key
//!   and offers [`rendezvous::truncate`]; the width *choice* is M10's.
//! - **The genesis-record schema** is ADR-007/M6. [`channelid`] treats genesis as
//!   opaque high-entropy canonical bytes (carrying a 128-bit nonce) and hashes
//!   them; it does not define the struct.
//! - **Prekey publication** to the rendezvous/log is ADR-005/ADR-008 (M3 wiring is
//!   not it; publication is M5). [`session`] consumes an already-verified
//!   in-memory [`crate::identity::keyagreement::PrekeyBundlePublic`].
//! - **The consent read-gate** is ADR-007/M6. Join establishes a pairwise session
//!   only; it confers no read authority.
//!
//! ## Engineering mantra (binding — see ADR-001)
//! No stubs, no `todo!()`, no shortcuts. The CPace construction is validated
//! against the CFRG draft's Ristretto255+SHA-512 test vectors and the Equihash
//! verifier against librustzcash vectors; both are the correctness gates.

pub mod channelid;
pub mod cpace;
pub mod pop;
pub mod pow;
pub mod rendezvous;
pub mod session;

pub use channelid::channel_id;
pub use cpace::{CpaceState, CPACE_ISK_LEN, CPACE_SHARE_LEN};
pub use pop::{IdentityProof, JoinPeerIdentity};
pub use pow::{Difficulty, PowParams, PowToken, ResponderNonce, EQUIHASH_K, EQUIHASH_N};
pub use rendezvous::{rendezvous, RENDEZVOUS_KEY_LEN};
pub use session::{join_accept, join_initiate, JoinContext, JoinInitiator, JoinResponder};
