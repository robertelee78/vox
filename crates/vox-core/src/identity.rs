//! # Identity and key model (ADR-002)
//!
//! The self-sovereign identity that roots every other Vox mechanism: key
//! agreement (ADR-004), channel join (ADR-005), governance certificates
//! (ADR-007), per-author log authentication (ADR-008), and deniable content
//! authentication (ADR-009). There are no accounts and no central key directory
//! (ADR-001); identity is a set of keys with strictly separated roles, verified
//! peer-to-peer, and post-quantum from day one (ADR-003).
//!
//! ## Crate selection (ADR-002 §1, ADR-003)
//! The hybrid-PQ primitives are provided by reviewed, maintained pure-Rust
//! crates, pinned in the workspace manifest:
//!
//! - **Ed25519** — `ed25519-dalek` v2 (the de-facto Rust Ed25519).
//! - **X25519** — `x25519-dalek` v2 (`static_secrets` for the long-term DH key).
//! - **ML-DSA-65** — RustCrypto `ml-dsa` (FIPS 204). Chosen over the
//!   integritychain `fips204` crate because RustCrypto is actively maintained,
//!   has had timing/malleability issues found *and fixed* under security review
//!   (a maturity signal, not a strike), uses current `rand_core`, and has broad
//!   ecosystem adoption.
//! - **ML-KEM-768** — RustCrypto `ml-kem` (FIPS 203), same rationale.
//!
//! Neither PQ stack is independently audited or CAVP-certified — *no* pure-Rust
//! PQ crate is, as of this writing. That is an accepted, documented residual:
//! the construction is **hybrid** (ADR-003), so a flaw in a single PQ primitive
//! does not by itself break security, and an independent audit is a release
//! prerequisite tracked at the project level.
//!
//! ## Randomness
//! Every key is derived from a fixed-size seed sampled from the OS CSPRNG
//! (`getrandom`) and then generated deterministically from that seed
//! ([`rng`]). Vox does not thread a `rand_core` RNG object through the crypto
//! crates; this keeps one auditable randomness source and avoids the two
//! coexisting `rand_core` major versions in the dependency tree.
//!
//! ## Module map
//! - [`composite`] — the composite Ed25519+ML-DSA-65 root of trust: fixed byte
//!   layout, both-halves-must-verify signatures, the [`RootSigner`] backend
//!   seam, and the complete in-software backend.
//! - [`keyagreement`] — the X25519 identity DH key, the root-signed hybrid
//!   signed prekey (X25519 + ML-KEM-768), and the consume-once one-time prekey
//!   pool (ADR-002 §2, for ADR-004 PQXDH).
//! - [`binding`] — the OpenPGP ↔ ML-DSA signed binding statement (ADR-002 §GPG).
//! - [`backup`] — `self_seed` generation and the serializable identity-backup
//!   bundle (ADR-002 §Backup; passphrase encryption is ADR-010/M8).
//! - [`device`] — the multi-device strategy model and per-channel pseudonymity
//!   selection (ADR-002 §Multi-device, §Pseudonymity).
//!
//! ## Engineering mantra (binding — see ADR-001)
//! No stubs, no `todo!()`, no shortcuts. Every type here is complete and tested.
//! Where a capability genuinely belongs to a later milestone (gpg-agent
//! delegation → ADR-010; passphrase encryption of the backup → ADR-010), the
//! boundary is stated explicitly in the relevant item's docs and what ships up
//! to that boundary is finished, not a placeholder.

pub mod backup;
pub mod binding;
pub mod composite;
pub mod device;
pub mod keyagreement;
pub mod rng;

pub use backup::{IdentityBackup, SelfSeed};
pub use binding::GpgBindingStatement;
pub use composite::{CompositePublicKey, CompositeSignature, RootSigner, SoftwareRootSigner};
pub use device::{ChannelIdentitySelection, DeviceStrategy};
pub use keyagreement::{
    OneTimePrekey, OneTimePrekeyPool, OneTimePrekeyPublic, PrekeyBundlePublic, SignedIdentityDhKey,
    SignedPrekey, SignedPrekeyPublic, X25519IdentityKey, X25519IdentityKeyPublic,
};
