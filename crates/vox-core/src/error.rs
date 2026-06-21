//! Crate-wide error type.
//!
//! Foundation milestone (M0) only models the errors the foundation can actually
//! raise. Later milestones extend [`Error`] as they add real failure modes —
//! never speculatively (ADR mantra: no stubs, no "we'll fill it in later").

use crate::cbor::CborError;

/// Result alias used throughout `vox-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// The unified `vox-core` error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Canonical-CBOR encode/decode failure (includes canonicality violations).
    #[error("cbor: {0}")]
    Cbor(#[from] CborError),

    /// A framed struct carried a 2-byte tag not in the ADR-008 registry.
    #[error("unknown struct tag {0:#06x}")]
    UnknownStructTag(u16),

    /// A framed struct carried a format version this build does not implement.
    #[error("unsupported format version {version} for struct tag {tag:#06x}")]
    UnsupportedVersion {
        /// The struct-type tag whose version was rejected.
        tag: u16,
        /// The unrecognized format version byte.
        version: u8,
    },

    /// An `algo_id` (u16) was not found in the ADR-003 registry.
    #[error("unknown algorithm id {0:#06x}")]
    UnknownAlgoId(u16),

    /// A ciphersuite id was not found in the ADR-003 registry.
    #[error("unknown ciphersuite id {0:#06x}")]
    UnknownSuite(u16),

    /// A negotiated/observed suite ranked below the channel's policy floor
    /// (ADR-003 floor-gated downgrade rejection — abort, never fall back).
    #[error("ciphersuite {observed:#06x} is below the policy floor {floor:#06x}")]
    SuiteBelowFloor {
        /// The suite that was offered/observed.
        observed: u16,
        /// The minimum suite the channel policy requires.
        floor: u16,
    },

    /// The operating-system CSPRNG was unavailable (ADR-002 identity key
    /// generation). A hard failure — Vox never falls back to a weaker source.
    #[error("operating-system CSPRNG unavailable")]
    Rng,

    /// Public-key bytes did not decode as a valid key for the named algorithm
    /// (ADR-002/003). The `algo` field is the ADR-003 algorithm ID.
    #[error("invalid key encoding for algorithm {algo:#06x}")]
    InvalidKeyEncoding {
        /// The ADR-003 algorithm ID whose key encoding was rejected.
        algo: u16,
    },

    /// Signature bytes did not decode as a structurally valid signature
    /// (ADR-002 composite signature parsing).
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,

    /// A signature failed verification (ADR-002). For composite signatures this
    /// is returned whenever *either* component half fails, without revealing
    /// which.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// A signing operation failed (ADR-002). Distinct from a verification
    /// failure: this is an error producing a signature, not checking one.
    #[error("signing operation failed")]
    SigningFailed,

    /// A field carried an algorithm ID that is valid in the registry but not the
    /// one this structure requires (ADR-003 type-confusion guard at a boundary).
    #[error("unexpected algorithm {got:#06x}, expected {expected:#06x}")]
    UnexpectedAlgo {
        /// The algorithm ID actually present.
        got: u16,
        /// The algorithm ID the structure requires.
        expected: u16,
    },

    /// A consume-once one-time prekey was requested but the pool is empty
    /// (ADR-002 §2). Callers fall back to the signed last-resort prekey.
    #[error("one-time prekey pool is empty")]
    PrekeyPoolEmpty,

    /// A backup/binding bundle's declared field was inconsistent or out of range
    /// on parse (ADR-002 §Backup, §GPG integration).
    #[error("malformed identity bundle: {0}")]
    MalformedBundle(&'static str),

    /// A received CPace public share or the derived shared point `K` was the
    /// group identity (ADR-005 CPace `scalar_mult_vfy` MUST-abort). The session
    /// is aborted: the peer either sent a degenerate share or no agreement
    /// exists.
    #[error("cpace identity-element / invalid share")]
    CpaceInvalidShare,

    /// A join message was structurally malformed (bad arity, wrong length field,
    /// missing component). Carries a static reason for diagnosis (ADR-005).
    #[error("malformed join message: {0}")]
    MalformedJoin(&'static str),

    /// An identity proof-of-possession failed (ADR-005 factor 2): either the
    /// composite signature over `sid ‖ transcript_hash` did not verify, or the
    /// presented identity's fingerprint did not match the expected one. The two
    /// are deliberately one error so a probe cannot distinguish "wrong key" from
    /// "wrong identity".
    #[error("join proof-of-possession failed")]
    JoinProofFailed,

    /// An Equihash join proof-of-work was invalid (ADR-005 anti-abuse layer 2):
    /// the solution did not verify for `(channelID, epoch, responder_nonce)`, did
    /// not meet the advertised difficulty, or its parameters were rejected.
    #[error("join proof-of-work invalid")]
    JoinPowInvalid,

    /// A log entry carried the ADR-009 *deniable* content authenticator, whose
    /// verification is provided by milestone M7 (ADR-009) — not implemented in M5.
    /// This is an honest capability boundary, not a stub: M5 builds the wire seam
    /// (the entry round-trips and is classified non-attributable) and the
    /// composite path fully, and refuses to *claim* a deniable verification it
    /// does not perform (ADR-008 §"build coupling with ADR-009").
    #[error("deniable authenticator verification is provided by M7 (ADR-009)")]
    DeniableVerificationUnavailable,

    /// A framed structure exceeded a hard size limit before any allocation
    /// proportional to attacker-declared counts/lengths was performed (ADR-008
    /// anti-abuse: the per-author quota must not be the first line of defense).
    /// Carries a static label naming the limit that was exceeded.
    #[error("declared size exceeds hard limit: {0}")]
    SizeLimitExceeded(&'static str),

    /// A governance capability token was not in the closed ADR-007 vocabulary.
    /// The evaluator's domain is closed: an unknown capability is a hard
    /// verification failure, never silently ignored (ADR-007 §"Capability
    /// vocabulary").
    #[error("unknown governance capability")]
    UnknownCapability,

    /// A governance struct (genesis record, admin-delegation cert, consent
    /// grant/revocation, admin-delegation revocation, policy update) was
    /// structurally malformed on parse — bad arity, an out-of-domain enum, a
    /// wrong-length digest/key, or a field forbidden by its schema (e.g. a
    /// policy-update carrying `deniability_mode`). Carries a static reason
    /// (ADR-007).
    #[error("malformed governance struct: {0}")]
    MalformedGovernance(&'static str),

    /// The caller-supplied governance causal edges contain a cycle (an entry is
    /// reachable from its own `causal_predecessors`). A real hash-linked log is
    /// acyclic by construction — a link can only name an already-existing entry —
    /// so this is malformed/adversarial input. The deterministic evaluator rejects
    /// it rather than recursing without bound (ADR-007 / ADR-008 anti-abuse:
    /// totality over *any* input, not just well-formed input).
    #[error("governance causal graph contains a cycle")]
    GovernanceCycle,

    /// An at-rest unlock failed: the AEAD over a SEK wrap, an identity-vault
    /// bundle, or a store segment did not authenticate (ADR-010 double-lock).
    /// Returned for a wrong channel passphrase, a wrong identity factor, a
    /// wrong-channel wrap, a tampered ciphertext, or a wrong KDF-profile version —
    /// they are deliberately one error so a probe cannot tell *which* factor was
    /// wrong (the at-rest analogue of [`Error::JoinProofFailed`]).
    #[error("at-rest unlock failed (wrong factor or tampered ciphertext)")]
    AtRestUnlockFailed,

    /// A SEK-backed operation (segment seal/open, re-wrap) was attempted after the
    /// app was **locked** (ADR-010 §"App-lock and memory hygiene"): the SEK was
    /// zeroized and invalidated, so it must be re-derived from both factors
    /// (re-auth) before the store can be touched again. Distinct from
    /// [`Error::AtRestUnlockFailed`] — it is not a wrong/forged factor, it is a
    /// closed door requiring re-authentication.
    #[error("at-rest store is locked; re-authenticate to obtain a fresh SEK")]
    AtRestLocked,

    /// An at-rest artifact (SEK wrap, vault bundle, store segment, content object)
    /// was structurally malformed on parse, or a KDF profile carried out-of-range
    /// Argon2id parameters. Carries a static reason (ADR-010).
    #[error("malformed at-rest artifact: {0}")]
    MalformedAtRest(&'static str),

    /// The Argon2id passphrase factor (`factor_pass`) could not be computed
    /// (ADR-010 §Double-lock). The only realistic cause is an invalid parameter
    /// profile reaching the KDF; surfaced as an error rather than panicking.
    #[error("argon2id key derivation failed")]
    Argon2Failed,

    /// A rendezvous record (member or pre-join), a multiaddr, or an endpoint list
    /// was structurally malformed on parse — bad arity, an unknown multiaddr
    /// discriminant, a wrong-length address/digest/key, a wrong struct tag, or a
    /// value out of range (ADR-012). Carries a static reason.
    #[error("malformed rendezvous artifact: {0}")]
    MalformedRendezvous(&'static str),

    /// A rendezvous record was well-formed and correctly signed but was **rejected
    /// by the reader's authenticated-store policy** (ADR-012): a stale/replayed
    /// `(seq, timestamp)` (older than the current record for that
    /// `(author, channel, epoch)`), a refresh faster than the minimum interval, a
    /// publisher that is not a channel member, an expired TTL, or a record whose
    /// `(channelID, epoch)` does not match the rendezvous key it was published
    /// under. Distinct from [`Error::MalformedRendezvous`] — the bytes are valid,
    /// the *policy* refuses them, so a poisoner cannot inject or replay endpoints.
    #[error("rendezvous record rejected by store policy: {0}")]
    RendezvousRejected(&'static str),

    /// A port-mapping exchange (PCP, RFC 6887, or NAT-PMP, RFC 6886) failed: the
    /// gateway returned a non-success result code, the response was malformed or
    /// for a different request (nonce/opcode/epoch mismatch), or the mapping the
    /// gateway granted did not satisfy the request. Carries a static reason
    /// (ADR-012 reachability ladder). A failure on one rung falls through to the
    /// next rung; it never silently claims a mapping that does not exist.
    #[error("port mapping failed: {0}")]
    PortMappingFailed(&'static str),

    /// A hole-punch coordination exchange (DCUtR-style Connect/Sync, ADR-012)
    /// failed: a malformed or out-of-sequence coordination message, a missing peer
    /// endpoint, or the half-RTT synchronization timer elapsed without a usable
    /// simultaneous-open window. Carries a static reason. Hole-punching is
    /// best-effort by nature (both-symmetric-NAT pairs cannot be punched, ADR-012);
    /// a failure degrades to the relay rung, never to a false success.
    #[error("hole-punch coordination failed: {0}")]
    HolePunchFailed(&'static str),

    /// Every rung of the reachability ladder was exhausted without establishing a
    /// connection to the peer (ADR-012): no direct candidate connected, no
    /// coordinator was reachable for a hole-punch, and no relay closed the residual.
    /// This is the honest documented limit (both peers behind CGNAT/symmetric NAT
    /// with no IPv6 and no reachable coordinator) — surfaced as an error, never a
    /// false success.
    #[error("peer unreachable: {0}")]
    Unreachable(&'static str),
}
