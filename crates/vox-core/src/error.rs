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

    /// Every rung of the ADR-012 ladder was tried and none landed, carrying **what each
    /// rung reported**.
    ///
    /// [`Self::Unreachable`] cannot say this: the direct rung and each circuit rung fail
    /// for independent reasons, and one `&'static str` can only name one of them. Keeping
    /// whichever rung happened to finish last is worse than useless, because the direct
    /// rung is always the slowest and so always wins that race — the operator is then
    /// told about a timeout while the rung that knew the real answer is discarded
    /// (ADR-018 §8b: whatever knows why must say why).
    #[error("peer unreachable — {0}")]
    LadderExhausted(String),

    /// A tunnel operation was refused by authorization (ADR-013): the requesting
    /// member holds no valid `dial:<service>` capability (or the host no
    /// `bind:<service>`), or the service is dark/unknown. Default-deny: the absence
    /// of a grant is a denial, and a denial is indistinguishable from "no such
    /// service" so an unauthorized member cannot even confirm a service exists.
    #[error("tunnel denied: {0}")]
    TunnelDenied(&'static str),

    /// A live tunnel was torn down because the host withdrew the dialer's reach
    /// (ADR-017 M17.11): the identity left the host's trust keyring, or the room's
    /// author set, while bytes were still flowing. Distinct from
    /// [`Error::TunnelDenied`] on purpose — a refusal at dial time must stay
    /// indistinguishable from "no such service", but a peer whose *established*
    /// session is cut already knows it had one, so telling it why leaks nothing and
    /// saves it from retrying against a decision that will not change.
    #[error("tunnel reach withdrawn: {0}")]
    TunnelRevoked(&'static str),

    /// A tunnel control message (service request, stream-setup handshake) or an
    /// SSH-CA certificate was structurally malformed on parse, exceeded a size
    /// bound, or carried an out-of-domain value (ADR-013). Carries a static reason.
    #[error("malformed tunnel artifact: {0}")]
    MalformedTunnel(&'static str),

    /// **Another process already holds this profile.** redb is single-writer, so one
    /// `vox` at a time may open a profile's store — and a running `vox daemon` or `vox
    /// tui` holds it for as long as it runs.
    ///
    /// Distinct from [`Error::Storage`] because the remedy is completely different and
    /// the caller is the only layer that can state it: nothing is wrong with the store,
    /// there is simply a node already running, and the verb should be asked of *that*
    /// node rather than of a second one. Collapsing it into a generic storage failure is
    /// how a person came to be told "store open: Database already open. Cannot acquire
    /// lock." for the ordinary act of running a command while their daemon was up.
    #[error("another vox already has this profile open")]
    ProfileBusy,

    /// The node's persistent store (ADR-016) failed an operation: opening or
    /// creating the file, a transaction, or a table access. `op` is a static
    /// description of what was attempted; `detail` carries the engine's message
    /// (never key material — the store only ever holds sealed artifacts).
    #[error("store {op}: {detail}")]
    Storage {
        /// What was being attempted.
        op: &'static str,
        /// The underlying engine/OS message.
        detail: String,
    },

    /// A `vox://` invite link was malformed (ADR-016 §"Invite link"): wrong scheme,
    /// a bad base32 digest, a malformed or over-long anchor list, a duplicate or
    /// unknown query field. A link is untrusted input from a chat message, so
    /// nothing about it is guessed. Carries a static reason.
    #[error("malformed invite link: {0}")]
    MalformedLink(&'static str),

    /// An `--anchor` spec, or a line of the anchors file, could not be used: it is not
    /// `<fingerprint>@<host:port>` or `<fingerprint>@<multiaddr>`, its fingerprint is not
    /// base32, its port is not a number, or its host does not resolve.
    ///
    /// Its own variant because it was [`Error::MalformedLink`], which renders as
    /// "malformed invite link" — so a person who mistyped `--anchor` was told their
    /// invite link was wrong, and they had not given one. The two are different inputs
    /// arriving from different places and a person fixes them in different files.
    #[error("bad anchor: {0}")]
    MalformedAnchor(&'static str),

    /// The responder refused a join (ADR-016 §"Join over the network"): the coarse
    /// reason it sent on the join stream. Deliberately not a fine-grained taxonomy —
    /// a wrong passphrase already fails locally on the joiner, so the responder has
    /// no reason to confirm a guess. Carries a static reason.
    #[error("join refused: {0}")]
    JoinRefused(&'static str),

    /// A peer opened a stream kind its class is not authorized to open (ADR-016
    /// §"Connections": an anchor has no channel authority, a pending joiner may
    /// open only the join stream, an unknown peer only the rendezvous service).
    /// The stream is reset with the same coded rejection an unauthenticated peer
    /// gets, so probing stream kinds reveals nothing. Carries a static reason.
    #[error("stream refused: {0}")]
    StreamRefused(&'static str),

    /// A profile lifecycle state error (ADR-016 §Profile): no identity in the
    /// profile, an identity already present, or an operation that needs the
    /// unlocked identity while the profile is locked. Carries a static reason.
    #[error("profile: {0}")]
    Profile(&'static str),

    /// A profile/store path could not be resolved or prepared (ADR-016 §Layout):
    /// no home directory, a directory that could not be created with the required
    /// mode, or an I/O failure on the vault file. Carries a static reason plus the
    /// OS message.
    #[error("profile path {op}: {detail}")]
    Path {
        /// What was being attempted.
        op: &'static str,
        /// The underlying OS message.
        detail: String,
    },
}
