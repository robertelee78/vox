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

    /// A message on a node's control socket could not be decoded (#211). Its own variant, never
    /// [`Self::MalformedBundle`]: a bad or unknown IPC frame said "malformed identity bundle", which
    /// points at identity corruption.
    #[error("malformed control-socket message: {0}")]
    MalformedIpc(&'static str),

    /// A client sent the node a request it does not know: most often a client from another vox
    /// version (#211).
    #[error("the node does not know this request (the client may be a different vox version)")]
    UnknownIpcRequest,

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

    /// A framed structure exceeded a hard size limit before any allocation
    /// proportional to attacker-declared counts/lengths was performed (ADR-008
    /// anti-abuse: a declared length is never trusted ahead of the bytes behind it).
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
    /// wrong-length digest/key, a field forbidden by its schema, or a genesis
    /// asking for a removed deniable room. Carries a static reason
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

    /// A log entry in the shape vox wrote **before v0.3.0**: its skeleton has no `seen` and no
    /// causal time (ADR-023 decision 1). v0.3.0 does not read them; the decider chose that
    /// such a room is made again (2026-09-29, #226). Its own variant so a person is told that,
    /// not "an internal error".
    #[error("a log entry written by vox before v0.3.0, whose message format changed")]
    LogFormatBeforeV030,

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

    /// A QUIC handshake failed for a reason other than authentication: the peer refused or
    /// closed the connection, never answered, or this node's endpoint is closing.
    ///
    /// Every handshake failure used to be [`Self::SignatureInvalid`], so a peer that was shutting
    /// down, or a dial nobody answered, reached the operator as "signature verification failed" —
    /// an alarm about keys for what is a closed door (V210-81). A failure of authentication itself
    /// still is `SignatureInvalid`.
    #[error("the connection could not be set up: {0}")]
    Handshake(String),

    /// This node could not listen on a local address it was told to use.
    ///
    /// Carried whole rather than as a `&'static str`: "quic endpoint bind" was the only thing
    /// the daemon could say when its `--listen` port was taken, and it reached the person as
    /// `Failed(Internal)` — a bug report for what is an occupied port (PRD-001 R36).
    #[error("cannot listen on {addr}: {reason}")]
    LocalBind {
        /// The address that could not be bound.
        addr: std::net::SocketAddr,
        /// Whether something else already holds it (the common case, and the one with an
        /// obvious fix).
        in_use: bool,
        /// What the operating system said.
        reason: String,
    },

    /// A tunnel operation was refused (ADR-013, ADR-017 decision 3): the host does not
    /// trust the requesting member, it is no current author of the room, or the service is
    /// dark/unknown. Default-deny, and a denial is indistinguishable from "no such service",
    /// so an unauthorized member cannot even confirm a service exists.
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

    /// A tunnel was refused because the connection to that member already carries
    /// [`TUNNELS_PER_PEER`](crate::transport::quic::TUNNELS_PER_PEER) tunnels, each holding a
    /// receive window this node agreed to buffer (V210-81). Said where the tunnel was asked
    /// for; the host refuses one past it too, uniformly, as it refuses anything. Carries what
    /// the person is told: how many are open, to which services, and how to free one.
    #[error("{0}")]
    TunnelLimit(String),

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

    /// The anchors file names no anchor that can be used — every line of it was skipped — and
    /// no `--anchor` was given (V210-75). **Said, never a refusal** (V210-107): the file is
    /// named and skipped, and the verb runs anchorless, reaching whoever it can reach directly.
    /// An anchor only bridges hosts that cannot otherwise reach each other (ADR-012), so a verb
    /// that truly needs one fails where it needs it, not here.
    #[error(
        "the anchors file {path} names no usable anchor ({skipped} skipped, each said above); \
         a peer this machine can reach directly needs none"
    )]
    AnchorsFileUnusable {
        /// The anchors file.
        path: String,
        /// How many of its lines were skipped; 1 for a file that cannot be read at all.
        skipped: usize,
    },

    /// The responder refused a join (ADR-016 §"Join over the network"): the coarse
    /// reason it sent on the join stream. Deliberately not a fine-grained taxonomy —
    /// a wrong passphrase already fails locally on the joiner, so the responder has
    /// no reason to confirm a guess. Carries a static reason.
    #[error("join refused: {0}")]
    JoinRefused(&'static str),

    /// Every one of the responder's join slots was held, so it refused before the exchange began
    /// (V210-92). The passphrase was never checked.
    #[error("a member is busy answering other joins")]
    JoinResponderBusy,

    /// This node ended a join it was answering, to give its slot to a joiner from a lighter source
    /// (V210-92): every slot was held and this join's source was the heaviest. Its joiner is told
    /// the member is busy, as at the cap.
    #[error("ended to answer a join from elsewhere: every join slot was held")]
    JoinEndedForNewcomer,

    /// This joiner's proof of work took longer than the responder waits for it, so the responder
    /// had stopped waiting before the solution arrived (V210-87). Both sides derive the wait from
    /// the same signed difficulty, so the joiner can say this rather than a refusal it cannot name.
    #[error(
        "this device took {solved_secs}s to solve the join's proof of work, and a member waits \
         {patience_secs}s for it"
    )]
    JoinSolveTooSlow {
        /// How long this side's grind took, in whole seconds.
        solved_secs: u64,
        /// How long the responder waits for it at the difficulty it demanded, in whole seconds.
        patience_secs: u64,
    },

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

    /// A node refused an app-API request over its control socket (ADR-022 decision 7),
    /// carrying the node's own reason — `no-listener`, not in the keyring, and so on —
    /// because the program asking has no other way to learn it.
    #[error("{0}")]
    AppRefused(String),

    /// Attaching to a node's control socket failed before any request: the connect, or
    /// the node's greeting. Said in a person's words, because each one needs a different
    /// remedy and they used to share one sentence (#191).
    #[error("{0}")]
    Ipc(IpcHandshake),

    /// A sync session did not complete, carrying the ADR-008 coded reason (#202).
    ///
    /// **Not [`Self::MalformedGovernance`].** Every sync failure used to be wrapped in it, so a
    /// peer's ordinary refusal of a colliding session read "malformed governance struct: sync
    /// failed: transport", which points at data corruption and cannot be told apart from a path
    /// that died.
    #[error("sync failed: {0}")]
    SyncFailed(crate::wire::WireError),

    /// A sync session did not complete because **the peer refused** it, with this coded reason.
    /// Kept apart from [`Self::SyncFailed`] and [`Self::SyncRejected`] so that a report can say
    /// which end stopped the session (#202's follow-up: all three used to read the same).
    #[error("sync failed: the peer refused: {0}")]
    SyncRefused(crate::wire::WireError),

    /// A sync session did not complete because **this node** refused what the peer sent, with
    /// this coded reason: an entry the log would not accept, or a frame out of protocol.
    #[error("sync failed: this node refused what the peer sent: {0}")]
    SyncRejected(crate::wire::WireError),

    /// The peer reset or stopped the stream with a coded reason (an ADR-008 [`WireError`]):
    /// it refused, deliberately, and said why. Distinct from [`Self::Unreachable`], which is a
    /// stream or connection that went away with nothing said.
    ///
    /// [`WireError`]: crate::wire::WireError
    #[error("the peer refused: {0}")]
    PeerRefused(crate::wire::WireError),
}

/// Why a node hung up, for [`IpcHandshake::HungUp`]'s message.
fn hung_up_why(still_running: bool) -> &'static str {
    if still_running {
        "it is still running, so it ended this request itself; its log says why"
    } else {
        "it is no longer running: it stopped, crashed or was stopped while answering. Start it \
         again"
    }
}

/// How an attach to a node's control socket failed ([`Error::Ipc`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcHandshake {
    /// The connect itself failed: nothing is listening on the socket.
    #[error("nothing is listening on the control socket ({reason})")]
    Unreachable {
        /// The OS message.
        reason: String,
    },
    /// Something accepted the connection and closed it without greeting.
    #[error("the node closed the connection before greeting")]
    ClosedBeforeHello,
    /// The node greeted, took a request and closed the connection before replying (V210-101).
    /// Nothing was malformed: the connection ended. Whether the node is still running is asked
    /// with a fresh connection when the reply goes missing, because the two need different
    /// remedies — a node that is gone is started again, one that is still running has a log that
    /// says why it ended the request.
    #[error("the node closed the connection before replying: {}", hung_up_why(*still_running))]
    HungUp {
        /// Whether a fresh connection to the same socket was taken when the reply went missing.
        still_running: bool,
    },
    /// The connection ended under a write (V210-101). A client names it [`Self::HungUp`], once
    /// it has asked whether the node is still running; the node's side says this.
    #[error("the other end closed the control-socket connection")]
    Cut,
    /// The node greeted in another control protocol: the two are different vox versions.
    #[error(
        "the node speaks a different control protocol (this vox is protocol {mine}, the node is \
         protocol {theirs}); update one of them"
    )]
    Protocol {
        /// The protocol this vox speaks.
        mine: u64,
        /// The protocol the node greeted with.
        theirs: u64,
    },
    /// What answered did not greet at all.
    #[error("what answered on the control socket did not greet like a vox node")]
    NotHello,
    /// The socket, or the process serving it, is not this user's: nothing is sent to it.
    #[error("refusing the control socket: {detail}")]
    NotYours {
        /// What was found instead.
        detail: String,
    },
    /// The node took the connection and then said nothing: it is suspended, or stuck. Waiting
    /// on it was forever (V210-83), since a suspended process's socket still accepts.
    #[error(
        "the node took the connection but did not answer within {secs} s: it may be suspended \
         (Ctrl-Z, SIGSTOP) or stuck. Resume it, or stop it and start it again"
    )]
    Silent {
        /// How long it was given.
        secs: u64,
    },
    /// A request was waiting, and a second connection then got no greeting: the node stopped
    /// answering while it worked on this one (V210-83).
    #[error(
        "the node stopped answering while this request waited: a new connection got no greeting \
         within {secs} s. It may be suspended (Ctrl-Z, SIGSTOP) or stuck. Resume it, or stop it \
         and start it again"
    )]
    StoppedAnswering {
        /// How long the new connection was given.
        secs: u64,
    },
    /// A request was waiting, and the node still greets, but its actor answered no ping: nothing
    /// sent to it will be answered (V210-83).
    #[error(
        "the node greets but has taken no command for {secs} s, so this request will not be \
         answered: it is stuck. Stop it and start it again"
    )]
    Stuck {
        /// How long the ping was given.
        secs: u64,
    },
}
