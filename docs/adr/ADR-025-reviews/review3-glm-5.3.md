[0m
> build · glm-5.3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m→ [0mRead docs/adr/ADR-025-reviews
[0m→ [0mRead docs/adr/ADR-025-reviews/review2-astra.md
[0m
[0m$ [0mwc -l /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/*.md
1761 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md
     307 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-glm-5.3.md
     412 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-kimi-k3.md
    4312 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-glm-5.3.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-kimi-k3.md
    3112 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
       6 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md
      12 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md
    9930 total
[0m
[0m✱ [0mGrep "^## (BLOCKER|MAJOR|MINOR|NIT|VERDICT)"[90m in docs/adr/ADR-025-reviews/review2-astra.md · 25 matches[0m
[0m
[0m$ [0mtail -5 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md; echo ---; cat /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md; echo ---; cat /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md; echo ---; cat /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-glm-5.3.md
The three changes I would most insist on:

1. **Make duplex reconciliation bounded and progress-making:** resolve bilateral send-before-read blockage, bound held streams locally, use compact coverage, and pace zero-progress retries.
2. **Specify the complete port transition lifecycle:** cancellation/retirement, permits, epochs/incarnations, monotonic completion credit, durable partial progress, backoff, and consent attribution.
3. **Rebuild S0b and the proofs together:** expose causal events, detect lost observations, isolate each mutant’s recovery path, and measure the actual base preconditions.
---
[0m
> build · glm-5.3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m→ [0mRead docs/adr/ADR-025-reviews
[0m→ [0mRead docs/adr/ADR-025-reviews/review2-astra.md
[0m
[0m$ [0mwc -l /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/*.md
1761 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md
     307 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-glm-5.3.md
     412 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-kimi-k3.md
    4312 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-glm-5.3.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-kimi-k3.md
    3112 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
       6 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md
      12 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md
    9930 total
[0m
[0m✱ [0mGrep "^## (BLOCKER|MAJOR|MINOR|NIT|VERDICT)"[90m in docs/adr/ADR-025-reviews/review2-astra.md · 25 matches[0m
---
[0m
> build · kimi-k3
[0m
[0m# [0mTodos
[•] Read ADR-025 revision 3 document
[ ] Read prior reviews (astra round 1+2, glm-5.3, kimi-k3)
[ ] Verify round-2 findings against rev 3 (RESOLVED/PARTIAL/NOT)
[ ] Verify code claims against 58fde36 and 8436100 trees
[ ] Attack Option C (full duplex) for corruption/deadlock/starvation
[ ] Check D2/D3/D5/D6/epoch rules and proof table
[ ] Write review: BLOCKER/MAJOR/MINOR/NIT + VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m$ [0mls -la /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/ && wc -l /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/*
total 1168
drwxr-xr-x@ 11 robert.lee  staff     352 Sep 26 17:59 .
drwxr-xr-x@ 32 robert.lee  staff    1024 Sep 26 12:25 ..
-rw-r--r--@  1 robert.lee  staff   85501 Sep 26 11:55 review-astra.md
-rw-r--r--@  1 robert.lee  staff   32827 Sep 26 12:05 review-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff   39080 Sep 26 12:12 review-kimi-k3.md
-rw-r--r--@  1 robert.lee  staff  230018 Sep 26 12:21 review2-astra.md
-rw-r--r--@  1 robert.lee  staff     101 Sep 26 12:16 review2-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff     101 Sep 26 12:17 review2-kimi-k3.md
-rw-r--r--@  1 robert.lee  staff  181496 Sep 26 12:29 review3-astra.md
-rw-r--r--@  1 robert.lee  staff    1103 Sep 26 18:00 review3-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff     509 Sep 26 18:00 review3-kimi-k3.md
    1761 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md
     307 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-glm-5.3.md
     412 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-kimi-k3.md
    4312 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-glm-5.3.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-kimi-k3.md
    3112 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
      19 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md
      13 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md
    9944 total
[0m
---
[0m
> build · glm-5.3
[0m
[91m[1mError: [0mUpstream request failed: Insufficient account funds
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review2-astra.md[90m [limit=180, offset=4133][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-astra.md[90m [limit=165, offset=2948][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '540,700p'
}

/// Map a parse/verify [`Error`] to the M0 wire application-error code (ADR-008
/// §"Abort / error signalling"). This is the single place the structured error
/// taxonomy is collapsed onto the coded wire contract, so an unknown struct
/// tag / unsupported version / unknown algo is **never** misreported as a generic
/// authenticator failure.
#[must_use]
pub fn wire_error_for(err: &Error) -> WireError {
    match err {
        Error::UnknownStructTag(_) => WireError::UnknownStructTag,
        Error::UnsupportedVersion { .. } => WireError::ProtocolVersionUnsupported,
        Error::UnknownAlgoId(_) | Error::UnexpectedAlgo { .. } => WireError::UnknownAlgoId,
        Error::SuiteBelowFloor { .. } => WireError::SuiteBelowFloor,
        // Signature/authenticator failures, malformed structures, the deniable
        // boundary, and oversize/CBOR malformation are all "this authenticator/
        // structure is not acceptable" → AuthenticatorInvalid. (Size limits are a
        // structural rejection; there is no dedicated size code in the M0 table.)
        _ => WireError::AuthenticatorInvalid,
    }
}

/// Map a DAG [`Rejected`] to the M0 wire application-error code.
#[must_use]
pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
    match rej {
        Rejected::NotAdmitted => WireError::EpochMismatch,
        Rejected::Verification(e) => wire_error_for(e),
        Rejected::Feed(_) => WireError::AuthenticatorInvalid,
        Rejected::Fork(_) => WireError::AuthenticatorInvalid,
        Rejected::GovernanceNotAttributable => WireError::AuthenticatorInvalid,
        // A duplicate is not a hard fail; callers handle it before mapping. If it
        // ever reaches here, treat as a benign authenticator-class rejection.
        Rejected::Duplicate => WireError::AuthenticatorInvalid,
    }
}

/// The outcome of applying a received `ENTRY` frame.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyOutcome {
    /// The entry was newly stored.
    Stored,
    /// The entry was a duplicate (idempotent — already held).
    Duplicate,
    /// The entry conflicted with a stored one at the same `(author, seq)`: a fork.
    /// This is a *local security event*, NOT a wire-protocol violation — it is
    /// recorded/surfaced (an attributable fork freezes the author; a deniable one
    /// raises an alarm) and sync **continues**. The stream is not closed for a
    /// fork (ADR-008 §"Fork / equivocation handling").
    Fork,
}

/// Apply a received `ENTRY` wire frame to the local [`Dag`] under the full
/// acceptance predicate.
///
/// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
/// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
/// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
/// (unknown tag, unsupported version, unknown algo, authenticator, …). A
/// **fork is not a wire fail**: it is surfaced and sync continues, so two
/// partitions can exchange conflicting heads and form the proof.
pub fn apply_entry<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    entry_wire: &[u8],
) -> std::result::Result<ApplyOutcome, WireError> {
    let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
    let key = resolver
        .key_for(&entry.skeleton.author_id)
        .ok_or(WireError::AuthenticatorInvalid)?;
    let kind = resolver.kind_for(&entry);
    match dag.accept(entry, kind, &key, admission) {
        Ok(_) => Ok(ApplyOutcome::Stored),
        Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
        // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
        // not close the stream.
        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
        Err(other) => Err(wire_error_for_rejected(&other)),
    }
}

/// Drive a complete **frontier-mode** session between two peers, each over its
/// own [`Transport`] endpoint, to convergence — exercising the real frame path
/// (`HELLO`/`HAVE`/`WANT`/`ENTRY`) over the abstract transport. `a` is the
/// initiator. `pump` moves frames between the two endpoints (for the in-memory
/// duplex it is [`DuplexTransport::pump`]; over QUIC the network is the pump).
/// Returns `(applied_into_a, applied_into_b)`.
///
/// Protocol per side: send `HELLO` (offering frontier); both compute and send
/// `HAVE`; each replies `WANT` for what it lacks; each streams the requested
/// `ENTRY` frames; each applies the entries it receives under the full acceptance
/// predicate. A malformed/unknown frame or a hard acceptance failure closes the
/// transport with the mapped [`WireError`].
#[allow(clippy::too_many_arguments)]
pub fn frontier_session<TA, TB, R, P>(
    ta: &mut TA,
    tb: &mut TB,
    a: &mut Dag,
    b: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    pump: P,
) -> std::result::Result<(usize, usize), WireError>
where
    TA: Transport,
    TB: Transport,
    R: AuthorResolver,
    P: FnMut(&mut TA, &mut TB) -> usize,
{
    // Centralized fail-and-close: ANY hard fail closes BOTH endpoints with the
    // exact coded reason (ADR-008 §"Abort / error signalling" — never a silent
    // downgrade, never an unclosed stream).
    match frontier_session_inner(ta, tb, a, b, resolver, admission, pump) {
        Ok(counts) => Ok(counts),
        Err(code) => {
            ta.close(code);
            tb.close(code);
            Err(code)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn frontier_session_inner<TA, TB, R, P>(
    ta: &mut TA,
    tb: &mut TB,
    a: &mut Dag,
    b: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    mut pump: P,
) -> std::result::Result<(usize, usize), WireError>
where
    TA: Transport,
    TB: Transport,
    R: AuthorResolver,
    P: FnMut(&mut TA, &mut TB) -> usize,
{
    let send_a = |t: &mut TA, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
    let send_b = |t: &mut TB, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    // 1. HELLO exchange + mode negotiation.
    send_a(ta, encode_hello(SYNC_MODE_FRONTIER))?;
    send_b(tb, encode_hello(SYNC_MODE_FRONTIER))?;
    pump(ta, tb);
    let a_remote_hello = expect_hello(ta.recv())?;
    let b_remote_hello = expect_hello(tb.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, a_remote_hello)?;
    negotiate_mode(SYNC_MODE_FRONTIER, b_remote_hello)?;

    // 2. HAVE exchange.
    send_a(ta, encode_have(&frontiers_of(a)))?;
    send_b(tb, encode_have(&frontiers_of(b)))?;
    pump(ta, tb);
    let a_sees = expect_have(ta.recv())?; // b's frontiers, seen by a
    let b_sees = expect_have(tb.recv())?; // a's frontiers, seen by b

    // 3. WANT exchange (each asks for what it lacks, including equal-seq forks).
    let a_wants = wants_for(a, &a_sees);
[0m
I've read the ADR and astra's round-2 findings (and note astra's round-3 review also exists). Now I'll verify the code claims against both trees.
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '700,960p'
let a_wants = wants_for(a, &a_sees);
    let b_wants = wants_for(b, &b_sees);
    send_a(ta, encode_want(&a_wants))?;
    send_b(tb, encode_want(&b_wants))?;
    pump(ta, tb);
    let a_got_want = expect_want(ta.recv())?; // what b wants from a
    let b_got_want = expect_want(tb.recv())?; // what a wants from b

    // 4. ENTRY streaming (each serves the other's WANT).
    for wire in entries_for_wants(a, &a_got_want) {
        send_a(ta, encode_entry(&wire))?;
    }
    for wire in entries_for_wants(b, &b_got_want) {
        send_b(tb, encode_entry(&wire))?;
    }
    pump(ta, tb);

    // 5. Apply received entries. A fork at an equal-seq divergent head surfaces
    //    here as the conflicting entry is fed into DAG fork handling; an
    //    attributable fork freezes the equivocator (its WireError is the coded
    //    close). Both peers drain independently.
    let into_a = drain_entries(ta, a, resolver, admission)?;
    let into_b = drain_entries(tb, b, resolver, admission)?;
    Ok((into_a, into_b))
}

/// Drive **one peer's** half of a frontier-mode session over a single
/// [`Transport`] endpoint, to completion. Unlike [`frontier_session`] (which pumps
/// both in-process duplex sides in one thread), this runs a single side over a
/// real bidirectional transport — the QUIC mapping (M9), where the network moves
/// bytes, so no `pump` is needed. Both peers are protocol-symmetric, so the same
/// function serves the initiator and the responder; run one on each peer
/// concurrently and both converge.
///
/// The phases mirror [`frontier_session`]: `HELLO` → `HAVE` → `WANT` → serve the
/// peer's `WANT` with `ENTRY` frames, then drain and apply the peer's `ENTRY`
/// frames. After serving its entries the peer half-closes its send direction
/// ([`Transport::close`] is **not** called on the success path — a clean
/// end-of-stream is signalled by [`Transport::recv`] returning `Ok(None)`), so the
/// drain loop terminates. A hard fail closes the transport with the mapped
/// [`WireError`].
///
/// Returns the number of entries newly applied into `dag`.
pub fn frontier_session_peer<T, R>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError>
where
    T: Transport,
    R: AuthorResolver,
{
    match frontier_session_peer_inner(t, dag, resolver, admission) {
        Ok(applied) => Ok(applied),
        Err(code) => {
            t.close(code);
            Err(code)
        }
    }
}

fn frontier_session_peer_inner<T, R>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError>
where
    T: Transport,
    R: AuthorResolver,
{
    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    // 1. HELLO exchange + mode negotiation.
    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    // 2. HAVE exchange.
    send(t, encode_have(&frontiers_of(dag)))?;
    let remote_have = expect_have(t.recv())?;

    // 3. WANT exchange (ask for what we lack, including equal-seq forks).
    let my_wants = wants_for(dag, &remote_have);
    send(t, encode_want(&my_wants))?;
    let their_wants = expect_want(t.recv())?;

    // 4. Serve their WANT with ENTRY frames, then signal end-of-stream by
    //    half-closing the send side via a benign close. We must NOT use
    //    `Transport::close` here (that is the hard-fail path); a clean FIN is the
    //    success terminator. The QUIC mapping finishes the send stream; the
    //    in-memory duplex relies on the drain loop observing an empty inbox.
    //    Bounded in count, bytes and time (see the module docs); stopping at the
    //    time bound is a clean end, not a failure — the peer keeps what it got.
    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
    for wire in entries_for_wants(dag, &their_wants) {
        if std::time::Instant::now() >= serve_deadline {
            break;
        }
        send(t, encode_entry(&wire))?;
    }
    // Signal a clean end-of-stream on our send side (success terminator, not a
    // hard close), so the peer's drain loop terminates at FIN.
    t.finish();

    // 5. Drain and apply the entries the peer serves us, until the peer's clean
    //    half-close (recv → Ok(None)).
    drain_entries(t, dag, resolver, admission)
}

/// What a frontier session may do to a room, **one step at a time**. Each method takes the room's
/// lock, does its step, releases the lock and returns owned data; none of them sees the transport.
/// [`frontier_session_room`] sees the transport and never the room. So no lock can be held across a
/// network wait, and the compiler keeps it that way: there is no scope in which both exist.
///
/// This replaces a session that held the room's mutex from its first frame to its last. A peer that
/// was slow to answer then held the room for up to the frame timeout, and every other use of the
/// room — a message being posted, the node's view being published after every event — waited
/// behind it (ADR-008's own implementation note named the fix).
pub trait SessionRoom {
    /// The room's frontiers, for `HAVE`.
    ///
    /// # Errors
    /// The room is unusable (poisoned, or moved to another epoch).
    fn frontiers(&self) -> std::result::Result<Vec<FeedFrontier>, WireError>;
    /// What to ask the peer for, given its `HAVE`.
    ///
    /// # Errors
    /// As [`SessionRoom::frontiers`].
    fn wants(&self, remote: &[FeedFrontier]) -> std::result::Result<Vec<WantRange>, WireError>;
    /// The entries to serve for the peer's `WANT` — owned and bounded.
    ///
    /// # Errors
    /// As [`SessionRoom::frontiers`].
    fn entries(&self, wants: &[WantRange]) -> std::result::Result<Vec<Vec<u8>>, WireError>;
    /// Apply a batch of received entries under a fresh lock, **against the room's current rules**: an
    /// author revoked while the batch was on the wire is refused, and a room that moved to another
    /// epoch refuses the whole batch. Returns how many were newly stored.
    ///
    /// # Errors
    /// A hard sync failure from an entry, or the room is unusable.
    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, WireError>;
}

/// How many received entries are staged before a batch is applied. Bounds what a session holds in
/// memory between locks; each batch is one short hold of the room.
pub const MAX_STAGED: usize = 256;

/// One peer's half of a frontier session, over `t`, against `room` — the same protocol as
/// [`frontier_session_peer`], with the room locked only inside each [`SessionRoom`] step and never
/// across a send or a receive.
///
/// # Errors
/// The coded [`WireError`] of a hard fail; the transport is closed with it.
pub fn frontier_session_room<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
where
    T: Transport,
    S: SessionRoom + ?Sized,
{
    match frontier_session_room_inner(t, room) {
        Ok(applied) => Ok(applied),
        Err(code) => {
            t.close(code);
            Err(code)
        }
    }
}

fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
where
    T: Transport,
    S: SessionRoom + ?Sized,
{
    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    send(t, encode_have(&room.frontiers()?))?;
    let remote_have = expect_have(t.recv())?;

    send(t, encode_want(&room.wants(&remote_have)?))?;
    let their_wants = expect_want(t.recv())?;

    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
    for wire in room.entries(&their_wants)? {
        if std::time::Instant::now() >= serve_deadline {
            break;
        }
        send(t, encode_entry(&wire))?;
    }
    t.finish();

    // Drained with no lock held; applied a batch at a time under a fresh one.
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    let mut staged: Vec<Vec<u8>> = Vec::new();
    let mut applied = 0;
    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
        if std::time::Instant::now() >= deadline {
            return Err(WireError::SyncModeUnsupported);
        }
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                staged.push(wire);
                if staged.len() >= MAX_STAGED {
                    applied += room.apply(std::mem::take(&mut staged))?;
                }
            }
            Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    if !staged.is_empty() {
        applied += room.apply(staged)?;
    }
    Ok(applied)
}

/// Apply staged entries into `dag`, returning how many were newly stored — the apply half of
/// [`SessionRoom::apply`], for a caller that already holds its room.
///
/// # Errors
/// The first hard sync failure.
pub fn apply_staged<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    staged: &[Vec<u8>],
) -> std::result::Result<usize, WireError> {
    let mut stored = 0;
    for wire in staged {
        if matches!(
            apply_entry(dag, resolver, admission, wire)?,
            ApplyOutcome::Stored
        ) {
            stored += 1;
        }
    }
    Ok(stored)
}

/// Read and apply every queued `ENTRY` frame on `t` into `dag`. A hard fail
/// returns the mapped [`WireError`]; the caller ([`frontier_session`]) performs
/// the coded stream close, so this function does not close itself (one central
/// fail-and-close path). An undecodable frame is a sync-protocol violation
/// (`SyncModeUnsupported`); an `ENTRY` that fails acceptance carries its own code
/// from [`apply_entry`].
fn drain_entries<T: Transport, R: AuthorResolver>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError> {
    let mut applied = 0;
    // **The whole phase is bounded, not just the gap between frames.**
    //
    // The transport's timeout is per frame, and this loop had no limit on how many frames it
    // would take, so a peer that sent one frame every nineteen seconds — forever — held this
    // room's lock for ever. The lock is taken for the entire session (see `sync_over`'s caller),
    // so that is every operation on the room stopped by one member, at no cost to it.
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '4700,4990p'
let bundles = net.board_bundles(channel_id, epoch);
        let known = self.board_authors.entry(*channel_id).or_default();
        let fresh = bundles.iter().filter(|b| known.insert(b.author_id)).count();
        if fresh == 0 {
            return;
        }
        if let Some(store) = self.profile.as_ref().map(Profile::store_handle) {
            let now = self.now();
            let mut channel = shared.lock().await;
            let _ = admit_board_records(
                &mut channel,
                &store,
                &bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now,
            )
            .await;
        }
        self.refresh_network_view().await;
        self.note_local_append(channel_id);
    }

    /// Whether a sync session with `peer` is running on `channel_id`: the collision a new
    /// session with that peer for that room must not start into (see `syncing`).
    fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
        self.syncing.contains(&(*channel_id, *peer))
    }

    /// Mark a channel as having a local append to push, and make every peer's
    /// schedule due (ADR-016: "a push immediately after a local append").
    fn note_local_append(&mut self, channel_id: &Digest32) {
        if self.net.is_none() {
            return;
        }
        self.push_now = true;
        self.pending_push.insert(*channel_id);
        // Something new: every peer is owed it again, including those that had the last one.
        self.pushed_to.remove(channel_id);
        for schedule in self.schedules.values_mut() {
            schedule.note_local_append();
        }
    }

    /// Run whatever the ADR-016 sync schedule says is due. Returns whether anything
    /// ran, so the caller only republishes the view when it might have changed.
    ///
    /// A peer with no live connection is skipped, not retried in place: it gets a
    /// fresh schedule when it reconnects.
    /// Re-run the ladder's publish side when the granted mappings are halfway through
    /// their lifetime, so a node that outlives a two-hour mapping stays dialable.
    ///
    /// Nothing happens while the network is down: the renewal instant is left in place
    /// so the next unlock's discovery supersedes it.
    ///
    /// The re-request runs on its own task (it talks to a gateway) and lands back as
    /// [`NetEvent::AddressesDiscovered`], which republishes the address records too —
    /// a renewal that came back with a *different* external port must be advertised.
    fn renew_mappings_if_due(&mut self) {
        let Some(due) = self.renew_mappings_at else {
            return;
        };
        if self.now() < due {
            return;
        }
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return;
        };
        // Cleared now, not when the refresh returns: one renewal in flight at a time.
        self.renew_mappings_at = None;
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let mappings = net.refresh_advertised().await;
            let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
        });
    }

    /// Push what a local append made due **now**, rather than at the next tick.
    ///
    /// A message was marked due by `note_local_append` and then waited for `TICK` — up to a full
    /// second — before anything sent it: PRD-001 R40 asks for chat under a second, and measured
    /// through the real binary the median was 322–894ms with a maximum of 1.021s, the tick's own
    /// shape. Run after the command or event that made the push due, and after its reply, so the
    /// command's own latency is unchanged.
    ///
    /// A burst coalesces for free: a room mid-session is owed rather than re-sent (see
    /// `run_due_syncs`), and the session's `SyncDone` re-arms this while pushes are still owed, so
    /// posts go out back to back instead of one per tick.
    async fn push_if_owed(&mut self) {
        if std::mem::take(&mut self.push_now) && self.run_due_syncs().await {
            self.publish().await;
        }
    }

    async fn run_due_syncs(&mut self) -> bool {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return false;
        };
        let now = self.now();
        let mut due: Vec<(Digest32, SyncTrigger)> = self
            .schedules
            .iter()
            .filter_map(|(peer, s)| s.due(now).map(|t| (*peer, t)))
            .collect();
        // **Owed peers first.** `schedules` is keyed by fingerprint, so without this every pass
        // visited peers in the same order, and one that sorted first and took the room each time
        // left the rest skipped each time. A stable sort keeps fingerprint order within each group.
        due.sort_by_key(|(peer, _)| !self.owed_first.contains(peer));
        for (peer, _) in &due {
            self.owed_first.remove(peer);
        }
        if due.is_empty() {
            return false;
        }
        let mut ran = false;
        // Which channels a local-append push actually got out. Everything else stays owed.
        let mut pushed: std::collections::BTreeSet<Digest32> = std::collections::BTreeSet::new();
        // Rooms any peer was skipped for because they were mid-session. Added to `pending_push`
        // only **after** the `retain` below — see there.
        let mut owed_rooms: std::collections::BTreeSet<Digest32> =
            std::collections::BTreeSet::new();
        for (peer, trigger) in due {
            if net.manager().existing(&peer).is_none() {
                continue;
            }
            // Which channels this pass covers: a local-append push touches only the
            // channels that changed; a connect or interval pass covers every channel
            // shared with this peer.
            let mut channels: Vec<Digest32> = Vec::new();
            // Rooms this pass wanted with this peer but found **already mid-session**. See the
            // `owed` handling after the loop: they are retried next tick, not forgotten.
            let mut owed: Vec<Digest32> = Vec::new();
            // A member reconciles a channel with its co-authors — and with that channel's
            // anchors, which keep the log for whoever is away (M15.2b). Both are decided per room
            // by `may_sync` below.

            // **Learn who this peer is before deciding we share nothing with it.**
            //
            // The filter below asks `is_author(&peer)`, and the thing that admits a newly joined
            // peer as an author — `learn_members`, reading the bundle records off this node's own
            // board — lives inside `sync_one`, which only runs for channels that already passed the
            // filter. So a peer that has just joined is skipped for having no entries, by the node
            // holding the evidence that it belongs, and the only code that would fix that sits
            // behind the check it is meant to satisfy. `learn_members`' own comment says reading
            // membership from the board "is a precondition for reconciling at all"; it was not one.
            //
            // The consequence, measured as a user: a message posted seconds after somebody joins is
            // **lost, not delayed** — the sender skips them, the connect trigger is consumed, and
            // the next chance is a full `SYNC_INTERVAL_SECS`. With the daemons settled, twelve posts
            // crossed twelve times in 0-1s; posting immediately after a join lost one in six even
            // after the owed-push fix below.
            //
            // Done only on a connect, not every tick: this reads the board and admits authors, which
            // is exactly the work a new connection warrants and would be waste on the interval.
            // Candidates first, decided after: the membership test below needs `&mut self` (it may
            // admit a member from this node's own board), which the maps cannot be borrowed across.
            let mut member_rooms: Vec<Digest32> = Vec::new();
            for cid in self.channels.keys() {
                if trigger == SyncTrigger::LocalAppend
                    && (!self.pending_push.contains(cid)
                        || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
                {
                    continue;
                }
                if self.in_session_with(cid, &peer) || self.publishing.contains(&(*cid, peer)) {
                    owed.push(*cid);
                    continue;
                }
                member_rooms.push(*cid);
            }
            // **A room goes only to a peer that belongs to it.** On a fresh connection this pushed
            // *every* open room to the peer — the inbound half of D5 refuses a non-member's request,
            // and this was the outbound half handing the same log over unasked. The bypass existed
            // because a peer that has just joined is not yet an author in this node's view;
            // `may_sync` covers that case properly, by admitting the peer from this node's own board
            // before deciding, which is the evidence the bypass was standing in for.
            //
            // **An anchor gets the rooms that name it, not every room** (V29-04, #39). An anchor was
            // pushed every room this node held because `anchor_ids` held it, and `anchor_ids` holds
            // the anchors named by ANY room's invite link: an anchor named only by room A's link was
            // handed room B's log unasked, while that anchor's own `may_sync` would have refused B
            // inbound. vox-bc's verifier reproduced it with real nodes: the other room's anchor was
            // pushed room B, one session and five entries. `may_sync` already accepts a room's own
            // anchors, and the configured ones are in every room's anchor set, so it decides alone.
            for cid in member_rooms {
                let belongs = {
                    let Some(epoch) = (match self.channels.get(&cid) {
                        Some(shared) => Some(shared.lock().await.epoch()),
                        None => None,
                    }) else {
                        continue;
                    };
                    self.may_sync(&cid, &peer, epoch).await
                };
                if belongs {
                    channels.push(cid);
                }
            }
            // An anchor forwards a room it keeps only to that room's authors — read fresh off its
            // own board first, so a member that has just been vouched for is not skipped. It used to
            // forward every kept room to any peer that connected or pushed.
            let mut kept_rooms: Vec<Digest32> = Vec::new();
            for cid in self.anchored.keys() {
                if trigger == SyncTrigger::LocalAppend
                    && (!self.pending_push.contains(cid)
                        || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
                {
                    continue;
                }
                if self.in_session_with(cid, &peer) {
                    owed.push(*cid);
                    continue;
                }
                kept_rooms.push(*cid);
            }
            for cid in kept_rooms {
                self.refresh_anchored_authors(&cid).await;
                let Some(state) = self.anchored.get(&cid).map(Arc::clone) else {
                    continue;
                };
                if state.lock().await.is_author(&peer) {
                    channels.push(cid);
                }
            }
            for channel_id in channels {
                if self.sync_one(&channel_id, peer).await {
                    ran = true;
                    // Any session carries the room's latest append, whatever triggered it.
                    self.pushed_to.entry(channel_id).or_default().insert(peer);
                    if trigger == SyncTrigger::LocalAppend {
                        pushed.insert(channel_id);
                    }
                }
            }
            if let Some(schedule) = self.schedules.get_mut(&peer) {
                schedule.note_synced(now);
                // **A room skipped because it was mid-session is owed, not synced.**
                //
                // The in-flight mark is per room, so when two peers came due for one room in the
                // same pass the first took it and the second was skipped — and `note_synced` above
                // then recorded the skipped peer as synced at the same `now` as the first. Both came
                // due together again, in the same `BTreeMap` order, and the same peer lost again:
                // **aligned once, aligned forever.** A local append makes every peer due at once, so
                // the alignment was the default after the first post, and which peer starved came
                // down to how the fingerprints sorted.
                //
                // Measured in `node_m15_anchor_gate` (instrumented, by the other session): in every
                // red, each member skipped the *other member* nine rounds running while its only
                // session — with the anchor — failed each time, so the one leg that could carry the
                // room never ran. Red about half the time in CI since before v0.2.5.
                //
                // Owed is not the unconditional retry the note on `pending_push` below warns
                // against: nothing here takes a lock, and it is retried only while that room is
                // mid-session, which is milliseconds. The next tick finds the room free.
                if !owed.is_empty() {
                    owed_rooms.extend(owed.iter().copied());
                    schedule.note_local_append();
                    self.owed_first.insert(peer);
                }
            }
        }
        // **Keep what did not go out.** This cleared unconditionally, which discarded the intent to
        // push an append whenever it had not actually been pushed — and the ordinary case is a peer
        // that has just joined: `note_local_append` marks "every peer's schedule due", but a peer
        // whose `NetEvent::Connected` the actor has not handled yet **has no schedule to mark**, so
        // nothing was owed to it and the entry was dropped rather than delayed. It then waited for
        // that peer's own `SYNC_INTERVAL_SECS`, and if that raced too, longer.
        //
        // Measured as a user: with the daemons settled, twelve posts crossed twelve times in 0-1s;
        // the proof that posts seconds after joining lost one in three.
        //
        // Note what is deliberately NOT changed: `note_synced` above still runs whether or not
        // anything went out. Making it conditional looks right and is wrong — it leaves the peer due
        // every tick, so one that cannot sync is retried once a second, each attempt taking the
        // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
        // hold on failure; what must survive is the work owed, which is this line.
        self.pending_push.retain(|cid| !pushed.contains(cid));
        // **After** the retain, or it undoes this. The skip happens in exactly the pass where the
        // room *was* pushed — to whichever peer took it first — so an owed room added inside the loop
        // was then removed here as "pushed", and the skipped peer's retry next tick found nothing
        // owed and dropped the push. It still arrived, on the next interval: up to 30s late instead
        // of immediately, and invisible to any gate that only asks whether it arrived. Found in
        // review by the other session.
        //
        // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
        // push to a peer whose session then fails is counted as done.
        self.pending_push.extend(owed_rooms);
        ran
    }

    /// Start reconciling one channel with one peer: learn who else has joined, then
    /// hand the channel to a detached session task.
[0m
sync.rs confirmed: serve-then-drain, `MAX_STAGED=256`, `SERVE_BUDGET`/`DRAIN_BUDGET` 30s each. Now the actor and scheduling code.
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '4990,5250p'
/// hand the channel to a detached session task.
    ///
    /// Returns whether a session was *started*. It is deliberately not awaited — see
    /// [`NetEvent::SyncDone`] for why awaiting deadlocks two nodes that start at the
    /// same moment. While the channel is away it is invisible to commands (they answer
    /// `UnknownChannel`) and, usefully, to this function, so a second pass cannot start
    /// a concurrent session for the same channel.
    async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return false;
        };
        let Some(conn) = net.manager().existing(&peer) else {
            return false;
        };
        let Some(store) = self.log_store() else {
            return false;
        };
        let target = match (
            self.channels.get(channel_id).map(Arc::clone),
            self.anchored.get(channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return false,
        };
        // An anchor's authors come from its own board, which is local: cheap, and it has to happen
        // before the session so the anchor can verify what arrives.
        if matches!(target, SessionTarget::Anchored(_)) {
            self.refresh_anchored_authors(channel_id).await;
        }
        if self.in_session_with(channel_id, &peer) {
            return false; // a session with this peer already has this room
        }
        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
            return false; // past the cap: skipped, not queued. The schedule comes round again.
        };
        self.syncing.insert((*channel_id, peer));
        let admit_store = self.profile.as_ref().map(Profile::store_handle);
        let cid = *channel_id;
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let _slot = slot;
            // 1. Learn who else has joined, or the first entry from a newer member kills the session
            //    (ADR-008). A round trip, so it belongs here and not on the actor.
            let epoch = match &target {
                SessionTarget::Channel(shared) => {
                    let known = shared.lock().await.epoch();
                    if let Some(pstore) = admit_store {
                        if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
                            {
                                let mut ch = shared.lock().await;
                                let _ = admit_board_records(
                                    &mut ch,
                                    &pstore,
                                    &set.bundles,
                                    ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                                    now,
                                )
                                .await;
                            }
                            // What the peer's board holds is filed on this node's own, so its board
                            // carries the whole membership it knows. Bundles go first: they carry
                            // the key an address record is verified with (M15.2a). Mirroring to the
                            // anchors follows on the actor when `SyncDone` lands, because that needs
                            // channel state.
                            for wire in set
                                .bundles
                                .iter()
                                .map(MemberBundleRecord::to_wire)
                                .chain(set.members.iter().map(RendezvousRecord::to_wire))
                            {
                                let _ = net.publish_local(&wire);
                            }
                            // **And the other way: what this node's board holds that the peer's
                            // lacks.** A member who joined through this node is on this node's
                            // board and no other, and the peer learned of it only when *it* next
                            // read this board, on its own periodic sync: 24–28 s for a third
                            // member to see a new one, measured. Offered here, a push that follows
                            // a join carries the newcomer to every connected member at once.
                            // Best-effort: a refusal (a record the peer's board already holds
                            // newer) costs nothing, and the peer's own sync still reads this board.
                            let missing = net.board_records_missing_from(&cid, known, &set);
                            if !missing.is_empty() {
                                if let Ok(mut client) =
                                    crate::nat::service::RendezvousClient::open(&conn).await
                                {
                                    for wire in &missing {
                                        if let Err(e) = client.put(wire).await {
                                            if !matches!(e, Error::RendezvousRejected(_)) {
                                                break;
                                            }
                                        }
                                    }
                                    client.finish();
                                }
                            }
                        }
                    }
                    shared.lock().await.epoch()
                }
                SessionTarget::Anchored(state) => state.lock().await.epoch(),
            };
            // 2. Open the stream. Also a round trip.
            //
            // **A stream that will not open still reports.** This returned without a word, and the
            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
            // marked mid-session for good: every later sync of it skipped, every inbound one
            // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
            let handle = tokio::runtime::Handle::current();
            let transport =
                match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::SyncDone {
                                channel_id: cid,
                                peer,
                                outcome: Err(e),
                            })
                            .await;
                        return;
                    }
                };
            // 3. Run the session. It takes the room's lock inside each protocol step and never across
            //    a send or a receive (`sync_over_room`), so a peer slow to answer no longer holds the
            //    room — or, through `publish()` and every other lock on it, the actor.
            let joined = tokio::task::spawn_blocking(move || {
                let mut t = transport;
                match target {
                    SessionTarget::Channel(shared) => {
                        crate::node::channel::ChannelState::sync_over_room(
                            &shared, &store, &mut t, now,
                        )
                    }
                    SessionTarget::Anchored(state) => {
                        crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
                    }
                }
            })
            .await;
            // A session that panicked still hands the room back: `Err` from the join is the panic.
            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
                "sync session panicked",
            )));
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id: cid,
                    peer,
                    outcome,
                })
                .await;
        });
        true
    }

    /// Take the channel out of the actor's map and run a session on its own task,
    /// returning it through [`NetEvent::SyncDone`].
    fn start_session(
        &mut self,
        channel_id: Digest32,
        peer: Digest32,
        transport: crate::transport::quic::QuicStreamTransport,
    ) {
        let Some(store) = self.log_store() else {
            return;
        };
        let target = match (
            self.channels.get(&channel_id).map(Arc::clone),
            self.anchored.get(&channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return,
        };
        // Marked here, past both early returns above, so a session that never starts never
        // leaves the room marked. Its caller used to mark it first.
        self.syncing.insert((channel_id, peer));
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let joined = tokio::task::spawn_blocking(move || {
                // The room is locked inside each protocol step only, never across the
                // network (`sync_over_room`).
                let mut t = transport;
                match target {
                    SessionTarget::Channel(shared) => {
                        crate::node::channel::ChannelState::sync_over_room(
                            &shared, &store, &mut t, now,
                        )
                    }
                    SessionTarget::Anchored(state) => {
                        crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
                    }
                }
            })
            .await;
            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
                "sync session panicked",
            )));
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id,
                    peer,
                    outcome,
                })
                .await;
        });
    }

    /// Reconcile a channel with every member this node can reach, now (the `Sync`
    /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let peers: Vec<Digest32> = {
            let channel = shared.lock().await;
            let me = channel.me();
            channel.members().into_iter().filter(|m| *m != me).collect()
        };
        let mut synced = 0usize;
        for peer in peers {
            if self.sync_one(channel_id, peer).await {
                synced += 1;
            }
        }
        if synced == 0 {
            return Outcome::Failed(Fault::Unreachable);
        }
        Outcome::Done
    }

    /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
    /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
    /// Serve one sync session for a request that has **already been read**.
    ///
    /// The preamble is read on the per-connection stream task (`node::network`), not here: the
    /// actor is the only writer of channel state and anything it awaits inline stops the whole
    /// node, so it must never wait on an untrusted peer to speak. What it does here is local
    /// and ordered, which is what the single-task design is for.
    /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
    /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
    /// of any room this node holds may — and the preamble then names whichever channel the
    /// peer likes. Nothing here checked the two against each other, so a member of room A who
    /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
    /// [`Self::may_sync`] for who counts.
    async fn run_sync_session(
        &mut self,
        peer: Digest32,
        channel_id: Digest32,
        epoch: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        use crate::node::syncstream::accept_sync;
        // Answering while our own session holds this room is the other half of the deadlock.
        //
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '5250,5400p'
//
        // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
        // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
        // silent refusal that reads as a hang, which is the shape of defect this whole change
        // exists to remove. A reset reaches it on the next read, and its schedule brings it
        // back in a second.
        //
        // **Refused before the lock, not after.** A session holds this room's mutex for its whole
        // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
        // behind the very session this check exists to detect.
        if self.in_session_with(&channel_id, &peer) {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        // Only a channel we hold open at that epoch — or keep as an anchor — can be
        // reconciled. An anchor whose board just received the genesis adopts it here
        // rather than making the member wait for the next tick.
        if !self.channels.contains_key(&channel_id) {
            self.adopt_anchored(&channel_id).await;
            self.refresh_anchored_authors(&channel_id).await;
        }
        let matches_epoch = match (
            self.channels.get(&channel_id),
            self.anchored.get(&channel_id),
        ) {
            (Some(shared), _) => shared.lock().await.epoch() == epoch,
            (None, Some(state)) => state.lock().await.epoch() == epoch,
            (None, None) => false,
        };

        // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
        // no log for it, most often — or at an epoch it is not at, returned here and let the streams
        // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
        // connection that died. Every push to an anchor that keeps no log for the room read as a
        // network fault. A coded reset says what happened. (It does not recover time: a dropped
        // stream already ended the initiator's session within milliseconds, measured; the long
        // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
        if !matches_epoch {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        if !self.may_sync(&channel_id, &peer, epoch).await {
            // Refused explicitly, with the same coded reset as a stream kind the peer may not
            // open, rather than left to read for a frame that never comes.
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
        self.start_session(channel_id, peer, transport);
    }

    /// Whether `peer` may reconcile `channel_id`'s log with this node.
    ///
    /// - An **admitted author** of that room. If it is not one yet, this node's own board is
    ///   consulted first — local, so cheap — because a member that joined through somebody
    ///   else is on the board before it is in this node's author table, and refusing it for
    ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
    ///   Admission there takes the same M17.6 evidence as everywhere else.
    /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
    ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
    ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
    ///   room's link is not an anchor of this one.
    ///
    /// For a room this node only anchors, the peer must be an author the board knows.
    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
            {
                let channel = shared.lock().await;
                if channel.is_author(peer)
                    || channel.anchors().nodes().iter().any(|a| a.id == *peer)
                {
                    return true;
                }
            }
            let (Some(net), Some(store)) = (
                self.net.as_ref().map(Arc::clone),
                self.profile.as_ref().map(Profile::store_handle),
            ) else {
                return false;
            };
            let bundles = net.board_bundles(channel_id, epoch);
            if !bundles.iter().any(|b| b.author_id == *peer) {
                return false;
            }
            let now = self.now();
            let mut channel = shared.lock().await;
            let _ = admit_board_records(
                &mut channel,
                &store,
                &bundles,
                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                now,
            )
            .await;
            return channel.is_author(peer);
        }
        if let Some(state) = self.anchored.get(channel_id) {
            return state.lock().await.is_author(peer);
        }
        false
    }

    /// Accept an inbound [`PairwiseFrame::Hello`], establishing the responder half of
    /// a session a peer opened from our bundle record. `true` if a session now exists.
    ///
    /// This is the join responder's PQXDH path minus the join: the message names a
    /// signed prekey and optionally a one-time prekey **from our own ring**, so a party
    /// holding no prekey of ours cannot open a session at all. The one-time prekey is
    /// consumed and the consume persisted before the handshake completes, so a crash
    /// here cannot leave it re-offerable; a replay is graded last-resort rather than
    /// silently accepted, the same reconciliation `joinstream` performs.
    ///
    /// An existing session is never replaced: a peer cannot reset our ratchet by
    /// sending a fresh `Hello`.
    async fn accept_hello(&mut self, channel_id: Digest32, peer: Digest32, initial: &[u8]) -> bool {
        let key = (channel_id, peer);
        let hello_hash = crate::hash::sha256(initial);
        let mut replaces = false;
        if self.sessions.contains_key(&key) {
            // The same hello again — the peer re-sending what we already accepted. The
            // session is the one we hold; accepting it twice would re-consume a one-time
            // prekey and reset a ratchet that is already in use.
            if self.accepted_hello.get(&key) == Some(&hello_hash) {
                return true;
            }
            // **Two sessions for one pair** (ADR-021 F12). Keep the one both ends will
            // keep. It used to keep whichever it held, and so did the peer — each kept its
            // own, and neither could open the key the other sent.
            let me = self.profile.as_ref().map(|p| p.fingerprint());
            let existing_mine = self.initiated.contains_key(&key);
            if let Some(me) = me {
                if !incoming_session_wins(&me, &peer, existing_mine) {
                    // Ours wins. The peer is holding its own, so it must be offered ours
                    // again: until it adopts it, nothing we seal can be opened there.
                    if let Some(i) = self.initiated.get_mut(&key) {
                        i.hello_delivered = false;
                    }
                    self.reopen.insert(key);
                    return false;
                }
            }
            replaces = true;
        }
        let Ok(init) = InitialMessage::from_wire(initial) else {
            return false;
        };
        let Some(shared) = self.channels.get(&channel_id).map(Arc::clone) else {
            return false;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "SyncDone\|retry_consent\|pending_consents\|note_synced\|fn due\|owed" | head -60
206:/// peer that went quiet mid-setup stopped the one task allowed to write channel state, for twenty
207:/// seconds, and the node answered nobody — including the pushes it had just marked owed.
221:/// through `NetEvent::SyncDone`, which is the seam that already exists for it.
226:/// of these, so the one task allowed to write channel state never waits on a network round trip. It
229:/// it answered nobody — including the pushes it had just marked owed. Measured on an anchor, which is
292:        NetEvent::SyncDone { .. } => "filing a sync that finished",
511:    /// looking like patience. Measured: a member whose own view showed `epoch-timeline=0` and no
583:    SyncDone {
598:    /// A sender key written to `peer` was not taken (see `pairwise_stream::refused`): it is owed
620:    /// the `SyncDone` handler, so two ends that collided do not retry together.
964:/// With that fixed (the owed-room change in `run_due_syncs`) the split exposed one real
1556:/// swallowed, which ADR-020 §7 forbids. If a third case is ever needed, every
1567:    /// Emission is never slowed by a slow subscriber, which is what makes this
1656:    /// With only `pending_push`, a room still owed to *one* peer was pushed again to *every* peer:
1657:    /// a member that had it already took the room again, and each `SyncDone` freed a room only for
1679:    /// decider's first real cross-machine join showed two of these and then `joined.`,
1723:    /// session for the room was refused and every push to them was owed. One dead member stalled a
1752:    /// A local append (or a finished session with pushes still owed) wants `run_due_syncs` now
1753:    /// rather than at the next tick. See `push_if_owed`.
1759:    /// reach this node's board (retried on the room's `SyncDone`). Each carries its attempts so
1762:    pending_consents: Vec<(Digest32, Digest32, oneshot::Sender<Outcome>, u8)>,
1771:    /// Peers that were skipped behind a busy room or had a push re-owed: served first on the next
1773:    owed_first: std::collections::BTreeSet<Digest32>,
1952:            pending_consents: Vec::new(),
1955:            owed_first: std::collections::BTreeSet::new(),
2043:                    // started lands: see `pending_consents`.
2050:                        self.push_if_owed().await;
2062:                    self.push_if_owed().await;
2070:                    self.push_if_owed().await;
2085:                    self.deliver_owed_rekeys().await;
2089:                    self.deliver_owed_consents(None).await;
2197:                // still names it, so `deliver_owed_consents` re-issues consent on the next
2571:                // **Said, not swallowed.** A refused bundle is a member no other member can admit as a
2944:        // **Not deferred while a session runs.** This used to be owed until the room had no
2949:        // with different members overlap, a busy room is never session-free, and the owed
3001:    /// it the one task allowed to write channel state. Measured on an anchor, which is the node this
3140:                // Whatever this member is owed goes out now that it can be reached, rather than on
3142:                self.answer_pending_consents(|_, target| *target == peer, None)
3144:                self.deliver_owed_rekeys().await;
3145:                self.deliver_owed_consents(None).await;
3201:                    self.deliver_owed_consents(None).await;
3271:                self.answer_pending_consents(
3363:                // The failed session carried nothing, so this peer is owed the room again.
3370:                self.owed_first.insert(peer);
3373:            NetEvent::SyncDone {
3379:                self.answer_pending_consents(|room, _| *room == channel_id, None)
3381:                // **A session that failed delivered nothing, so its push is owed again.**
3391:                // **Owed to that peer only, and not for ever.** The first version re-owed the room to
3393:                // an anchor that keeps no log for the room refuses every one — was then re-owed
3395:                // pass, and the member's owed push lost every round: the independent verdict
3421:                // is owed and goes at once. Gating this on success left an owed push waiting for the
3425:                    // A push that found this room mid-session is owed; the room is free now.
3465:                            Some(shared) => !shared.lock().await.owed_consents(&trusted).is_empty(),
3469:                            self.deliver_owed_consents(None).await;
3774:        self.deliver_owed_consents(None).await;
4226:        // someone, which is a human act, and `deliver_owed_consents` issues the grant.
4343:            // rides the next `SyncDone` of a session **with the target**. Checking for any session
4356:        self.pending_consents
4360:    /// Retry the explicit consents `matches` selects (`Dialed` passes its peer, `SyncDone` its
4362:    async fn answer_pending_consents(
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '3355,3440p'
// A session with that board for this room was held back while the round ran.
                self.push_now = true;
            }
            NetEvent::SkdmTaken { channel_id, peer } => {
                self.key_backoff.remove(&(channel_id, peer));
            }
            NetEvent::PushRetry { channel_id, peer } => {
                self.pending_push.insert(channel_id);
                // The failed session carried nothing, so this peer is owed the room again.
                if let Some(to) = self.pushed_to.get_mut(&channel_id) {
                    to.remove(&peer);
                }
                if let Some(schedule) = self.schedules.get_mut(&peer) {
                    schedule.note_local_append();
                }
                self.owed_first.insert(peer);
                self.push_now = true;
            }
            NetEvent::SyncDone {
                channel_id,
                peer,
                outcome,
            } => {
                self.syncing.remove(&(channel_id, peer));
                self.answer_pending_consents(|room, _| *room == channel_id, None)
                    .await;
                // **A session that failed delivered nothing, so its push is owed again.**
                // `run_due_syncs` counts a push as done when the session *starts*, which is the
                // only thing it can know then; a session the peer refused — because its own
                // session for this room was running — or that died on the wire carried nothing, and
                // the entry waited for the peer's next 30s interval. Measured over a forced relay
                // once pushes went out at once instead of on the tick: median 40–110ms, and a tail
                // at exactly 30s (p95 29.7–30.0s) — the collisions an immediate push makes more
                // likely. Owed again, retried on the *next tick* and not at once: a peer that keeps
                // refusing must not be answered with a tight loop.
                //
                // **Owed to that peer only, and not for ever.** The first version re-owed the room to
                // *every* peer, every time any session failed. A peer whose sessions always fail —
                // an anchor that keeps no log for the room refuses every one — was then re-owed
                // every tick, sorted ahead of the member it shared the room with, took the room each
                // pass, and the member's owed push lost every round: the independent verdict
                // measured 2–3 relayed runs in 10 losing a message for 120s (vox-bc, #41). Now the
                // retry goes to the peer that failed, at most `MAX_PUSH_RETRIES` times running; past
                // that the pair waits for the periodic interval like any other.
                //
                // **After a short random wait, not the next tick.** The commonest failure is a
                // collision: both ends push on the same event, each refuses the other because its
                // own session for the room is running, and both fail. Retried on the tick, the two
                // retries landed together again and a message took up to a second (median 364–531ms
                // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
                if outcome.is_err() {
                    let failures = self.push_failures.entry((channel_id, peer)).or_insert(0);
                    *failures = failures.saturating_add(1);
                    if *failures <= MAX_PUSH_RETRIES {
                        let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
                        let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
                        let tx = self.net_tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(wait).await;
                            let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
                        });
                    }
                } else {
                    self.push_failures.remove(&(channel_id, peer));
                }
                // The room is free now **whatever the outcome**: a push that found it mid-session
                // is owed and goes at once. Gating this on success left an owed push waiting for the
                // tick whenever the session that held the room failed — which a log-less anchor's
                // always does — and put a 1.00s ceiling on exactly the messages it delayed.
                if !self.pending_push.is_empty() {
                    // A push that found this room mid-session is owed; the room is free now.
                    self.push_now = true;
                }
                self.refresh_network_view().await;
                if let Ok(o) = outcome {
                    // **Event, not interval.** Propagation was event-driven in one direction only:
                    // an append here pushed at once, but a sync that *brought entries in* marked
                    // nothing, so this node sat on them until its own `SYNC_INTERVAL_SECS`. For an
                    // anchor that is the entire job undone — it holds the log for whoever is away and
                    // then forwards it a half-minute late. End to end the worst case was 30s to reach
                    // the anchor plus 30s for the next member to pull.
                    //
                    // Self-limiting rather than a storm: reconciliation is idempotent, so the peer
                    // this came from applies nothing on the way back and marks nothing onward.
                    // The actor-side half of what the slot just did: a session may have admitted
                    // authors and mirrored records onto this node's board, and both change who may
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '4330,4400p'
const MAX_CONSENT_ATTEMPTS: u8 = 3;
        if !matches!(outcome, Outcome::Failed(Fault::Unreachable))
            || attempts >= MAX_CONSENT_ATTEMPTS
        {
            let _ = reply.send(outcome);
            return;
        }
        let connected = self
            .net
            .as_ref()
            .is_some_and(|n| n.manager().existing(&target).is_some());
        if connected {
            // Started or not (a session with this same member may already be running), the retry
            // rides the next `SyncDone` of a session **with the target**. Checking for any session
            // on the room kept a consent waiting on sessions with other members, which, now that
            // sessions are guarded per (room, peer), need never all end.
            let _ = self.sync_one(&channel_id, target).await;
            if !self.in_session_with(&channel_id, &target) {
                let _ = reply.send(outcome);
                return;
            }
        } else if attempts > 0 {
            // A dial already landed once for this consent and the connection is gone again.
            let _ = reply.send(outcome);
            return;
        }
        self.pending_consents
            .push((channel_id, target, reply, attempts.saturating_add(1)));
    }

    /// Retry the explicit consents `matches` selects (`Dialed` passes its peer, `SyncDone` its
    /// room), or answer them all with `failed` (`ReachFailed`).
    async fn answer_pending_consents(
        &mut self,
        matches: impl Fn(&Digest32, &Digest32) -> bool,
        failed: Option<Outcome>,
    ) {
        let (waiting, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_consents)
            .into_iter()
            .partition(|(room, target, _, _)| matches(room, target));
        self.pending_consents = rest;
        if waiting.is_empty() {
            return;
        }
        for (channel_id, target, reply, attempts) in waiting {
            match failed {
                Some(o) => {
                    let _ = reply.send(o);
                }
                None => {
                    // Still waiting on its dial: that is `Dialed`'s or `ReachFailed`'s to answer, not
                    // a session with somebody else that happened to finish first.
                    let connected = self
                        .net
                        .as_ref()
                        .is_some_and(|n| n.manager().existing(&target).is_some());
                    if !connected {
                        self.pending_consents
                            .push((channel_id, target, reply, attempts));
                        continue;
                    }
                    let outcome = self.consent(&channel_id, target, false).await;
                    self.settle_consent(channel_id, target, reply, outcome, attempts)
                        .await;
                }
            }
        }
        // The view reflects whatever was granted before anyone reads it.
        self.publish().await;
    }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs | cat -n | sed -n '1,140p'
1	//! ADR-008 anti-entropy sync on a typed `sync` stream, and the schedule ADR-016
     2	//! specifies for it (§"Sync scheduling").
     3	//!
     4	//! The reconciliation engine is ADR-008's and is used unchanged; this module only
     5	//! opens/accepts the stream and states the policy:
     6	//!
     7	//! - **When.** A session per shared channel on every new connection
     8	//!   ([`SyncTrigger::Connected`]), every [`SYNC_INTERVAL_SECS`] while connected
     9	//!   ([`SyncTrigger::Periodic`]), and a push immediately after a local append
    10	//!   ([`SyncTrigger::LocalAppend`]). [`SyncSchedule`] is the pure clock-driven
    11	//!   decision, so the node's timer logic is testable without a network.
    12	//! - **Which mode.** Frontier mode until a channel exceeds
    13	//!   [`RANGE_MODE_AUTHOR_THRESHOLD`] authors, then range reconciliation
    14	//!   ([`should_use_range_mode`]) — the scale rule ADR-008 requires.
    15	//!
    16	//! ## The stream names its channel first
    17	//! A frontier session reconciles **one channel's** log, but a connection is per
    18	//! *peer* (ADR-016 §"Connections") and a peer may share several channels with us —
    19	//! so the ADR-008 frames alone are not enough to know which log to open. The
    20	//! initiator therefore sends a one-field preamble naming the `(channelID, epoch)`
    21	//! before handing the stream to the engine, exactly as the join stream does. The
    22	//! ADR-008 frame sequence itself is untouched; the channelID is not a secret (it is
    23	//! on the board and in the invite link) and the preamble is inside the authenticated
    24	//! stream regardless.
    25	//!
    26	//! ## Blocking, deliberately
    27	//! ADR-008's engine is synchronous, and [`QuicStreamTransport`] bridges it onto
    28	//! async quinn with [`tokio::runtime::Handle::block_on`]. A session therefore runs
    29	//! on a thread that may block — `tokio::task::spawn_blocking` in the node, a plain
    30	//! thread in tests — never inside an async task on a runtime worker.
    31	
    32	use quinn::{RecvStream, SendStream};
    33	use tokio::runtime::Handle;
    34	
    35	use crate::cbor::{Decoder, Encoder};
    36	use crate::error::{Error, Result};
    37	use crate::hash::Digest32;
    38	use crate::transport::framing::{read_frame, write_frame};
    39	use crate::transport::quic::{QuicStreamTransport, VoxConnection};
    40	use crate::transport::streams::{open_typed, StreamKind};
    41	
    42	/// Seconds between periodic sync sessions with a connected peer (ADR-016).
    43	pub const SYNC_INTERVAL_SECS: u64 = 30;
    44	
    45	/// Author count above which a channel reconciles in **range** mode instead of
    46	/// frontier mode (ADR-008 at scale).
    47	pub const RANGE_MODE_AUTHOR_THRESHOLD: usize = 100;
    48	
    49	/// Whether a channel with `authors` admitted authors should use range
    50	/// reconciliation rather than frontier mode.
    51	#[must_use]
    52	pub fn should_use_range_mode(authors: usize) -> bool {
    53	    authors > RANGE_MODE_AUTHOR_THRESHOLD
    54	}
    55	
    56	/// Why a sync session is being run.
    57	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    58	pub enum SyncTrigger {
    59	    /// A connection to this peer was just established.
    60	    Connected,
    61	    /// The periodic interval elapsed.
    62	    Periodic,
    63	    /// This node appended locally and is pushing it out.
    64	    LocalAppend,
    65	}
    66	
    67	/// The per-peer sync clock (ADR-016 §"Sync scheduling"), as a pure function of
    68	/// time and local appends so it can be tested without a network.
    69	#[derive(Debug, Clone, Copy)]
    70	pub struct SyncSchedule {
    71	    last_sync: u64,
    72	    pending_append: bool,
    73	}
    74	
    75	impl SyncSchedule {
    76	    /// A schedule for a peer that has just connected: the first session is due
    77	    /// immediately.
    78	    #[must_use]
    79	    pub fn connected() -> Self {
    80	        Self {
    81	            last_sync: 0,
    82	            pending_append: false,
    83	        }
    84	    }
    85	
    86	    /// Record a local append: the next check pushes it out without waiting for the
    87	    /// interval.
    88	    pub fn note_local_append(&mut self) {
    89	        self.pending_append = true;
    90	    }
    91	
    92	    /// Record that a session ran at `now_secs`.
    93	    pub fn note_synced(&mut self, now_secs: u64) {
    94	        self.last_sync = now_secs;
    95	        self.pending_append = false;
    96	    }
    97	
    98	    /// The trigger due at `now_secs`, if any. A local append wins over the
    99	    /// interval, and the first call after [`SyncSchedule::connected`] is
   100	    /// `Connected`.
   101	    #[must_use]
   102	    pub fn due(&self, now_secs: u64) -> Option<SyncTrigger> {
   103	        if self.last_sync == 0 {
   104	            return Some(SyncTrigger::Connected);
   105	        }
   106	        if self.pending_append {
   107	            return Some(SyncTrigger::LocalAppend);
   108	        }
   109	        if now_secs.saturating_sub(self.last_sync) >= SYNC_INTERVAL_SECS {
   110	            return Some(SyncTrigger::Periodic);
   111	        }
   112	        None
   113	    }
   114	}
   115	
   116	impl Default for SyncSchedule {
   117	    fn default() -> Self {
   118	        Self::connected()
   119	    }
   120	}
   121	
   122	/// The largest sync preamble either side will read (`[channel_id, epoch]`).
   123	const MAX_SYNC_PREAMBLE: usize = 64;
   124	
   125	/// Open a `sync`-typed bi-stream on `conn` for one channel and wrap it as the
   126	/// ADR-008 transport. The kind frame is written first so the peer dispatches it,
   127	/// then the preamble naming the channel (see the module docs).
   128	pub async fn open_sync(
   129	    conn: &VoxConnection,
   130	    handle: Handle,
   131	    channel_id: &Digest32,
   132	    epoch: u64,
   133	) -> Result<QuicStreamTransport> {
   134	    let (mut send, recv) = open_typed(conn, StreamKind::Sync).await?;
   135	    let mut e = Encoder::new();
   136	    e.array(2).bytes(channel_id).uint(epoch);
   137	    write_frame(&mut send, &e.finish()).await?;
   138	    Ok(QuicStreamTransport::new(handle, send, recv))
   139	}
   140
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | cat -n | sed -n '200,240p'; echo ====; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | cat -n | sed -n '2660,2740p'
200	    fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey> {
   201	        self.authors.get(author).cloned()
   202	    }
   203	
   204	    fn kind_for(&self, entry: &Entry) -> EntryKind {
   205	        // A governance payload is a struct-tagged frame, a sender-key message is
   206	        // domain-prefixed. A payload that is neither, or a pruned one (which cannot
   207	        // be classified at all), falls back to `Content` — the conservative choice,
   208	        // since governance entries must retain their payload (ADR-008) and so are
   209	        // never the pruned case.
   210	        entry
   211	            .payload
   212	            .as_deref()
   213	            .and_then(|p| classify_payload(p).ok())
   214	            .unwrap_or(EntryKind::Content)
   215	    }
   216	}
   217	
   218	/// What one [`ChannelState::sync_over`] session did.
   219	#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
   220	pub struct SyncOutcome {
   221	    /// Entries the ADR-008 session applied to the log.
   222	    pub applied: usize,
   223	    /// How many of those were governance entries folded into the evaluator.
   224	    pub governance: usize,
   225	    /// How many of those were decrypted and rendered into the timeline.
   226	    pub rendered: usize,
   227	}
   228	
   229	/// What [`ChannelState::accept_entry`] did with a peer's entry.
   230	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
   231	pub enum Accepted {
   232	    /// A governance entry: verified, stored, and folded into the evaluator.
   233	    Governance,
   234	    /// A content entry: verified and stored, but not readable — this node holds no
   235	    /// sender key for that author yet, or that author has not consented to this
   236	    /// identity (ADR-007: consent, not credentials, grants reading).
   237	    ContentNotReadable,
   238	    /// A content entry that was decrypted and rendered into the timeline.
   239	    Rendered,
   240	}
zsh:1: === not found
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | cat -n | sed -n '2640,2760p'
2640	    }
  2641	
  2642	    /// Whether this channel can currently answer an inbound join.
  2643	    #[must_use]
  2644	    pub fn can_answer_join(&self) -> bool {
  2645	        !self.passphrase.is_empty()
  2646	    }
  2647	}
  2648	
  2649	/// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
  2650	/// lets go. See [`ChannelState::sync_over_room`].
  2651	struct ChannelSessionRoom<'a> {
  2652	    shared: &'a tokio::sync::Mutex<ChannelState>,
  2653	    store: &'a Store,
  2654	    now_secs: u64,
  2655	    /// The epoch the session began at; a room that has moved on refuses what was staged for it.
  2656	    epoch: u64,
  2657	    out: std::cell::RefCell<SyncOutcome>,
  2658	    /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
  2659	    fatal: std::cell::RefCell<Option<Error>>,
  2660	}
  2661	
  2662	impl ChannelSessionRoom<'_> {
  2663	    fn room(
  2664	        &self,
  2665	    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
  2666	    {
  2667	        let ch = self.shared.blocking_lock();
  2668	        if ch.poisoned {
  2669	            return Err(crate::wire::WireError::TransportFailed);
  2670	        }
  2671	        if ch.epoch != self.epoch {
  2672	            return Err(crate::wire::WireError::EpochMismatch);
  2673	        }
  2674	        Ok(ch)
  2675	    }
  2676	}
  2677	
  2678	impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
  2679	    fn frontiers(
  2680	        &self,
  2681	    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
  2682	        Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
  2683	    }
  2684	
  2685	    fn wants(
  2686	        &self,
  2687	        remote: &[crate::log::sync::FeedFrontier],
  2688	    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
  2689	        Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
  2690	    }
  2691	
  2692	    fn entries(
  2693	        &self,
  2694	        wants: &[crate::log::sync::WantRange],
  2695	    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
  2696	        Ok(crate::log::sync::entries_for_wants(
  2697	            &self.room()?.dag,
  2698	            wants,
  2699	        ))
  2700	    }
  2701	
  2702	    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
  2703	        let mut guard = self.room()?;
  2704	        let ch = &mut *guard;
  2705	        let before = ch.heads();
  2706	        // The resolver as it is *now*: an author revoked while this batch was on the wire is not
  2707	        // an author of this room any more, and its entries are refused.
  2708	        let resolver = ch.resolver();
  2709	        // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
  2710	        // at a time and stops at the first it refuses; those before it are already in the log.
  2711	        // Returning the refusal first skipped persisting and rendering them, yet the log now held
  2712	        // them, so every later session saw nothing to send and they were never shown: one joiner
  2713	        // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
  2714	        // refusal was the other joiner's entry, from an author this node had not admitted yet.
  2715	        // `sync_over` always did it in this order ("reconciliation done; only now surface a
  2716	        // session failure"); the per-step path lost it.
  2717	        let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
  2718	        match ch.absorb_arrived(self.store, &before, self.now_secs) {
  2719	            Ok(got) => {
  2720	                let mut out = self.out.borrow_mut();
  2721	                out.rendered += got.rendered;
  2722	                out.governance += got.governance;
  2723	                stored
  2724	            }
  2725	            Err(e) => {
  2726	                *self.fatal.borrow_mut() = Some(e);
  2727	                Err(crate::wire::WireError::TransportFailed)
  2728	            }
  2729	        }
  2730	    }
  2731	}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | cat -n | sed -n '395,430p'
395	    }
   396	    let genesis = Genesis::from_wire(d.bytes()?)?;
   397	    let authors = parse_authors(d.bytes()?)?;
   398	    d.finish()?;
   399	    Ok((genesis, authors))
   400	}
   401	
   402	/// An anchored copy as a [`crate::log::sync::SessionRoom`]; see `AnchorState::sync_over_room`.
   403	struct AnchorSessionRoom<'a> {
   404	    shared: &'a tokio::sync::Mutex<AnchorState>,
   405	    store: &'a Store,
   406	    epoch: u64,
   407	    out: std::cell::RefCell<SyncOutcome>,
   408	    fatal: std::cell::RefCell<Option<Error>>,
   409	}
   410	
   411	impl AnchorSessionRoom<'_> {
   412	    fn copy(
   413	        &self,
   414	    ) -> std::result::Result<tokio::sync::MutexGuard<'_, AnchorState>, crate::wire::WireError> {
   415	        let st = self.shared.blocking_lock();
   416	        if st.poisoned {
   417	            return Err(crate::wire::WireError::TransportFailed);
   418	        }
   419	        if st.epoch != self.epoch {
   420	            return Err(crate::wire::WireError::EpochMismatch);
   421	        }
   422	        Ok(st)
   423	    }
   424	}
   425	
   426	impl crate::log::sync::SessionRoom for AnchorSessionRoom<'_> {
   427	    fn frontiers(
   428	        &self,
   429	    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
   430	        Ok(crate::log::sync::frontiers_of(&self.copy()?.dag))
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 rev-parse HEAD; git -C /opt/vox/.claude/worktrees/ac-fix202 status --porcelain | head -5
843610005df17ecac6d3d803adeed12491f21654
[0m
Now the #202 tree (working tree at 8436100).
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs | sed -n '1,130p'
1	//! The real M5 [`Transport`] over a reliable QUIC
     2	//! bi-stream.
     3	//!
     4	//! M5 frames are opaque byte vectors; here they are length-delimited on the stream
     5	//! with the [`crate::transport::framing`] 4-byte big-endian length prefix so the
     6	//! byte stream is re-segmented into exactly the frames M5 sent. The synchronous M5
     7	//! sync engine is bridged onto async quinn via a tokio runtime [`Handle`].
     8	
     9	use std::time::Duration;
    10	
    11	use quinn::{RecvStream, SendStream};
    12	use tokio::runtime::Handle;
    13	
    14	use crate::error::{Error, Result};
    15	use crate::log::sync::Transport;
    16	use crate::transport::framing::{read_frame, write_frame};
    17	use crate::transport::quic::{close_code, VoxConnection, MAX_STREAM_FRAME};
    18	use crate::wire::WireError;
    19	
    20	/// How long one sync frame may take to arrive or to be accepted for sending before
    21	/// the session is failed.
    22	///
    23	/// A session runs with the channel's lock held (the ADR-008 engine is synchronous
    24	/// over channel state), so a peer that stops answering — its actor busy, its
    25	/// network gone — would otherwise hold that lock for as long as it liked, and every
    26	/// other use of the channel on this node would wait behind it: a join to answer, a
    27	/// key to take, a message to send. Twenty seconds is far longer than any real
    28	/// exchange and shorter than anyone waits.
    29	pub const SYNC_FRAME_TIMEOUT: Duration = Duration::from_secs(20);
    30	
    31	/// A [`sync::Transport`](crate::log::sync::Transport) over one reliable QUIC
    32	/// bi-stream, bridging the synchronous M5 sync engine onto async quinn via a tokio
    33	/// runtime [`Handle`].
    34	///
    35	/// M5 frames are opaque byte vectors; here they are length-delimited on the stream
    36	/// with a 4-byte big-endian length prefix so the byte stream is re-segmented into
    37	/// exactly the frames M5 sent. `recv` returns `Ok(None)` on a clean peer
    38	/// half-close (FIN). A hard [`WireError`] close resets the stream with the mapped
    39	/// QUIC code.
    40	pub struct QuicStreamTransport {
    41	    handle: Handle,
    42	    send: SendStream,
    43	    recv: RecvStream,
    44	    /// Set once closed so further sends fail (mirrors the M5 duplex contract).
    45	    closed: Option<WireError>,
    46	    /// Per-frame bound on both directions; see [`SYNC_FRAME_TIMEOUT`].
    47	    frame_timeout: Duration,
    48	}
    49	
    50	impl QuicStreamTransport {
    51	    /// Wrap an opened `(SendStream, RecvStream)` pair, bridged onto `handle`, with
    52	    /// the standard [`SYNC_FRAME_TIMEOUT`].
    53	    #[must_use]
    54	    pub fn new(handle: Handle, send: SendStream, recv: RecvStream) -> Self {
    55	        Self::with_timeout(handle, send, recv, SYNC_FRAME_TIMEOUT)
    56	    }
    57	
    58	    /// [`QuicStreamTransport::new`] with an explicit per-frame bound.
    59	    #[must_use]
    60	    pub fn with_timeout(
    61	        handle: Handle,
    62	        send: SendStream,
    63	        recv: RecvStream,
    64	        frame_timeout: Duration,
    65	    ) -> Self {
    66	        Self {
    67	            handle,
    68	            send,
    69	            recv,
    70	            closed: None,
    71	            frame_timeout,
    72	        }
    73	    }
    74	
    75	    /// Open a new bi-stream on `conn` and wrap it (initiator side).
    76	    pub async fn open(handle: Handle, conn: &VoxConnection) -> Result<Self> {
    77	        let (send, recv) = conn.open_stream().await?;
    78	        Ok(Self::new(handle, send, recv))
    79	    }
    80	
    81	    /// Accept the next bi-stream on `conn` and wrap it (responder side).
    82	    pub async fn accept(handle: Handle, conn: &VoxConnection) -> Result<Self> {
    83	        let (send, recv) = conn.accept_stream().await?;
    84	        Ok(Self::new(handle, send, recv))
    85	    }
    86	}
    87	
    88	impl Transport for QuicStreamTransport {
    89	    fn send(&mut self, frame: &[u8]) -> Result<()> {
    90	        if self.closed.is_some() {
    91	            return Err(Error::Unreachable("quic transport: send after close"));
    92	        }
    93	        let send = &mut self.send;
    94	        let bound = self.frame_timeout;
    95	        self.handle
    96	            .block_on(async move {
    97	                tokio::time::timeout(bound, write_frame(send, frame))
    98	                    .await
    99	                    .map_err(|_| Error::Unreachable("sync: peer stopped taking frames"))
   100	            })
   101	            .and_then(|r| r)
   102	    }
   103	
   104	    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
   105	        // A clean FIN exactly at a frame boundary is the peer's success
   106	        // half-close → `Ok(None)`; anything else is a real transport failure.
   107	        let recv = &mut self.recv;
   108	        let bound = self.frame_timeout;
   109	        self.handle
   110	            .block_on(async move {
   111	                tokio::time::timeout(bound, read_frame(recv, MAX_STREAM_FRAME))
   112	                    .await
   113	                    .map_err(|_| Error::Unreachable("sync: peer went quiet"))
   114	            })
   115	            .and_then(|r| r)
   116	    }
   117	
   118	    fn close(&mut self, code: WireError) {
   119	        if self.closed.is_some() {
   120	            return;
   121	        }
   122	        self.closed = Some(code);
   123	        // Reset the send side with the mapped QUIC code, and stop the recv side.
   124	        let _ = self.send.reset(close_code(code));
   125	        let _ = self.recv.stop(close_code(code));
   126	    }
   127	
   128	    fn finish(&mut self) {
   129	        if self.closed.is_some() {
   130	            return;
[0m
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs | sed -n '150,300p'
150	/// How long opening a stream may wait for the peer to grant one. Stream credit on a live
   151	/// connection is immediate; the only thing this waits for is a peer that is not granting it, so
   152	/// it is sized like a frame read (`SYNC_FRAME_TIMEOUT`, 20s) rather than a handshake.
   153	const OPEN_STREAM_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);
   154	
   155	/// How often a silent connection sends a keep-alive.
   156	///
   157	/// Comfortably under half [`MAX_IDLE_MS`], so a single lost keep-alive cannot expire the
   158	/// connection — the ratio iroh uses for the same reason (25s against a 35s idle timeout in
   159	/// `iroh-relay`). Without this quinn sends nothing on an idle path and the connection dies
   160	/// at the idle timeout, which for a tunnel means a person's session dropping while they
   161	/// read.
   162	pub(crate) const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(20);
   163	
   164	/// The largest UDP payload a Vox endpoint accepts, and the ceiling path-MTU discovery
   165	/// searches up to (PRD-001 R41).
   166	///
   167	/// quinn's default ceiling is 1452 — Ethernet's — so every path, loopback and jumbo-frame
   168	/// links included, ran at 1452-byte packets, and a tunnel on this machine spent most of its
   169	/// time in one `sendmsg` per packet: profiled, the sending node sat in `__sendmsg` and in
   170	/// the connection lock that `sendmsg` is made under, with encryption at a few percent.
   171	/// Discovery is probing, not assuming: a path that will not carry a larger packet loses the
   172	/// probe and keeps what it had, so a 1500-byte link is exactly where it was.
   173	///
   174	/// **8192, not the loopback MTU (16384).** macOS refuses a UDP datagram over
   175	/// `net.inet.udp.maxdgram` (9216 by default), and with the ceiling at 16356 connections
   176	/// failed outright on this machine rather than falling back — measured, not reasoned. 8192
   177	/// stays under that limit on every platform Vox builds for.
   178	pub const MAX_UDP_PAYLOAD: u16 = 8_192;
   179	
   180	/// The UDP socket buffers a node asks for, each way.
   181	///
   182	/// The OS default (768 KiB receive on macOS) overflowed during a burst, and a large packet
   183	/// lost to overflow reads to quinn as a black hole: it drops the path MTU back to 1200 and
   184	/// does not probe again for a minute. Measured with the larger ceiling and larger stream
   185	/// windows (an experiment since dropped): without these buffers the MTU fell back to 1200 in
   186	/// 3 of 3 runs (`black_holes_detected` 1–9); with them, 0 black holes in 3 of 3.
   187	/// The OS may grant less, and Linux does so silently (`net.core.rmem_max`); that is not an
   188	/// error, but it decides the path-MTU ceiling (`mtu_ceiling_for`).
   189	const UDP_SOCKET_BUFFER: usize = 4 << 20;
   190	
   191	/// Per-stream flow-control window (and half the connection's send window), sized for the
   192	/// bandwidth-delay product of a 1 Gbit/s path at ~130 ms, or 10 Gbit/s at ~13 ms.
   193	pub const STREAM_WINDOW: u32 = 16 << 20;
   194	
   195	/// Flow-control credit a peer gets for the whole connection, across all its streams: what this
   196	/// node will buffer for one peer that sends and is not read.
   197	///
   198	/// quinn's default is unlimited, which is safe only while the per-stream window is small. At
   199	/// [`STREAM_WINDOW`] a peer may open quinn's default 100 concurrent bidirectional streams, so an
   200	/// unlimited connection window let one peer park 100 × 16 MiB = 1.6 GiB in this node's memory
   201	/// by writing into streams nobody reads. Two full stream windows keeps a single tunnel at full
   202	/// speed, and lets a second one run beside it.
   203	pub const CONNECTION_WINDOW: u32 = 2 * STREAM_WINDOW;
   204	
   205	/// quinn's own path-MTU ceiling (`MtuDiscoveryConfig::default().upper_bound`): 1500-byte Ethernet
   206	/// less IPv6 and UDP headers. What an endpoint falls back to when its socket cannot take the
   207	/// bursts [`MAX_UDP_PAYLOAD`] brings.
   208	pub const DEFAULT_UDP_PAYLOAD: u16 = 1_452;
   209	
   210	/// The path-MTU ceiling for a socket whose receive buffer is `effective` bytes, as the OS
   211	/// reports it after `UDP_SOCKET_BUFFER` was asked for, and why.
   212	///
   213	/// **The 8192 ceiling needs the buffer it was measured with.** A burst of large datagrams that
   214	/// overflows the receive buffer loses a run of large packets and nothing small, which is exactly
   215	/// what quinn's black-hole detector looks for: it drops the path to 1200 bytes, below the 1452 a
   216	/// stock endpoint keeps, and does not probe again for a minute. On macOS the 768 KiB default did
   217	/// that in 3 of 3 runs and the 4 MiB buffer in 0 of 3. Linux, though, caps `SO_RCVBUF` at
   218	/// `net.core.rmem_max` without an error (about 208 KiB by default; only `CAP_NET_ADMIN` can
   219	/// exceed it), so an endpoint there ran the 8192 ceiling on a tenth of the buffer, and CI's
   220	/// loopback proof pinned the dialler at 1200.
   221	///
   222	/// So the larger ceiling is taken only when the buffer the OS actually granted is at least the
   223	/// one it was measured with, read back in each OS's own units (`GRANTED_WHEN_FULL`):
   224	/// - **Linux** reports twice what it granted (it counts its own bookkeeping): the read-back is
   225	///   `2 × min(requested, net.core.rmem_max)`. A full grant reads as 8 MiB, and a cap at the
   226	///   default reads as about 416 KiB. Comparing against 4 MiB there would be wrong: a host with
   227	///   `rmem_max` between 2 and 4 MiB reads back 4–8 MiB and would take 8192 on half the buffer.
   228	/// - **Other platforms** (macOS) report what they granted.
   229	///
   230	/// Anything short keeps quinn's default ceiling, which is what every other QUIC endpoint on that
   231	/// host runs with.
   232	#[must_use]
   233	pub fn mtu_ceiling_for(effective: usize) -> (u16, &'static str) {
   234	    if effective >= GRANTED_WHEN_FULL {
   235	        (
   236	            MAX_UDP_PAYLOAD,
   237	            "the receive buffer takes a burst of 8192-byte datagrams",
   238	        )
   239	    } else {
   240	        (
   241	            DEFAULT_UDP_PAYLOAD,
   242	            "the OS granted a smaller receive buffer than 8192-byte datagrams need \
   243	             (on Linux, raise net.core.rmem_max to at least 4 MiB)",
   244	        )
   245	    }
   246	}
   247	
   248	/// What `SO_RCVBUF` reads back when the full `UDP_SOCKET_BUFFER` was granted: Linux doubles the
   249	/// value it stores (`sock_setsockopt`: `sk_rcvbuf = 2 * min(val, rmem_max)`), other platforms do
   250	/// not.
   251	#[cfg(target_os = "linux")]
   252	const GRANTED_WHEN_FULL: usize = 2 * UDP_SOCKET_BUFFER;
   253	#[cfg(not(target_os = "linux"))]
   254	const GRANTED_WHEN_FULL: usize = UDP_SOCKET_BUFFER;
   255	
   256	/// The endpoint parameters every Vox endpoint runs with.
   257	fn endpoint_config(mtu_ceiling: u16) -> quinn::EndpointConfig {
   258	    let mut cfg = quinn::EndpointConfig::default();
   259	    let _ = cfg.max_udp_payload_size(mtu_ceiling);
   260	    cfg
   261	}
   262	
   263	/// The transport parameters every Vox connection runs with, in both directions.
   264	fn transport_config(mtu_ceiling: u16) -> Arc<quinn::TransportConfig> {
   265	    let mut cfg = quinn::TransportConfig::default();
   266	    cfg.keep_alive_interval(Some(KEEP_ALIVE));
   267	    // `From<VarInt>` rather than `try_from(Duration)`: the millisecond value is a compile-
   268	    // time constant inside the varint range, so there is no error case to handle.
   269	    cfg.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
   270	        MAX_IDLE_MS,
   271	    ))));
   272	    let mut mtu = quinn::MtuDiscoveryConfig::default();
   273	    mtu.upper_bound(mtu_ceiling);
   274	    cfg.mtu_discovery_config(Some(mtu));
   275	    // Enough flow-control credit to fill a long, fast path (PRD-001 R41). quinn's default
   276	    // stream window is 1.25 MB, sized for 100 Mbit/s at 100 ms; at 1 Gbit/s and 20 ms RTT that
   277	    // caps a tunnel at ~500 Mbit/s whatever the link does. Measured over a shaped 1 Gbit/s,
   278	    // 20 ms path: 414 Mbit/s with the default, ~940 with these. The window is credit the
   279	    // receiver grants, not memory it allocates up front.
   280	    cfg.stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW));
   281	    cfg.send_window(2 * u64::from(STREAM_WINDOW));
   282	    cfg.receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW));
   283	    // Cubic, restarted after the connection idles: a tunnel's transfer must not inherit the
   284	    // congestion history of an older one on the same long-lived connection (PRD-001 R41).
   285	    cfg.congestion_controller_factory(Arc::new(
   286	        crate::transport::congestion::IdleRestartConfig::default(),
   287	    ));
   288	    Arc::new(cfg)
   289	}
   290	
   291	/// How long one inbound handshake may take before it is abandoned.
   292	///
   293	/// This bounds a **pre-authentication** cost: until the handshake completes there is no
   294	/// identity to hold anybody to, so the only defence is that an unfinished attempt is cheap
   295	/// and finite. Generous enough for a slow or relayed path — the ADR-012 ladder's rung 4 is a
   296	/// circuit through an anchor — and short enough that abandoned attempts do not accumulate.
   297	/// How long one inbound handshake may take before it is abandoned.
   298	///
   299	/// Public so a proof about handshake stalling can derive its own bound from this instead of
   300	/// restating it: a gate that hard-codes 30 seconds keeps passing when this constant moves,
[0m
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs | sed -n '740,800p'
740	    ///
   741	    /// Read from the table before this end sends its first packet. A circuit detached before
   742	    /// then leaves nothing to carry the handshake, so a connection that completes was on a
   743	    /// circuit exactly when this says so.
   744	    #[must_use]
   745	    pub fn via_circuit(&self) -> bool {
   746	        self.via_circuit
   747	    }
   748	
   749	    /// The recorded session-establishment entry (tag `0x0011`) for this session,
   750	    /// pinning the negotiated suite + group so a downgrade is auditable.
   751	    #[must_use]
   752	    pub fn session(&self) -> &SessionEstablishment {
   753	        &self.session
   754	    }
   755	
   756	    /// The negotiated TLS group code point recorded for this session
   757	    /// (X25519MLKEM768 = `0x11EC`).
   758	    #[must_use]
   759	    pub fn negotiated_group(&self) -> u16 {
   760	        debug_assert_eq!(self.session.negotiated_group, X25519MLKEM768_CODE_POINT);
   761	        self.session.negotiated_group
   762	    }
   763	
   764	    /// Open a fresh outbound bidirectional stream for a logical flow.
   765	    ///
   766	    /// **Bounded, and reported as the peer being gone.** `open_bi` waits for stream credit, and
   767	    /// it waits indefinitely: a peer that stops granting credit — or a connection one end has
   768	    /// retired while the other still holds it — parked the caller for good with no error, and a
   769	    /// sync session parked there holds its room. And a connection that had closed came back as
   770	    /// `MalformedBundle("quic open_bi")`, which nothing maps, so it reached a person as
   771	    /// `Failed(Internal)`: a join whose stream opened on a retired connection said "internal
   772	    /// error" rather than "unreachable". Both failures are the same fact — this peer is not there
   773	    /// on this connection — and now say so.
   774	    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
   775	        match tokio::time::timeout(OPEN_STREAM_PATIENCE, self.connection.open_bi()).await {
   776	            Ok(Ok(pair)) => Ok(pair),
   777	            Ok(Err(_)) => Err(Error::Unreachable("quic stream: the connection is closed")),
   778	            Err(_) => Err(Error::Unreachable(
   779	                "quic stream: the peer granted no stream in time",
   780	            )),
   781	        }
   782	    }
   783	
   784	    /// Accept the next inbound bidirectional stream the peer opened.
   785	    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
   786	        self.connection
   787	            .accept_bi()
   788	            .await
   789	            .map_err(|_| Error::Unreachable("quic stream: the connection is closed"))
   790	    }
   791	
   792	    /// Send one RFC 9221 unreliable datagram carrying `payload`. The connection
   793	    /// prepends the next 64-bit sequence number (ADR-011 datagram framing); the
   794	    /// caller never sees or chooses sequences. Fails if the framed datagram
   795	    /// exceeds the peer's advertised limit ([`VoxConnection::max_datagram_payload`]).
   796	    pub fn send_datagram(&self, payload: &[u8]) -> Result<()> {
   797	        let frame = lock(&self.datagram_tx).frame(payload);
   798	        self.connection
   799	            .send_datagram(bytes::Bytes::from(frame))
   800	            .map_err(|_| Error::MalformedBundle("quic send_datagram"))
[0m
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs | sed -n '5200,5330p'
5200	    /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
  5201	    /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
  5202	    /// of any room this node holds may — and the preamble then names whichever channel the
  5203	    /// peer likes. Nothing here checked the two against each other, so a member of room A who
  5204	    /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
  5205	    /// [`Self::may_sync`] for who counts.
  5206	    async fn run_sync_session(
  5207	        &mut self,
  5208	        peer: Digest32,
  5209	        channel_id: Digest32,
  5210	        epoch: u64,
  5211	        send: quinn::SendStream,
  5212	        recv: quinn::RecvStream,
  5213	    ) {
  5214	        use crate::node::syncstream::accept_sync;
  5215	        // Answering while our own session holds this room is the other half of the deadlock.
  5216	        //
  5217	        // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
  5218	        // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
  5219	        // silent refusal that reads as a hang, which is the shape of defect this whole change
  5220	        // exists to remove. A reset reaches it on the next read, and its schedule brings it
  5221	        // back in a second.
  5222	        //
  5223	        // **Refused before the lock, not after.** A session holds this room's mutex for its whole
  5224	        // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
  5225	        // behind the very session this check exists to detect.
  5226	        if self.syncing.contains(&channel_id) {
  5227	            let (mut send, mut recv) = (send, recv);
  5228	            if self.owed_a_reason(&channel_id, &peer, epoch) {
  5229	                // Busy: our own session for this room is running (with this peer, a collision, or
  5230	                // with another). Said to a room peer, so its session ends as `SessionBusy`, not as
  5231	                // a transport failure (#202).
  5232	                crate::node::net::refuse_stream_because(
  5233	                    &mut send,
  5234	                    &mut recv,
  5235	                    crate::wire::WireError::SessionBusy,
  5236	                );
  5237	            } else {
  5238	                crate::node::net::refuse_stream(&mut send, &mut recv);
  5239	            }
  5240	            return;
  5241	        }
  5242	        // Only a channel we hold open at that epoch — or keep as an anchor — can be
  5243	        // reconciled. An anchor whose board just received the genesis adopts it here
  5244	        // rather than making the member wait for the next tick.
  5245	        if !self.channels.contains_key(&channel_id) {
  5246	            self.adopt_anchored(&channel_id).await;
  5247	            self.refresh_anchored_authors(&channel_id).await;
  5248	        }
  5249	        let matches_epoch = match (
  5250	            self.channels.get(&channel_id),
  5251	            self.anchored.get(&channel_id),
  5252	        ) {
  5253	            (Some(shared), _) => shared.lock().await.epoch() == epoch,
  5254	            (None, Some(state)) => state.lock().await.epoch() == epoch,
  5255	            (None, None) => false,
  5256	        };
  5257	
  5258	        // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
  5259	        // no log for it, most often — or at an epoch it is not at, returned here and let the streams
  5260	        // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
  5261	        // connection that died. Every push to an anchor that keeps no log for the room read as a
  5262	        // network fault. A coded reset says what happened. (It does not recover time: a dropped
  5263	        // stream already ended the initiator's session within milliseconds, measured; the long
  5264	        // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
  5265	        if !matches_epoch {
  5266	            let (mut send, mut recv) = (send, recv);
  5267	            if self.owed_a_reason(&channel_id, &peer, epoch) {
  5268	                crate::node::net::refuse_stream_because(
  5269	                    &mut send,
  5270	                    &mut recv,
  5271	                    crate::wire::WireError::EpochMismatch,
  5272	                );
  5273	            } else {
  5274	                crate::node::net::refuse_stream(&mut send, &mut recv);
  5275	            }
  5276	            return;
  5277	        }
  5278	        if !self.may_sync(&channel_id, &peer, epoch).await {
  5279	            // Refused explicitly, with the same coded reset as a stream kind the peer may not
  5280	            // open, rather than left to read for a frame that never comes.
  5281	            let (mut send, mut recv) = (send, recv);
  5282	            crate::node::net::refuse_stream(&mut send, &mut recv);
  5283	            return;
  5284	        }
  5285	        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
  5286	        self.start_session(channel_id, peer, transport);
  5287	    }
  5288	
  5289	    /// Whether `peer` may reconcile `channel_id`'s log with this node.
  5290	    ///
  5291	    /// - An **admitted author** of that room. If it is not one yet, this node's own board is
  5292	    ///   consulted first — local, so cheap — because a member that joined through somebody
  5293	    ///   else is on the board before it is in this node's author table, and refusing it for
  5294	    ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
  5295	    ///   Admission there takes the same M17.6 evidence as everywhere else.
  5296	    /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
  5297	    ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
  5298	    ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
  5299	    ///   room's link is not an anchor of this one.
  5300	    ///
  5301	    /// For a room this node only anchors, the peer must be an author the board knows.
  5302	    /// Whether a refusal may tell `peer` **why** (#202): it is this room's session partner, or it
  5303	    /// has a member record for the room on the board. Decided without the room's lock, because
  5304	    /// the refusals that ask run before it. Anyone else is refused with the uninformative code,
  5305	    /// so a stranger who names a room learns nothing about whether this node holds it.
  5306	    fn owed_a_reason(&self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
  5307	        self.syncing_with.get(channel_id) == Some(peer)
  5308	            || self.net.as_ref().is_some_and(|net| {
  5309	                net.board_bundles(channel_id, epoch)
  5310	                    .iter()
  5311	                    .any(|b| b.author_id == *peer)
  5312	            })
  5313	    }
  5314	
  5315	    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
  5316	        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
  5317	            {
  5318	                let channel = shared.lock().await;
  5319	                if channel.is_author(peer)
  5320	                    || channel.anchors().nodes().iter().any(|a| a.id == *peer)
  5321	                {
  5322	                    return true;
  5323	                }
  5324	            }
  5325	            let (Some(net), Some(store)) = (
  5326	                self.net.as_ref().map(Arc::clone),
  5327	                self.profile.as_ref().map(Profile::store_handle),
  5328	            ) else {
  5329	                return false;
  5330	            };
[0m
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs | sed -n '205,235p'; echo ----; cat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs | sed -n '300,330p'
205	        self.feeds.get(author)
   206	    }
   207	
   208	    /// All authors with a feed, sorted (deterministic iteration).
   209	    #[must_use]
   210	    pub fn authors(&self) -> Vec<Digest32> {
   211	        let mut a: Vec<Digest32> = self.feeds.keys().copied().collect();
   212	        a.sort_unstable();
   213	        a
   214	    }
   215	
   216	    /// Whether `author` has been frozen by a fork proof.
   217	    #[must_use]
   218	    pub fn is_frozen(&self, author: &Digest32) -> bool {
   219	        self.frozen.contains_key(author)
   220	    }
   221	
   222	    /// The recorded fork proof for a frozen author, if any.
   223	    #[must_use]
   224	    pub fn fork_proof(&self, author: &Digest32) -> Option<&ForkProof> {
   225	        self.frozen.get(author)
   226	    }
   227	
   228	    /// Look up a stored entry by its 32-byte hash (the Negentropy key).
   229	    #[must_use]
   230	    pub fn get_by_hash(&self, hash: &Digest32) -> Option<&Entry> {
   231	        let (author, seq) = self.by_hash.get(hash)?;
   232	        self.feeds.get(author).and_then(|f| f.get(*seq))
   233	    }
   234	
   235	    /// Whether an entry with this hash is stored.
----
   300	        let epoch = entry.skeleton.epoch;
   301	        let hash = entry.entry_hash();
   302	
   303	        // Governance/control entries MUST be composite (attributable) in EVERY
   304	        // channel (ADR-008 §"Per-entry-type authentication"): a deniable
   305	        // authenticator on a governance entry is rejected outright, so the
   306	        // governance plane — and its fork attribution — stays intact even in
   307	        // deniable channels.
   308	        if matches!(kind, EntryKind::Governance) && !entry.authenticator.is_attributable() {
   309	            return Err(Rejected::GovernanceNotAttributable);
   310	        }
   311	
   312	        // A frozen author's further entries are refused outright.
   313	        if self.frozen.contains_key(&author) {
   314	            return Err(Rejected::NotAdmitted);
   315	        }
   316	
   317	        // Idempotent duplicate.
   318	        if self.by_hash.contains_key(&hash) {
   319	            return Err(Rejected::Duplicate);
   320	        }
   321	
   322	        // Admission.
   323	        if !admission.is_admitted(&channel, epoch, &author) {
   324	            return Err(Rejected::NotAdmitted);
   325	        }
   326	
   327	        // Authenticator + structure (deniable verified via the M7 seam if given).
   328	        // This precedes equivocation classification on purpose: only an entry
   329	        // that is admitted AND authenticates may surface a fork proof / alarm.
   330	        entry
[0m
Confirmed the 202 transport: 16 MiB stream window (quic.rs:193,280), 32 MiB connection/send windows (quic.rs:203,281-282), 20s bounded opener (quic.rs:150-153,774-781), 20s frame timeout (stream_transport.rs:29). Now the 202 actor refusal path and dag classes.
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs | sed -n '1800,1840p'; echo ----; cat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs | sed -n '1930,1950p'; echo ----; cat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs | sed -n '2040,2110p'
1800	    /// say otherwise.
  1801	    ///
  1802	    /// The remaining consenters are re-keyed by the caller (the node's tick, from
  1803	    /// [`ChannelState::owed_rekeys`]); the rotation does not wait on that, because a
  1804	    /// revocation that took effect only once everyone else was reachable would be no
  1805	    /// revocation at all.
  1806	    pub fn revoke_consent(
  1807	        &mut self,
  1808	        profile: &Profile,
  1809	        target: Digest32,
  1810	        now_secs: u64,
  1811	    ) -> Result<ConsentRevocation> {
  1812	        let me = self.me();
  1813	        if target == me {
  1814	            return Err(Error::MalformedGovernance(
  1815	                "an identity cannot revoke its own consent",
  1816	            ));
  1817	        }
  1818	        if !MembershipView::new(&self.evaluator)
  1819	            .readers_of(&me)
  1820	            .contains(&target)
  1821	        {
  1822	            return Err(Error::MalformedGovernance("no consent to revoke"));
  1823	        }
  1824	        // Rotate first: the entry names the generation that excludes `target`, so
  1825	        // that generation has to exist before the fact is signed.
  1826	        let new_chain_id = self.rotate_sender(profile.store(), now_secs)?;
  1827	        let signer = profile.signer()?;
  1828	        let revocation =
  1829	            issue_consent_revocation(signer, &self.channel_id, self.epoch, target, new_chain_id)?;
  1830	        self.append_governance(profile, &revocation.to_wire(), now_secs)?;
  1831	        // Nothing is owed to a revoked member; drop the row so a later re-consent
  1832	        // starts from "holds nothing".
  1833	        if self.delivered.remove(&target).is_some() {
  1834	            self.persist_delivered(profile.store())?;
  1835	        }
  1836	        Ok(revocation)
  1837	    }
  1838	
  1839	    /// Forget that `target` holds this identity's current sender key, so the next
  1840	    /// re-key round delivers it again (ADR-021 F12).
----
  1930	    /// hashes accepted so far (ADR-007's causal relation is only ever *followed*,
  1931	    /// never trusted for authority).
  1932	    fn gov_heads(&self) -> std::collections::BTreeSet<Digest32> {
  1933	        self.gov_entries.iter().map(|g| g.entry_hash).collect()
  1934	    }
  1935	
  1936	    /// The resolver ADR-008 sync needs: this channel's admitted authors and the
  1937	    /// entry classification for `kind_for`.
  1938	    #[must_use]
  1939	    pub fn resolver(&self) -> ChannelAuthors {
  1940	        ChannelAuthors {
  1941	            authors: self.authors.clone(),
  1942	        }
  1943	    }
  1944	
  1945	    /// Run one ADR-008 **frontier sync** session over `transport` against a peer,
  1946	    /// then durably record and render whatever arrived (ADR-016 §"Sync
  1947	    /// scheduling").
  1948	    ///
  1949	    /// Sync is ADR-008's business and applies entries to the log itself; this method
  1950	    /// is the reconciliation the runtime owes afterwards. It snapshots each author's
----
  2040	                    "synced entry from an unadmitted author",
  2041	                ))?
  2042	                .clone();
  2043	            let wire = self
  2044	                .dag
  2045	                .get_by_hash(&entry_hash)
  2046	                .ok_or(Error::MalformedGovernance("synced entry vanished"))?
  2047	                .to_wire();
  2048	            let id = self.next_log_id;
  2049	            let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
  2050	            if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg) {
  2051	                self.poisoned = true;
  2052	                return Err(e);
  2053	            }
  2054	            self.next_log_id = id.saturating_add(1);
  2055	            match classify_payload(&payload)? {
  2056	                EntryKind::Governance => {
  2057	                    let entry = self
  2058	                        .dag
  2059	                        .get_by_hash(&entry_hash)
  2060	                        .ok_or(Error::MalformedGovernance("synced entry vanished"))?
  2061	                        .clone();
  2062	                    let gov = GovEntry::from_verified_log_entry(
  2063	                        &entry,
  2064	                        &key,
  2065	                        &self.channel_id,
  2066	                        self.gov_heads(),
  2067	                    )?;
  2068	                    self.gov_entries.push(gov);
  2069	                    self.evaluator = Arc::new(Self::build_evaluator(
  2070	                        &self.genesis,
  2071	                        &self.authors,
  2072	                        &self.gov_entries,
  2073	                        now_secs,
  2074	                    )?);
  2075	                    out.governance += 1;
  2076	                }
  2077	                EntryKind::Content => {
  2078	                    if self.render_content(store, author, entry_hash, &payload, now_secs)? {
  2079	                        out.rendered += 1;
  2080	                    }
  2081	                }
  2082	            }
  2083	        }
  2084	        // Reconciliation done; only now surface a session failure, with its coded
  2085	        // reason preserved (ADR-008 never downgrades a failure silently).
  2086	        Ok(out)
  2087	    }
  2088	
  2089	    /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
  2090	    /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
  2091	    ///
  2092	    /// # Errors
  2093	    /// The room is poisoned, a persist fails, or the session hard-fails.
  2094	    pub fn sync_over_room<T: Transport>(
  2095	        shared: &tokio::sync::Mutex<Self>,
  2096	        store: &Store,
  2097	        transport: &mut T,
  2098	        now_secs: u64,
  2099	    ) -> Result<SyncOutcome> {
  2100	        let epoch = {
  2101	            let ch = shared.blocking_lock();
  2102	            if ch.poisoned {
  2103	                return Err(Error::Profile(
  2104	                    "channel is poisoned after a failed persist; reopen it",
  2105	                ));
  2106	            }
  2107	            ch.epoch
  2108	        };
  2109	        let room = ChannelSessionRoom {
  2110	            shared,
[0m
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs | sed -n '2640,2730p'
2640	
  2641	/// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
  2642	/// lets go. See [`ChannelState::sync_over_room`].
  2643	struct ChannelSessionRoom<'a> {
  2644	    shared: &'a tokio::sync::Mutex<ChannelState>,
  2645	    store: &'a Store,
  2646	    now_secs: u64,
  2647	    /// The epoch the session began at; a room that has moved on refuses what was staged for it.
  2648	    epoch: u64,
  2649	    out: std::cell::RefCell<SyncOutcome>,
  2650	    /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
  2651	    fatal: std::cell::RefCell<Option<Error>>,
  2652	}
  2653	
  2654	impl ChannelSessionRoom<'_> {
  2655	    fn room(
  2656	        &self,
  2657	    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
  2658	    {
  2659	        let ch = self.shared.blocking_lock();
  2660	        if ch.poisoned {
  2661	            return Err(crate::wire::WireError::TransportFailed);
  2662	        }
  2663	        if ch.epoch != self.epoch {
  2664	            return Err(crate::wire::WireError::EpochMismatch);
  2665	        }
  2666	        Ok(ch)
  2667	    }
  2668	}
  2669	
  2670	impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
  2671	    fn frontiers(
  2672	        &self,
  2673	    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
  2674	        Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
  2675	    }
  2676	
  2677	    fn wants(
  2678	        &self,
  2679	        remote: &[crate::log::sync::FeedFrontier],
  2680	    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
  2681	        Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
  2682	    }
  2683	
  2684	    fn entries(
  2685	        &self,
  2686	        wants: &[crate::log::sync::WantRange],
  2687	    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
  2688	        Ok(crate::log::sync::entries_for_wants(
  2689	            &self.room()?.dag,
  2690	            wants,
  2691	        ))
  2692	    }
  2693	
  2694	    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
  2695	        let mut guard = self.room()?;
  2696	        let ch = &mut *guard;
  2697	        let before = ch.heads();
  2698	        // The resolver as it is *now*: an author revoked while this batch was on the wire is not
  2699	        // an author of this room any more, and its entries are refused.
  2700	        let resolver = ch.resolver();
  2701	        // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
  2702	        // at a time and stops at the first it refuses; those before it are already in the log.
  2703	        // Returning the refusal first skipped persisting and rendering them, yet the log now held
  2704	        // them, so every later session saw nothing to send and they were never shown: one joiner
  2705	        // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
  2706	        // refusal was the other joiner's entry, from an author this node had not admitted yet.
  2707	        // `sync_over` always did it in this order ("reconciliation done; only now surface a
  2708	        // session failure"); the per-step path lost it.
  2709	        let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
  2710	        match ch.absorb_arrived(self.store, &before, self.now_secs) {
  2711	            Ok(got) => {
  2712	                let mut out = self.out.borrow_mut();
  2713	                out.rendered += got.rendered;
  2714	                out.governance += got.governance;
  2715	                stored
  2716	            }
  2717	            Err(e) => {
  2718	                *self.fatal.borrow_mut() = Some(e);
  2719	                Err(crate::wire::WireError::TransportFailed)
  2720	            }
  2721	        }
  2722	    }
  2723	}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "MAX_SERVE_ENTRIES\|MAX_SERVE_BYTES\|SERVE_BUDGET\|DRAIN_BUDGET\|fn wants_for\|fn entries_for_wants\|fn frontier_session_room_inner\|t.finish()\|fn drain_entries\|MAX_STAGED" 
42://! at most [`MAX_SERVE_ENTRIES`] entries / [`MAX_SERVE_BYTES`] bytes within
43://! [`SERVE_BUDGET`]. That is correctness, not a quota (PRD-001 R4): a session that
73:const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
81:/// entries verify and file in well under the requester's `DRAIN_BUDGET`.
82:pub const MAX_SERVE_ENTRIES: usize = 1024;
85:/// [`MAX_SERVE_ENTRIES`]: a single entry may be up to [`MAX_PAYLOAD_LEN`], so a
88:pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;
93:/// `DRAIN_BUDGET` closes on the other direction. Stopping here is not a failure:
95:pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
450:pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
479:/// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
480:/// [`MAX_SERVE_BYTES`].
491:pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
502:                    && (out.len() >= MAX_SERVE_ENTRIES
503:                        || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
795:    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
804:    t.finish();
847:pub const MAX_STAGED: usize = 256;
869:fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
886:    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
893:    t.finish();
896:    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
906:                if staged.len() >= MAX_STAGED {
948:fn drain_entries<T: Transport, R: AuthorResolver>(
966:    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "past the cap: skipped\|Known and not fixed here\|running-marker\|fn sync_one\|fn start_session\|fn sync_channel\|fn run_sync_session\|fn may_sync\|in_session_with(&channel_id, &peer)\|fn push_if_owed\|fn run_due_syncs\|schedule.note_synced(now)\|fn adopt_anchored\|fn refresh_anchored_authors" | head -30
2760:    async fn adopt_anchored(&mut self, channel_id: &Digest32) {
2793:    async fn adopt_anchored_from_board(&mut self) {
2813:    async fn refresh_anchored_authors(&mut self, channel_id: &Digest32) {
4787:    async fn push_if_owed(&mut self) {
4793:    async fn run_due_syncs(&mut self) -> bool {
4934:                schedule.note_synced(now);
4983:        // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
4997:    async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
5024:            return false; // past the cap: skipped, not queued. The schedule comes round again.
5148:    fn start_session(
5202:    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
5240:    async fn run_sync_session(
5260:        if self.in_session_with(&channel_id, &peer) {
5317:    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '5090,5105p'
}
                SessionTarget::Anchored(state) => state.lock().await.epoch(),
            };
            // 2. Open the stream. Also a round trip.
            //
            // **A stream that will not open still reports.** This returned without a word, and the
            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
            // marked mid-session for good: every later sync of it skipped, every inbound one
            // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
            let handle = tokio::runtime::Handle::current();
            let transport =
                match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::SyncDone {
[0m
[0m$ [0mcat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs | sed -n '820,900p'; echo ----; cat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/streams.rs | sed -n '70,115p'; echo ----; cat -n /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/circuitstream.rs | sed -n '1,15p'
820	            // is gone (see [`SILENCE_IS_DEATH`]). Severed: its circuit is gone, so it can send
   821	            // nothing — and a second circuit to this peer is exactly what severs it, so it is
   822	            // severed at both ends by the time either files the newcomer that replaced it. The
   823	            // newcomer is filed and the dead one closed, whatever the tie-break would have said.
   824	            // Everything else is decided by path class and then by `tie_key`, which both ends
   825	            // compute identically; the class is the connection's own recorded fact (see
   826	            // [`path_class`]), not a reading of a table that changes underneath it.
   827	            if is_live(existing) && self.is_dead(existing) {
   828	                existing.close(WireError::Unresponsive);
   829	            } else if is_live(existing) {
   830	                let existing = Arc::clone(existing);
   831	                let (new_class, held_class) = (
   832	                    path_class(&self.endpoint, &conn),
   833	                    path_class(&self.endpoint, &existing),
   834	                );
   835	                let newcomer_loses = new_class < held_class
   836	                    || (new_class == held_class && tie_key(&conn) >= tie_key(&existing));
   837	                if newcomer_loses {
   838	                    drop(map);
   839	                    if !serve_loser {
   840	                        conn.close(WireError::AuthenticatorInvalid);
   841	                        return Filed {
   842	                            kept: existing,
   843	                            also_serve: None,
   844	                        };
   845	                    }
   846	                    let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
   847	                    let retired = Arc::new(conn);
   848	                    lock(&self.retiring).push((Arc::clone(&retired), retire_at));
   849	                    return Filed {
   850	                        kept: existing,
   851	                        also_serve: Some(retired),
   852	                    };
   853	                }
   854	                let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
   855	                lock(&self.retiring).push((existing, retire_at));
   856	            }
   857	        }
   858	        let conn = Arc::new(conn);
   859	        // The baseline for its silence: it has just completed a handshake, so it was heard now.
   860	        let _ = self.silent_for(&conn);
   861	        map.insert(peer, Arc::clone(&conn));
   862	        Filed {
   863	            kept: conn,
   864	            also_serve: None,
   865	        }
   866	    }
   867	
   868	    /// How long a retired connection is kept readable before it is closed.
   869	    #[must_use]
   870	    pub fn retire_grace_secs(&self) -> u64 {
   871	        self.retire_grace_secs
   872	    }
   873	
   874	    /// Close every retired connection whose grace has elapsed (or that the peer
   875	    /// already closed). Returns how many were closed. The node's tick calls this.
   876	    pub fn retire_expired(&self) -> usize {
   877	        let now = (self.clock)();
   878	        let mut retiring = lock(&self.retiring);
   879	        let before = retiring.len();
   880	        retiring.retain(|(conn, at)| {
   881	            // **Still carried** means somebody other than this list holds the connection:
   882	            // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
   883	            // long as they run, so the strong count is the liveness signal, and it needs no
   884	            // bookkeeping that could disagree with reality.
   885	            //
   886	            // The grace alone is not enough to close on. It is sized for a request finishing
   887	            // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
   888	            // file transfer is in flight for hours. Closing on the timer killed live sessions
   889	            // mid-stream whenever a better path displaced the one they were on, which reached
   890	            // the person as `Connection reset by peer` in the middle of their work.
   891	            let still_carried = Arc::strong_count(conn) > 1;
   892	            if (now >= *at && !still_carried) || !is_live(conn) {
   893	                conn.close(WireError::AuthenticatorInvalid);
   894	                false
   895	            } else {
   896	                true
   897	            }
   898	        });
   899	        before - retiring.len()
   900	    }
----
    70	    pub fn parse(frame: &[u8]) -> Result<Self> {
    71	        let mut d = Decoder::new(frame);
    72	        if d.array()? != 1 {
    73	            return Err(Error::MalformedBundle("stream kind arity"));
    74	        }
    75	        let v = u8::try_from(d.uint()?).map_err(|_| Error::MalformedBundle("stream kind range"))?;
    76	        d.finish()?;
    77	        Self::from_u8(v).ok_or(Error::MalformedBundle("unknown stream kind"))
    78	    }
    79	}
    80	
    81	/// Open a bi-stream on `conn` typed as `kind` (the kind frame is written first).
    82	pub async fn open_typed(
    83	    conn: &VoxConnection,
    84	    kind: StreamKind,
    85	) -> Result<(SendStream, RecvStream)> {
    86	    let (mut send, recv) = conn.open_stream().await?;
    87	    write_frame(&mut send, &kind.frame()).await?;
    88	    Ok((send, recv))
    89	}
    90	
    91	/// Accept the next bi-stream on `conn` and read its kind frame. A stream the peer
    92	/// closes before typing it, or types with an unknown kind, is an error.
    93	pub async fn accept_typed(conn: &VoxConnection) -> Result<(StreamKind, SendStream, RecvStream)> {
    94	    accept_typed_on(conn.quinn()).await
    95	}
    96	
    97	/// [`accept_typed`] on the bare quinn handle, for a caller that must wait for streams
    98	/// **without holding the [`VoxConnection`]** — the node's per-connection stream loop, which
    99	/// would otherwise count as a user of the connection for as long as the connection lives.
   100	pub async fn accept_typed_on(
   101	    conn: &quinn::Connection,
   102	) -> Result<(StreamKind, SendStream, RecvStream)> {
   103	    let (send, mut recv) = conn
   104	        .accept_bi()
   105	        .await
   106	        .map_err(|_| Error::Unreachable("quic stream: the connection is closed"))?;
   107	    let frame = read_frame(&mut recv, MAX_KIND_FRAME)
   108	        .await?
   109	        .ok_or(Error::MalformedBundle("stream closed before kind"))?;
   110	    let kind = StreamKind::parse(&frame)?;
   111	    Ok((kind, send, recv))
   112	}
----
     1	//! The **circuit stream** (`StreamKind::Circuit`): the relay of last resort
     2	//! (ADR-012 rung 4).
     3	//!
     4	//! When neither a direct dial nor a hole punch can reach a peer — both behind
     5	//! symmetric NAT, no IPv6 — a peer already connected to both carries the traffic.
     6	//! What it carries is the two peers' **QUIC packets**: each end attaches a
     7	//! [circuit](crate::transport::mux) to its endpoint, and the dial, the handshake and
     8	//! the identity pinning are exactly those of a direct connection. The relay forwards
     9	//! `DATAGRAM` frames it cannot read. That is what ADR-012's "ciphertext-only" relay
    10	//! means here, and it holds by construction: there is no plaintext for the relay to
    11	//! see, because the connection is not with the relay.
    12	//!
    13	//! ## Verbs
    14	//!
    15	//! | frame | direction | meaning |
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '5006,5026p'
};
        let target = match (
            self.channels.get(channel_id).map(Arc::clone),
            self.anchored.get(channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return false,
        };
        // An anchor's authors come from its own board, which is local: cheap, and it has to happen
        // before the session so the anchor can verify what arrives.
        if matches!(target, SessionTarget::Anchored(_)) {
            self.refresh_anchored_authors(channel_id).await;
        }
        if self.in_session_with(channel_id, &peer) {
            return false; // a session with this peer already has this room
        }
        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
            return false; // past the cap: skipped, not queued. The schedule comes round again.
        };
        self.syncing.insert((*channel_id, peer));
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '875,916p'
send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    send(t, encode_have(&room.frontiers()?))?;
    let remote_have = expect_have(t.recv())?;

    send(t, encode_want(&room.wants(&remote_have)?))?;
    let their_wants = expect_want(t.recv())?;

    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
    for wire in room.entries(&their_wants)? {
        if std::time::Instant::now() >= serve_deadline {
            break;
        }
        send(t, encode_entry(&wire))?;
    }
    t.finish();

    // Drained with no lock held; applied a batch at a time under a fresh one.
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    let mut staged: Vec<Vec<u8>> = Vec::new();
    let mut applied = 0;
    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
        if std::time::Instant::now() >= deadline {
            return Err(WireError::SyncModeUnsupported);
        }
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                staged.push(wire);
                if staged.len() >= MAX_STAGED {
                    applied += room.apply(std::mem::take(&mut staged))?;
                }
            }
            Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    if !staged.is_empty() {
        applied += room.apply(staged)?;
    }
    Ok(applied)
[0m
One last citation check, then I'll compose the review.
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '228,248p'
/// `SYNC_FRAME_TIMEOUT`, so a peer that went quiet mid-setup stopped the node for twenty seconds and
/// it answered nobody — including the pushes it had just marked owed. Measured on an anchor, which is
/// the node it hurts most because it is the hop a message takes when two members are never online
/// together:
///
/// ```text
/// vox node: took 1 entry for room 4yxukqstptuq
/// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
/// ```
///
/// Past the cap a sync is **skipped, not queued**: the schedule comes round again, and a queue of
/// sessions for rooms whose state has since moved on is worse than none.
const SYNCS_IN_FLIGHT: usize = 16;

/// How many inbound joins this node answers at once.
///
/// Answering a join is the one inbound thing a **stranger** can ask for: the passphrase is the
/// join credential, so anyone holding the address and the passphrase gets an exchange, and the
/// exchange waits on them three times and verifies their proof of work. Run on the actor, that
/// made one joiner — slow, malicious, or merely behind a bad link — able to stop a node from
/// answering anybody: no messages, no syncs, nothing, for as long as it cared to stall. An anchor
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "fn wire_error_for_rejected\|Rejected::NotAdmitted => WireError::EpochMismatch\|fn apply_entry\|fn wants_for\|send(t, encode_want\|Rejected::Duplicate => WireError"
450:pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
564:pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
566:        Rejected::NotAdmitted => WireError::EpochMismatch,
573:        Rejected::Duplicate => WireError::AuthenticatorInvalid,
602:pub fn apply_entry<R: AuthorResolver>(
785:    send(t, encode_want(&my_wants))?;
883:    send(t, encode_want(&room.wants(&remote_have)?))?;
[0m
All code claims verified against both trees. Here is my review.

---

# Review of ADR-025 revision 3 (glm-5.3, round 3)

Read-only. I verified every code claim below against 58fde36 (`git show`) and the 8436100 working tree. Note: `review3-astra.md` already contains a completed round-3 astra review of this revision; my findings below are my own verification and analysis, reached independently unless noted.

## Round-2 disposition (review2-astra.md)

| R2 finding | Disposition | Reason |
|---|---|---|
| 1. Turnover busy refusals return | **PARTIAL** | Busy refusal is gone and `INBOUND_PER_PORT=2` covers turnover, but holding has no admission deadline under the opener's 20 s HELLO read (`202:transport/stream_transport.rs:104–115`) while two admitted sessions can run ~50–60 s (serve 30 s + drain 30 s, `180:log/sync.rs:73,95`), so a correct peer's held stream times out and fails instead of being queued — D4's "queueing, not collision" is not guaranteed (see B3/M1). |
| 2. `owed`/notify lifecycle incomplete | **PARTIAL** | No notify exists; D2 capture-at-admission/consume-at-completion, `BackoffExpired`, manual-sync override, and epoch/incarnation rules are specified. But replacement of a *running* attempt's resources is unspecified (B2), backoff-vs-epoch-change interaction is unspecified (m3), and `done_gen` credit is not monotonic across concurrent completions (m1). |
| 3. Count ≠ coverage; permanent-prefix re-serve | **PARTIAL** | Position-matched coverage and the per-epoch excluded set close the named holes. But the position-set representation is unbounded against a malicious `HAVE` (M2), `excluded`/`unadmitted` are not computable from today's acceptance path (M2), and zero-progress truncation retries "at once" with no pacing (M3). |
| 4. Anchors, preparation, commands, capacity | **PARTIAL** (mostly resolved) | Verified: outbound setup fetches the board and admits authors (`180:node/actor.rs:5033–5089`); inbound adopts and refreshes before the membership check (`180:node/actor.rs:5265–5293`); `vox room sync` keeps `Done`-once-started (`180:node/actor.rs:5202–5223`); per-peer slot cap added. Remaining: the consent `(room,target,token)` keying is planned work, not the cited baseline (m4); the capacity disclaimer names the wrong case (m2). |
| 5. Notify amplification | **PARTIAL** | Notify is gone, but the replacement bound claim — "an inbound flood is bounded by the per-port admission limit, and holding" (ADR:383) — is false: `held` is not bounded by `INBOUND_PER_PORT`, and the real bounds (quinn's ~100 concurrent streams and the 32 MiB connection window, `202:transport/quic.rs:195–203`) are never cited (B3). |
| 6. Proofs lacked observed preconditions / measured base | **PARTIAL** | S0b, the CANNOT-MEASURE rule, S0c, and P7–P9 are real improvements. But several preconditions are unobservable from S0b's field list, P1's justification predicate false-fails honest inbound sessions, and P7/P8's mutants do not discriminate (M4). |
| 7. D2 condition must be exact and atomic | **PARTIAL** | `gH + nP` checked at completion in the same epoch is stated. Monotonic credit across concurrent completions and the lock boundary of the check are not (m1). |
| 8. Wrong-tree citations | **RESOLVED** | I re-checked the principal sites: `180:node/actor.rs:5260–5263, 5023–5024, 4933–4934, 4983–4984, 5094–5098, 237–239`; `180:node/channel.rs:218–227`; `180:node/syncstream.rs:93–113`. All match. |
| Nits ("exactly one"; counter semantics) | **PARTIAL** | "At most one outbound from each end" fixed; counter equations (endpoint-local vs pair-aggregated, `opened = completed + failed`?) still undefined. |

## BLOCKER

### B1. Full duplex makes a bilateral flow-control livelock reachable and permanent

Both ends serve their whole bounded batch before draining any of it (`180:log/sync.rs:886–916`: the serve loop, `t.finish()` at 893, then the drain loop). One session may serve up to 64 MiB (`180:log/sync.rs:88`, bound check at 502–503), but each end grants only a 16 MiB per-stream receive window (`202:transport/quic.rs:193,280`, config used in both directions, `202:transport/quic.rs:264–288`), and a blocked frame write fails at 20 s (`202:transport/stream_transport.rs:20–29,88–102`).

So when **both** ends need >~16 MiB from the other (both members offline for a while, both posting media): each writes ~16 MiB, each blocks in `write_frame` (neither drains — neither has finished serving), both time out at 20 s, both sessions fail having transferred nothing durable (the buffered window is discarded on reset). D3 row 4 raises requests, D5 backs off, both retry into the identical state. Nothing ever reduces either backlog: every session stalls the same way. **Livelock, forever.**

This is inherited machinery, but the current glare is what prevents it today: one of the two simultaneous sessions is refused (`180:node/actor.rs:5260–5263`; `202:node/actor.rs:5226–5240`), so only one direction runs at a time and the survivor's peer is draining. Option C removes that refusal by design — the collision that accidentally serialized the two directions is the thing C deletes. C's headline scenario (both ends open at once) is exactly this livelock's precondition.

P3 is one-directional (Bob offline while Alice posts), so the proof table does not exercise it. **Required:** bound one session's serve below the peer's stream window (e.g., `MAX_SERVE_BYTES` < 16 MiB, at family scale), or interleave serve/drain, and add a real-binary bilateral large-backlog proof with both orientations.

### B2. "A stale SyncDone changes nothing" wedges the port: result-ignoring and resource-release are conflated

D1: a `SyncDone` whose token is not in `out`/`inbound`, or whose `conn` or `epoch` is stale, "changes nothing except a `stale` counter" (ADR:166–168); on a new incarnation "the old session's eventual `SyncDone` is counted stale and changes nothing" (ADR:285–286).

Read literally, the stale attempt's completion also does not **clear `out`** — so after a reconnect/epoch change mid-session, the port's `out` stays occupied by an attempt whose completion is forbidden to update anything, and the port can never open another outbound. P7's "never two concurrent outbound attempts on one port" then holds vacuously, on a dead port. The same conflation hits `inbound` and `held` entries and the outbound **slot** the stale attempt holds (slots are held through the session; a stale session still runs to its frame-timeout end, ~50–80 s).

The room worker fences epoch and poison, not connection incarnation (`202:node/channel.rs:2654–2666`), so the stale attempt keeps applying entries meanwhile — harmless to the log (idempotent, verified) but real work under a dead port's name. **Required:** specify retirement — replacement clears `out`/`inbound`/`held` and releases the slot exactly once, independent of whether the *result* may update the port — and say whether a legitimately displaced live connection's streams (retired-but-carried, `202:node/net.rs:827–855,874–898`) may still ride a port whose `conn` moved on.

## MAJOR

### M1. Holding is not safe against a malicious member, and manufactures failures for correct ones

Three verified holes in D4:

- **`held` has no local cap or deadline** (ADR:151, 236–239). The 20 s bound is the *opener's* timeout — it ends the opener's attempt, not this side's held entry. Nothing specified ever removes a held stream whose opener gave up; a member can keep the deque full indefinitely (bounded in practice only by quinn's ~100 concurrent streams and the 32 MiB connection window, `202:transport/quic.rs:195–203` — limits the ADR never mentions while claiming the per-port limit bounds the flood, ADR:383).
- **Holding can fail a correct peer.** Admission can wait far past the opener's 20 s HELLO read: two admitted inbound sessions can each occupy the port ~50–60 s (`SERVE_BUDGET`/`DRAIN_BUDGET` 30 s each, `180:log/sync.rs:73,95`, plus per-frame 20 s timeouts). A correct peer's third stream is held, times out, fails, backs off (D5), returns, is held again. That is the busy refusal re-expressed as a timeout — the exact outcome revision 3 exists to remove, now without a named reason.
- **Zero-progress truncation retries immediately, forever.** D3 row 2 raises a request "at once" for unfilled positions; D5 paces zero progress only for `unadmitted`. A member that advertises a tail, serves nothing (or only entries the receiver already holds), and FINs, triggers an endless tight loop of individually "justified" sessions — which also defeats P1's justification assertion as a bound. Zero-progress on *any* class needs backoff.

### M2. D3's entry classes and coverage are not computable from the code as specified

- `excluded` vs `unadmitted` are indistinguishable today: a frozen author and an unadmitted author both come back `Rejected::NotAdmitted` (`202:log/dag.rs:312–324`); the frozen predicate exists separately (`202:log/dag.rs:216–220`) but the acceptance path must be split to classify, and the ADR doesn't say so.
- **"Revoked" is undefined and, as shipped, wrong:** `revoke_consent` rotates the sender key, appends the revocation, and updates the delivery ledger (`202:node/channel.rs:1806–1836`); the resolver still uses the admitted-author map (`202:node/channel.rs:1936–1943`). Consent revocation is not authorship eviction — an author's log entries remain valid and storeable. An `excluded`-because-revoked rule that permanently skips the author's ranges in later `WANT`s would permanently drop live entries.
- `persist-failed` cannot be retried as specified: a persist failure poisons the room (`202:node/channel.rs:2050–2052`) and every later session refuses it until reopen (`202:node/channel.rs:2100–2106`). "Raise a request; D5 backoff" retries into a wall. The reopen path is the actual fix and is unspecified.
- `unadmitted` is a hard fail today: `apply_entry` maps `NotAdmitted → Err(EpochMismatch)` (`180:log/sync.rs:564–566,602`), closing the stream. Classifying instead of failing is new apply semantics, not just observation; unstated.
- **Coverage representation is unbounded:** "a set of requested positions: `(author, seq)` over each range, clamped to the peer's `HAVE`" (ADR:207–209) — the clamp *is* the peer's advertised `max_seq`, a `u64`. A `HAVE` claiming `max_seq = u64::MAX` makes the requested set unrepresentable. The existing server deliberately avoids work proportional to range numbers (`180:log/sync.rs:491–539`); the receiver's coverage must too (compact intervals + the advertised head hash for `(N,N)`). This also bounds S0b's "requested positions" log field, which as specified has unbounded per-entry size.

The fork-head half is sound: I could not construct a substitution that passes position-matched coverage — a same-position substitute is either a real equivocation (correctly frozen) or the receiver's own head (caught by the advertised-hash check). Duplicate-substitution is closed **given** the representation and class fixes.

### M3. The proof table: preconditions unobservable, two mutants provably green

- **P1's justification predicate is wrong as written.** "Every session in the log is justified (it started while its port needed one)" false-fails honest **inbound** sessions: B's post raises B's need, B opens to A, and A's port can be entirely clean (nothing at A bumped `room.gen` or `req_gen`). The predicate must be direction-aware (outbound: local need; inbound: attribute to the opener). P6 inherits this.
- **P7's mutant does not go red.** "Tokens ignored at `SyncDone`": the stale rule is a *disjunction* (token not current **or** conn/epoch stale). The old-incarnation attempt's completion is still rejected by the unchanged incarnation check, `stale ≥ 1` still holds, mutant green. Mutate the whole stale-result guard, or force a superseded token on the *same* incarnation.
- **P8's mutant does not go red.** Bob's return is a new connection incarnation at *both* ends; Bob's ports raise requests (ADR:284–286), Bob opens his own outbound, his `WANT` fetches Alice's post — no `BackoffExpired` involved. The assert must isolate Alice's retry path (e.g., assert on Alice's outbound specifically, or suppress Bob's need).
- **P2's precondition is unobservable from S0b** ("at least one port recorded as queued while 4 of that peer's slots were in use"): S0b lists no queue events and no slot occupancy — counters don't include `queued`, the session log has neither field. Same for P8 ("backoff entered" — no backoff events in S0b) and P9 (the sender's "served entries" are not a logged field; the receiver's protocol-violation reason is not either).
- **P1's "justified" is also unobservable:** it needs `req_gen`/`req_done`/`done_gen` at admission, none of which S0b lists. And the last-64 log can evict: 40 duplex rounds with justified follow-ups can exceed 64 sessions per node, so "every session in the log" silently weakens mid-run.
- **P4's mutant holds only if Bob's port is otherwise quiet** — any outstanding request or concurrent outbound runs `learn_members` (`180:node/actor.rs:5033–5089`) and admits Carol without row 3. The control is unstated. P5 needs the tested entry's identity and store generation to prove "did not carry that post"; not in S0b.
- **The #202 replacement's assert can fail on honest behavior:** `EpochMismatch`'s text is disclosed only when `owed_a_reason` — session partner or board record (`202:node/actor.rs:5306–5313`). An anchor that keeps no log for the room typically holds no board record for it either → the refusal is the uninformative reset → the member reads a transport failure, not `EpochMismatch`. The setup must pin and observe the anchor's board state.

### M4. S0b cannot supply what the proofs need (beyond M3's specifics)

Missing: request generations captured/consumed and `done_gen` at admission/completion; queue/dequeue and slot-occupancy events; backoff entry/expiry; failure *reasons* (not just a `failed` counter); served-entry identities; per-entry store generations. "Received by class" does not identify entries. A 64-entry log needs an overflow indicator if "every session" assertions are to mean anything. S0b is the right idea landed first; its schema must be derived from the proof table's preconditions, and currently it isn't.

## MINOR

- **m1. `done_gen` credit must be monotonic.** D2 assigns `done_gen = gH + nP` or `gH` per completion; an older attempt completing later with a smaller `gH` lowers a newer credit. Self-correcting (one redundant idempotent session), but specify epoch-scoped monotonic advancement. Ignoring inbound in the outbound decision does **not** by itself loop honestly — I traced convergence to ≤1 extra session; the unbounded case is M1's zero-progress rule.
- **m2. D6's disclaimer names the wrong case.** "No proof asserts a delivery bound for the seventeenth *stalled* peer" (ADR:341–342) — but 4 stalled peers × the 4-per-peer cap saturate all 16 slots, and the victim is the *live* peer waiting behind them for up to a session's ~50–80 s lifetime. Round-robin governs admission, not preemption. State that limitation and prove sustained service with stalled + live peers mixed.
- **m3. Backoff vs epoch change is unspecified.** A new epoch resets `done_gen` and raises requests, but nothing says whether an existing backoff survives it (or a reconnect). An 8 s backoff inherited across an epoch change delays a fresh room's first sync for no reason.
- **m4. The consent bullet reads as baseline behavior.** "A consent's retry keys on (room, target) and the token, not on the room alone (`180:node/actor.rs` 3373–3380, 4362–4393)" (ADR:287–288) — the cited code does the opposite: `SyncDone` filters pending consents by room only (`|room, _| *room == channel_id`), and the stored tuple has no token (`180:node/actor.rs:1762,4356–4369`). It's planned work; the citation invites misreading.
- **m5. "At most two sessions per pair" (ADR:130) is not a bound on unfinished sessions.** Turnover admits 2 inbound + 1 outbound = 3 concurrent on one pair, plus held. The cell describes the collision case; as a bound it's false.

## NIT

- Counter equations still undefined (R2 nit, unresolved): is `opened = completed + failed` endpoint-local, and do inbound-served completions count?
- Where does the room generation live, and is it persisted across restarts? "Monotonic per room" needs a home; on restart both it and `done_gen` reset consistently, but the ADR should say so.
- Options table (ADR:129): "an inbound session is always admitted, queued if the port is at its inbound limit" — "always admitted… queued" contradicts itself; D4's wording is the accurate one.
- "What each review changed" says revision 3 is "not yet reviewed" (ADR:9) while `review3-astra.md` (BLOCK) sits in the reviews directory; update the table when the round concludes.

## What I could not break (option C, question 2, directly)

Two concurrent sessions on one (room, peer): **no corruption, no double-apply, no room-lock deadlock.** Each protocol step takes the room lock alone and the transport is never touched under it (`180:node/channel.rs:2649–2730`, `202:node/channel.rs:2641–2722`; the `SessionRoom` split is compiler-enforced, `180:log/sync.rs:756–762` docs); duplicates are refused idempotently (`202:log/dag.rs:317–320`); apply captures heads under the same lock (`202:node/channel.rs:2694–2722`); a partial batch is absorbed before its error is reported (`202:node/channel.rs:2701–2721`), so nothing stored is lost. Inbound takes no slot (`180:node/actor.rs:5148–5197` — verified: no `try_acquire` there), so two nodes cannot deadlock on each other's 16 slots. The deadlock that exists is at the transport layer (B1), and the starvation that exists is slot-level (m2). Tree citations I checked beyond the above all matched: `180:node/actor.rs:5260–5263, 5023–5024, 4933–4934, 4983–4984, 5094–5098, 237–239`; `180:node/channel.rs:218–227`; `180:node/syncstream.rs:93–113`; `202:transport/quic.rs:150–153, 774–781`; `202:node/actor.rs:5226–5240, 5306–5313`. I found no planned work described as done; base columns are honestly labeled "predicted"/"to be measured".

## VERDICT

**BLOCK**

The three changes I would most insist on:

1. **Make the duplex exchange progress-making:** bound one session's serve below the peer's 16 MiB stream window (or interleave serve and drain), and prove it with a real-binary bilateral large-backlog proof in both orientations — C's own headline scenario otherwise livelocks.
2. **Specify the port's resource lifecycle, not just its result-filtering:** replacement/staleness must retire `out`, `inbound`, `held` and the slot exactly once while ignoring the result; held streams need a local cap and deadline; zero-progress on any class must pace with backoff; `done_gen` credit must be monotonic.
3. **Make D3 computable and the proofs discriminating:** compact coverage representation, split `excluded`/`unadmitted` (frozen vs admission), define "revoked" against what `revoke_consent` actually does, specify the poisoned-room reopen path; then rebuild S0b's schema from the proofs' preconditions and fix P1's direction-aware justification, P7/P8's non-discriminating mutants, and the #202 proof's `owed_a_reason` precondition.
