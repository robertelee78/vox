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
[0m$ [0mgrep -n "^#" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md | tail -60
678:#[derive(Debug, Default)]
737:#[derive(Debug, Clone, Copy, PartialEq, Eq)]
748:#[derive(Debug, Clone, Copy, PartialEq, Eq)]
763:#[must_use]
771:#[must_use]
785:#[must_use]
799:#[must_use]
807:#[must_use]
823:#[derive(Debug, Clone, PartialEq, Eq)]
965:#[must_use]
990:#[must_use]
1031:#[must_use]
1088:#[must_use]
1104:#[must_use]
1119:#[derive(Debug)]
1120:#[non_exhaustive]
1176:#[allow(clippy::too_many_arguments)]
1205:#[allow(clippy::too_many_arguments)]
2574:#[must_use]
2580:#[derive(Debug, Clone, Copy, PartialEq, Eq)]
2592:#[derive(Debug, Clone, Copy)]
2687:#[must_use]
4133:## BLOCKER
4135:### 1. One designated opener does not guarantee one unfinished session
4151:### 2. `owed` plus “one outstanding notify” is not a complete work lifecycle
4167:## MAJOR
4169:### 3. D3’s arithmetic is computable; its claimed completeness is too strong
4184:### 4. Anchors, membership preparation, commands, and capacity need explicit paths
4196:### 5. Notify coalescing is not an amplification bound
4204:### 6. The rebuilt proof table still does not establish mutant discrimination
4223:### Round-1 disposition
4266:## MINOR
4268:### 7. D2 is conservative and sound only with an exact atomic condition
4282:### 8. Several “58fde36” citations are actually from other trees
4296:## NIT
4304:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review2-astra.md[90m [offset=4100, limit=215][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-glm-5.3.md
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-kimi-k3.md
Now let me read the round-1 reviews and check the small review3 files.
[0m
[0m$ [0mgrep -n "^#\{1,3\} \|^## BLOCKER\|^## MAJOR\|^## MINOR\|^## NIT\|^## VERDICT" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md | tail -50
2948:## BLOCKER
2950:### B1. Both directions can stall while serving, before either starts receiving
2970:### B2. The resource and retry bounds trust the peer where they must be receiver-enforced
2982:## MAJOR
2984:### M1. Replacement and stale completion are specified as filtering, not resource lifecycle
3002:### M2. D3’s classifications need policy and durability definitions
3015:### M3. The proof table still cannot discriminate several named mutants
3034:### M4. S0b cannot supply the advertised causal evidence
3051:## MINOR
3053:### m1. D2 should preserve monotonic completion credit
3065:### m2. D6 limits one stalled peer, not aggregate stall latency
3071:### m3. Tree accuracy and planned-versus-done wording
3082:## NIT
3086:### Round-2 finding disposition
3104:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-astra.md[90m [offset=2940, limit=175][0m
[0m
[0m# [0mTodos
[✓] Read ADR-025 revision 3 document
[•] Read prior reviews (astra round 1+2, glm-5.3, kimi-k3, astra round 3)
[ ] Verify code claims against 58fde36 and 8436100 trees
[ ] Verify round-2 findings against rev 3 (RESOLVED/PARTIAL/NOT)
[ ] Attack Option C (full duplex) for corruption/deadlock/starvation
[ ] Check D2/D3/D5/D6/epoch rules and proof table
[ ] Write review: BLOCKER/MAJOR/MINOR/NIT + VERDICT
[0m
[0m$ [0mgrep -n "^## \|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md | tail -30; echo ====; grep -n "^## \|^### \|^**B\|^**M" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-glm-5.3.md | tail -30; echo ====; grep -n "^## \|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-kimi-k3.md | tail -30
1607:## BLOCKER
1609:### 1. D3 cannot establish “delivered through `gen_at_have`”
1626:### 2. D4 lacks session identity and has destructive completion races
1656:### 3. Content generation alone cannot encode every trigger
1664:## MAJOR
1666:### 4. `AWAIT_KEEPER` needs a narrower meaning; two seconds is unsupported
1684:### 5. The proof plan does not establish its advertised properties
1703:### 6. D6 leaves admission capacity and fairness ambiguous
1711:## MINOR
1713:### 7. Context claims: verdicts against the actual trees
1725:### 8. D6 contains a false baseline claim; the release rationale overstates D3’s evidence
1741:## NIT
1743:### 9. The alternatives discussion does not justify the chosen complexity
1753:## VERDICT
zsh:1: === not found
[0m
[0m$ [0mgrep -n "^## \|^### " "/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-glm-5.3.md" | tail -30
259:## BLOCKER
269:## MAJOR
281:## MINOR
295:## NIT
301:## VERDICT
[0m
[0m$ [0mgrep -n "^## \|^### " "/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-kimi-k3.md" | tail -30
353:## BLOCKER
357:## MAJOR
378:## MINOR
390:## NIT
400:## Answers to the remaining numbered questions, compactly
406:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-glm-5.3.md[90m [offset=255, limit=53][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-kimi-k3.md[90m [offset=350, limit=62][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '440,540p'
/// - for every remote feed whose `max_seq` **exceeds** what we hold, request
///   `(local_max + 1 ..= remote_max)` (the ordinary tail-extension case);
/// - **and** — the equal-length fork case — when the remote's `max_seq` **equals**
///   our `max_seq` but its `head_hash` **differs** from ours, request the head
///   `(max_seq ..= max_seq)`. Two partitions each holding `(author, seq = N)` with
///   different valid hashes would otherwise never exchange the conflicting entry
///   and no fork proof would form (ADR-008 §"Fork / equivocation handling"). The
///   pulled conflicting entry is fed into DAG fork handling, which freezes the
///   author on an attributable proof and raises an alarm on a deniable one.
#[must_use]
pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
    let mut wants = Vec::new();
    for rf in remote {
        let local = dag.feed(&rf.author_id);
        let local_max = local.map_or(0, |f| f.max_seq());
        if rf.max_seq > local_max {
            wants.push(WantRange {
                author_id: rf.author_id,
                from_seq: local_max + 1,
                to_seq: rf.max_seq,
            });
        } else if rf.max_seq == local_max && local_max > 0 {
            // Equal head seq: compare the gossiped head hashes. A mismatch is a
            // divergence (equal-length fork) — pull the remote head entry so the
            // conflict reaches DAG fork handling.
            let local_head = local.map_or(crate::log::entry::ZERO_HASH, |f| f.head_hash());
            if local_head != rf.head_hash {
                wants.push(WantRange {
                    author_id: rf.author_id,
                    from_seq: local_max,
                    to_seq: local_max,
                });
            }
        }
    }
    wants
}

/// Collect the `ENTRY` wire frames satisfying a peer's `WANT` ranges from the
/// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
/// [`MAX_SERVE_BYTES`].
///
/// **The work is bounded by what this node holds, never by the ranges' numbers.**
/// This used to loop `from_seq..=to_seq` doing one lookup per number, collecting
/// into memory with the room's lock held, so a single `WANT (author, 1,
/// u64::MAX)` — any member may send one — pinned a core on a loop that would not
/// finish in the life of the machine, and nothing else could touch that room
/// again (PRD-001 D2). Now each author's ranges are merged, so duplicates and
/// overlaps cost nothing and serve nothing twice, and each merged range walks
/// only the entries the feed actually has. Entries not held are simply omitted.
#[must_use]
pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for (author, ranges) in merged_wants(wants) {
        let Some(feed) = dag.feed(&author) else {
            continue;
        };
        for (from, to) in ranges {
            for entry in feed.range(from, to) {
                let wire = entry.to_wire();
                if !out.is_empty()
                    && (out.len() >= MAX_SERVE_ENTRIES
                        || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
                {
                    return out;
                }
                bytes = bytes.saturating_add(wire.len());
                out.push(wire);
            }
        }
    }
    out
}

/// A `WANT`'s ranges grouped by author (in author order) with each author's
/// ranges sorted and merged, so the ranges are disjoint and ascending. Inverted
/// ranges are dropped. The cost is `O(n log n)` in the number of ranges, which
/// the frame size already bounds.
fn merged_wants(wants: &[WantRange]) -> std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> {
    let mut by_author: std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for w in wants.iter().filter(|w| w.from_seq <= w.to_seq) {
        by_author
            .entry(w.author_id)
            .or_default()
            .push((w.from_seq, w.to_seq));
    }
    for ranges in by_author.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for &(from, to) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        *ranges = merged;
    }
    by_author
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '855,945p'
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
[0m
Now let me verify code citations. First, `log/sync.rs` on 58fde36:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "MAX_SERVE\|SERVE_BUDGET\|DRAIN_BUDGET\|MAX_STAGED\|const \|t.finish()\|serve_deadline\|let send\|encode_hello\|expect_hello\|encode_have\|expect_have\|encode_want\|expect_want" | head -40
42://! at most [`MAX_SERVE_ENTRIES`] entries / [`MAX_SERVE_BYTES`] bytes within
43://! [`SERVE_BUDGET`]. That is correctness, not a quota (PRD-001 R4): a session that
73:const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
81:/// entries verify and file in well under the requester's `DRAIN_BUDGET`.
82:pub const MAX_SERVE_ENTRIES: usize = 1024;
85:/// [`MAX_SERVE_ENTRIES`]: a single entry may be up to [`MAX_PAYLOAD_LEN`], so a
88:pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;
93:/// `DRAIN_BUDGET` closes on the other direction. Stopping here is not a failure:
95:pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
102:pub const MAX_ENTRY_WIRE: usize = MAX_PAYLOAD_LEN + MAX_AUTHENTICATOR_LEN + 4096;
223:pub fn encode_hello(mode_bitmap: u8) -> Vec<u8> {
231:pub fn encode_have(frontiers: &[FeedFrontier]) -> Vec<u8> {
245:pub fn encode_want(ranges: &[WantRange]) -> Vec<u8> {
479:/// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
480:/// [`MAX_SERVE_BYTES`].
502:                    && (out.len() >= MAX_SERVE_ENTRIES
503:                        || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
680:    let send_a = |t: &mut TA, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
681:    let send_b = |t: &mut TB, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
684:    send_a(ta, encode_hello(SYNC_MODE_FRONTIER))?;
685:    send_b(tb, encode_hello(SYNC_MODE_FRONTIER))?;
687:    let a_remote_hello = expect_hello(ta.recv())?;
688:    let b_remote_hello = expect_hello(tb.recv())?;
693:    send_a(ta, encode_have(&frontiers_of(a)))?;
694:    send_b(tb, encode_have(&frontiers_of(b)))?;
696:    let a_sees = expect_have(ta.recv())?; // b's frontiers, seen by a
697:    let b_sees = expect_have(tb.recv())?; // a's frontiers, seen by b
702:    send_a(ta, encode_want(&a_wants))?;
703:    send_b(tb, encode_want(&b_wants))?;
705:    let a_got_want = expect_want(ta.recv())?; // what b wants from a
706:    let b_got_want = expect_want(tb.recv())?; // what a wants from b
772:    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
775:    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
776:    let remote_hello = expect_hello(t.recv())?;
780:    send(t, encode_have(&frontiers_of(dag)))?;
781:    let remote_have = expect_have(t.recv())?;
785:    send(t, encode_want(&my_wants))?;
786:    let their_wants = expect_want(t.recv())?;
795:    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
797:        if std::time::Instant::now() >= serve_deadline {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '300,340p'
.first()
        .ok_or(Error::MalformedBundle("sync empty frame"))?;
    let id = FrameId::from_u8(id_byte).ok_or(Error::MalformedBundle("sync unknown frame id"))?;
    let body = &bytes[1..];
    match id {
        FrameId::Hello => {
            let mut d = Decoder::new(body);
            let bitmap = u8::try_from(d.uint()?)
                .map_err(|_| Error::MalformedBundle("hello bitmap range"))?;
            d.finish()?;
            Ok(SyncFrame::Hello(bitmap))
        }
        FrameId::Have => {
            let mut d = Decoder::new(body);
            let n = d.array()?;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                if d.array()? != 3 {
                    return Err(Error::MalformedBundle("have tuple arity"));
                }
                let author_id = take_digest(&mut d)?;
                let max_seq = d.uint()?;
                let head_hash = take_digest(&mut d)?;
                v.push(FeedFrontier {
                    author_id,
                    max_seq,
                    head_hash,
                });
            }
            d.finish()?;
            Ok(SyncFrame::Have(v))
        }
        FrameId::Want => {
            let mut d = Decoder::new(body);
            let n = d.array()?;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                if d.array()? != 3 {
                    return Err(Error::MalformedBundle("want tuple arity"));
                }
                let author_id = take_digest(&mut d)?;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '855,920p' | cat -n | sed 's/^/  /' | awk '{printf "%d%s\n", $1+854, substr($0, index($0,$2)-0)}' 2>/dev/null | head -5; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | awk 'NR>=855 && NR<=920 {printf "%d: %s\n", NR, $0}'
855pub fn frontier_session_room<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
856where
857T: Transport,
858S: SessionRoom + ?Sized,
859{
855: pub fn frontier_session_room<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
856: where
857:     T: Transport,
858:     S: SessionRoom + ?Sized,
859: {
860:     match frontier_session_room_inner(t, room) {
861:         Ok(applied) => Ok(applied),
862:         Err(code) => {
863:             t.close(code);
864:             Err(code)
865:         }
866:     }
867: }
868: 
869: fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
870: where
871:     T: Transport,
872:     S: SessionRoom + ?Sized,
873: {
874:     let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
875: 
876:     send(t, encode_hello(SYNC_MODE_FRONTIER))?;
877:     let remote_hello = expect_hello(t.recv())?;
878:     negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;
879: 
880:     send(t, encode_have(&room.frontiers()?))?;
881:     let remote_have = expect_have(t.recv())?;
882: 
883:     send(t, encode_want(&room.wants(&remote_have)?))?;
884:     let their_wants = expect_want(t.recv())?;
885: 
886:     let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
887:     for wire in room.entries(&their_wants)? {
888:         if std::time::Instant::now() >= serve_deadline {
889:             break;
890:         }
891:         send(t, encode_entry(&wire))?;
892:     }
893:     t.finish();
894: 
895:     // Drained with no lock held; applied a batch at a time under a fresh one.
896:     let deadline = std::time::Instant::now() + DRAIN_BUDGET;
897:     let mut staged: Vec<Vec<u8>> = Vec::new();
898:     let mut applied = 0;
899:     while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
900:         if std::time::Instant::now() >= deadline {
901:             return Err(WireError::SyncModeUnsupported);
902:         }
903:         match decode_frame(&frame) {
904:             Ok(SyncFrame::Entry(wire)) => {
905:                 staged.push(wire);
906:                 if staged.len() >= MAX_STAGED {
907:                     applied += room.apply(std::mem::take(&mut staged))?;
908:                 }
909:             }
910:             Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
911:         }
912:     }
913:     if !staged.is_empty() {
914:         applied += room.apply(staged)?;
915:     }
916:     Ok(applied)
917: }
918: 
919: /// Apply staged entries into `dag`, returning how many were newly stored — the apply half of
920: /// [`SessionRoom::apply`], for a caller that already holds its room.
[0m
[0m$ [0msed -n '1,120p' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs
//! The real M5 [`Transport`] over a reliable QUIC
//! bi-stream.
//!
//! M5 frames are opaque byte vectors; here they are length-delimited on the stream
//! with the [`crate::transport::framing`] 4-byte big-endian length prefix so the
//! byte stream is re-segmented into exactly the frames M5 sent. The synchronous M5
//! sync engine is bridged onto async quinn via a tokio runtime [`Handle`].

use std::time::Duration;

use quinn::{RecvStream, SendStream};
use tokio::runtime::Handle;

use crate::error::{Error, Result};
use crate::log::sync::Transport;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{close_code, VoxConnection, MAX_STREAM_FRAME};
use crate::wire::WireError;

/// How long one sync frame may take to arrive or to be accepted for sending before
/// the session is failed.
///
/// A session runs with the channel's lock held (the ADR-008 engine is synchronous
/// over channel state), so a peer that stops answering — its actor busy, its
/// network gone — would otherwise hold that lock for as long as it liked, and every
/// other use of the channel on this node would wait behind it: a join to answer, a
/// key to take, a message to send. Twenty seconds is far longer than any real
/// exchange and shorter than anyone waits.
pub const SYNC_FRAME_TIMEOUT: Duration = Duration::from_secs(20);

/// A [`sync::Transport`](crate::log::sync::Transport) over one reliable QUIC
/// bi-stream, bridging the synchronous M5 sync engine onto async quinn via a tokio
/// runtime [`Handle`].
///
/// M5 frames are opaque byte vectors; here they are length-delimited on the stream
/// with a 4-byte big-endian length prefix so the byte stream is re-segmented into
/// exactly the frames M5 sent. `recv` returns `Ok(None)` on a clean peer
/// half-close (FIN). A hard [`WireError`] close resets the stream with the mapped
/// QUIC code.
pub struct QuicStreamTransport {
    handle: Handle,
    send: SendStream,
    recv: RecvStream,
    /// Set once closed so further sends fail (mirrors the M5 duplex contract).
    closed: Option<WireError>,
    /// Per-frame bound on both directions; see [`SYNC_FRAME_TIMEOUT`].
    frame_timeout: Duration,
}

impl QuicStreamTransport {
    /// Wrap an opened `(SendStream, RecvStream)` pair, bridged onto `handle`, with
    /// the standard [`SYNC_FRAME_TIMEOUT`].
    #[must_use]
    pub fn new(handle: Handle, send: SendStream, recv: RecvStream) -> Self {
        Self::with_timeout(handle, send, recv, SYNC_FRAME_TIMEOUT)
    }

    /// [`QuicStreamTransport::new`] with an explicit per-frame bound.
    #[must_use]
    pub fn with_timeout(
        handle: Handle,
        send: SendStream,
        recv: RecvStream,
        frame_timeout: Duration,
    ) -> Self {
        Self {
            handle,
            send,
            recv,
            closed: None,
            frame_timeout,
        }
    }

    /// Open a new bi-stream on `conn` and wrap it (initiator side).
    pub async fn open(handle: Handle, conn: &VoxConnection) -> Result<Self> {
        let (send, recv) = conn.open_stream().await?;
        Ok(Self::new(handle, send, recv))
    }

    /// Accept the next bi-stream on `conn` and wrap it (responder side).
    pub async fn accept(handle: Handle, conn: &VoxConnection) -> Result<Self> {
        let (send, recv) = conn.accept_stream().await?;
        Ok(Self::new(handle, send, recv))
    }
}

impl Transport for QuicStreamTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed.is_some() {
            return Err(Error::Unreachable("quic transport: send after close"));
        }
        let send = &mut self.send;
        let bound = self.frame_timeout;
        self.handle
            .block_on(async move {
                tokio::time::timeout(bound, write_frame(send, frame))
                    .await
                    .map_err(|_| Error::Unreachable("sync: peer stopped taking frames"))
            })
            .and_then(|r| r)
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        // A clean FIN exactly at a frame boundary is the peer's success
        // half-close → `Ok(None)`; anything else is a real transport failure.
        let recv = &mut self.recv;
        let bound = self.frame_timeout;
        self.handle
            .block_on(async move {
                tokio::time::timeout(bound, read_frame(recv, MAX_STREAM_FRAME))
                    .await
                    .map_err(|_| Error::Unreachable("sync: peer went quiet"))
            })
            .and_then(|r| r)
    }

    fn close(&mut self, code: WireError) {
        if self.closed.is_some() {
            return;
[0m
[0m$ [0msed -n '1,40p' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/framing.rs
//! Length-delimited frames on a reliable QUIC bi-stream (ADR-011 §"Two contracts
//! on one connection"): every stream flow — M5 sync, the rendezvous service, the
//! join stream — carries a sequence of opaque frames, each prefixed by its 4-byte
//! big-endian length, so the byte stream is re-segmented into exactly the
//! messages the sender framed.
//!
//! These are the async primitives; [`crate::transport::stream_transport`] bridges
//! them to the synchronous M5 engine. A caller supplies the per-flow frame cap so
//! a hostile peer cannot announce a huge length to force an allocation.

use quinn::{RecvStream, SendStream};

use crate::error::{Error, Result};

/// Write one length-prefixed frame.
pub async fn write_frame(send: &mut SendStream, frame: &[u8]) -> Result<()> {
    let len = u32::try_from(frame.len())
        .map_err(|_| Error::SizeLimitExceeded("quic stream frame length"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(write_failure)?;
    send.write_all(frame).await.map_err(write_failure)?;
    Ok(())
}

/// A stream the peer **reset or stopped with a coded reason** refused on purpose and said why;
/// anything else went away with nothing said (#202). Reading the code is what lets the initiator
/// of a sync tell a collision the peer refused from a path that died.
fn refused(code: quinn::VarInt) -> Option<Error> {
    u8::try_from(code.into_inner())
        .ok()
        .and_then(crate::wire::WireError::from_code)
        .map(Error::PeerRefused)
}

fn write_failure(e: quinn::WriteError) -> Error {
    match e {
        quinn::WriteError::Stopped(code) => refused(code),
        _ => None,
    }
[0m
Line numbers for the session steps all check out. Now the transport layer (202 tree) for astra's B1 claim and the ADR's D4 holding claim:
[0m$ [0mawk 'NR>=170 && NR<=215 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs
170: /// the connection lock that `sendmsg` is made under, with encryption at a few percent.
171: /// Discovery is probing, not assuming: a path that will not carry a larger packet loses the
172: /// probe and keeps what it had, so a 1500-byte link is exactly where it was.
173: ///
174: /// **8192, not the loopback MTU (16384).** macOS refuses a UDP datagram over
175: /// `net.inet.udp.maxdgram` (9216 by default), and with the ceiling at 16356 connections
176: /// failed outright on this machine rather than falling back — measured, not reasoned. 8192
177: /// stays under that limit on every platform Vox builds for.
178: pub const MAX_UDP_PAYLOAD: u16 = 8_192;
179: 
180: /// The UDP socket buffers a node asks for, each way.
181: ///
182: /// The OS default (768 KiB receive on macOS) overflowed during a burst, and a large packet
183: /// lost to overflow reads to quinn as a black hole: it drops the path MTU back to 1200 and
184: /// does not probe again for a minute. Measured with the larger ceiling and larger stream
185: /// windows (an experiment since dropped): without these buffers the MTU fell back to 1200 in
186: /// 3 of 3 runs (`black_holes_detected` 1–9); with them, 0 black holes in 3 of 3.
187: /// The OS may grant less, and Linux does so silently (`net.core.rmem_max`); that is not an
188: /// error, but it decides the path-MTU ceiling (`mtu_ceiling_for`).
189: const UDP_SOCKET_BUFFER: usize = 4 << 20;
190: 
191: /// Per-stream flow-control window (and half the connection's send window), sized for the
192: /// bandwidth-delay product of a 1 Gbit/s path at ~130 ms, or 10 Gbit/s at ~13 ms.
193: pub const STREAM_WINDOW: u32 = 16 << 20;
194: 
195: /// Flow-control credit a peer gets for the whole connection, across all its streams: what this
196: /// node will buffer for one peer that sends and is not read.
197: ///
198: /// quinn's default is unlimited, which is safe only while the per-stream window is small. At
199: /// [`STREAM_WINDOW`] a peer may open quinn's default 100 concurrent bidirectional streams, so an
200: /// unlimited connection window let one peer park 100 × 16 MiB = 1.6 GiB in this node's memory
201: /// by writing into streams nobody reads. Two full stream windows keeps a single tunnel at full
202: /// speed, and lets a second one run beside it.
203: pub const CONNECTION_WINDOW: u32 = 2 * STREAM_WINDOW;
204: 
205: /// quinn's own path-MTU ceiling (`MtuDiscoveryConfig::default().upper_bound`): 1500-byte Ethernet
206: /// less IPv6 and UDP headers. What an endpoint falls back to when its socket cannot take the
207: /// bursts [`MAX_UDP_PAYLOAD`] brings.
208: pub const DEFAULT_UDP_PAYLOAD: u16 = 1_452;
209: 
210: /// The path-MTU ceiling for a socket whose receive buffer is `effective` bytes, as the OS
211: /// reports it after `UDP_SOCKET_BUFFER` was asked for, and why.
212: ///
213: /// **The 8192 ceiling needs the buffer it was measured with.** A burst of large datagrams that
214: /// overflows the receive buffer loses a run of large packets and nothing small, which is exactly
215: /// what quinn's black-hole detector looks for: it drops the path to 1200 bytes, below the 1452 a
[0m
[0m$ [0mawk 'NR>=270 && NR<=290 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs; awk 'NR>=755 && NR<=790 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs
270:         MAX_IDLE_MS,
271:     ))));
272:     let mut mtu = quinn::MtuDiscoveryConfig::default();
273:     mtu.upper_bound(mtu_ceiling);
274:     cfg.mtu_discovery_config(Some(mtu));
275:     // Enough flow-control credit to fill a long, fast path (PRD-001 R41). quinn's default
276:     // stream window is 1.25 MB, sized for 100 Mbit/s at 100 ms; at 1 Gbit/s and 20 ms RTT that
277:     // caps a tunnel at ~500 Mbit/s whatever the link does. Measured over a shaped 1 Gbit/s,
278:     // 20 ms path: 414 Mbit/s with the default, ~940 with these. The window is credit the
279:     // receiver grants, not memory it allocates up front.
280:     cfg.stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW));
281:     cfg.send_window(2 * u64::from(STREAM_WINDOW));
282:     cfg.receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW));
283:     // Cubic, restarted after the connection idles: a tunnel's transfer must not inherit the
284:     // congestion history of an older one on the same long-lived connection (PRD-001 R41).
285:     cfg.congestion_controller_factory(Arc::new(
286:         crate::transport::congestion::IdleRestartConfig::default(),
287:     ));
288:     Arc::new(cfg)
289: }
290: 
755: 
756:     /// The negotiated TLS group code point recorded for this session
757:     /// (X25519MLKEM768 = `0x11EC`).
758:     #[must_use]
759:     pub fn negotiated_group(&self) -> u16 {
760:         debug_assert_eq!(self.session.negotiated_group, X25519MLKEM768_CODE_POINT);
761:         self.session.negotiated_group
762:     }
763: 
764:     /// Open a fresh outbound bidirectional stream for a logical flow.
765:     ///
766:     /// **Bounded, and reported as the peer being gone.** `open_bi` waits for stream credit, and
767:     /// it waits indefinitely: a peer that stops granting credit — or a connection one end has
768:     /// retired while the other still holds it — parked the caller for good with no error, and a
769:     /// sync session parked there holds its room. And a connection that had closed came back as
770:     /// `MalformedBundle("quic open_bi")`, which nothing maps, so it reached a person as
771:     /// `Failed(Internal)`: a join whose stream opened on a retired connection said "internal
772:     /// error" rather than "unreachable". Both failures are the same fact — this peer is not there
773:     /// on this connection — and now say so.
774:     pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
775:         match tokio::time::timeout(OPEN_STREAM_PATIENCE, self.connection.open_bi()).await {
776:             Ok(Ok(pair)) => Ok(pair),
777:             Ok(Err(_)) => Err(Error::Unreachable("quic stream: the connection is closed")),
778:             Err(_) => Err(Error::Unreachable(
779:                 "quic stream: the peer granted no stream in time",
780:             )),
781:         }
782:     }
783: 
784:     /// Accept the next inbound bidirectional stream the peer opened.
785:     pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
786:         self.connection
787:             .accept_bi()
788:             .await
789:             .map_err(|_| Error::Unreachable("quic stream: the connection is closed"))
790:     }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=5015 && NR<=5035 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=4925 && NR<=4940 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=4975 && NR<=4995 {printf "%d: %s\n", NR, $0}'
5015:         // An anchor's authors come from its own board, which is local: cheap, and it has to happen
5016:         // before the session so the anchor can verify what arrives.
5017:         if matches!(target, SessionTarget::Anchored(_)) {
5018:             self.refresh_anchored_authors(channel_id).await;
5019:         }
5020:         if self.in_session_with(channel_id, &peer) {
5021:             return false; // a session with this peer already has this room
5022:         }
5023:         let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
5024:             return false; // past the cap: skipped, not queued. The schedule comes round again.
5025:         };
5026:         self.syncing.insert((*channel_id, peer));
5027:         let admit_store = self.profile.as_ref().map(Profile::store_handle);
5028:         let cid = *channel_id;
5029:         let now = self.now();
5030:         let tx = self.net_tx.clone();
5031:         tokio::spawn(async move {
5032:             let _slot = slot;
5033:             // 1. Learn who else has joined, or the first entry from a newer member kills the session
5034:             //    (ADR-008). A round trip, so it belongs here and not on the actor.
5035:             let epoch = match &target {
---
4925:                     ran = true;
4926:                     // Any session carries the room's latest append, whatever triggered it.
4927:                     self.pushed_to.entry(channel_id).or_default().insert(peer);
4928:                     if trigger == SyncTrigger::LocalAppend {
4929:                         pushed.insert(channel_id);
4930:                     }
4931:                 }
4932:             }
4933:             if let Some(schedule) = self.schedules.get_mut(&peer) {
4934:                 schedule.note_synced(now);
4935:                 // **A room skipped because it was mid-session is owed, not synced.**
4936:                 //
4937:                 // The in-flight mark is per room, so when two peers came due for one room in the
4938:                 // same pass the first took it and the second was skipped — and `note_synced` above
4939:                 // then recorded the skipped peer as synced at the same `now` as the first. Both came
4940:                 // due together again, in the same `BTreeMap` order, and the same peer lost again:
---
4975:         self.pending_push.retain(|cid| !pushed.contains(cid));
4976:         // **After** the retain, or it undoes this. The skip happens in exactly the pass where the
4977:         // room *was* pushed — to whichever peer took it first — so an owed room added inside the loop
4978:         // was then removed here as "pushed", and the skipped peer's retry next tick found nothing
4979:         // owed and dropped the push. It still arrived, on the next interval: up to 30s late instead
4980:         // of immediately, and invisible to any gate that only asks whether it arrived. Found in
4981:         // review by the other session.
4982:         //
4983:         // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
4984:         // push to a peer whose session then fails is counted as done.
4985:         self.pending_push.extend(owed_rooms);
4986:         ran
4987:     }
4988: 
4989:     /// Start reconciling one channel with one peer: learn who else has joined, then
4990:     /// hand the channel to a detached session task.
4991:     ///
4992:     /// Returns whether a session was *started*. It is deliberately not awaited — see
4993:     /// [`NetEvent::SyncDone`] for why awaiting deadlocks two nodes that start at the
4994:     /// same moment. While the channel is away it is invisible to commands (they answer
4995:     /// `UnknownChannel`) and, usefully, to this function, so a second pass cannot start
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=5090 && NR<=5110 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=5250 && NR<=5320 {printf "%d: %s\n", NR, $0}'
5090:                 }
5091:                 SessionTarget::Anchored(state) => state.lock().await.epoch(),
5092:             };
5093:             // 2. Open the stream. Also a round trip.
5094:             //
5095:             // **A stream that will not open still reports.** This returned without a word, and the
5096:             // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
5097:             // marked mid-session for good: every later sync of it skipped, every inbound one
5098:             // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
5099:             let handle = tokio::runtime::Handle::current();
5100:             let transport =
5101:                 match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
5102:                     Ok(t) => t,
5103:                     Err(e) => {
5104:                         let _ = tx
5105:                             .send(NetEvent::SyncDone {
5106:                                 channel_id: cid,
5107:                                 peer,
5108:                                 outcome: Err(e),
5109:                             })
5110:                             .await;
---
5250:         //
5251:         // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
5252:         // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
5253:         // silent refusal that reads as a hang, which is the shape of defect this whole change
5254:         // exists to remove. A reset reaches it on the next read, and its schedule brings it
5255:         // back in a second.
5256:         //
5257:         // **Refused before the lock, not after.** A session holds this room's mutex for its whole
5258:         // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
5259:         // behind the very session this check exists to detect.
5260:         if self.in_session_with(&channel_id, &peer) {
5261:             let (mut send, mut recv) = (send, recv);
5262:             crate::node::net::refuse_stream(&mut send, &mut recv);
5263:             return;
5264:         }
5265:         // Only a channel we hold open at that epoch — or keep as an anchor — can be
5266:         // reconciled. An anchor whose board just received the genesis adopts it here
5267:         // rather than making the member wait for the next tick.
5268:         if !self.channels.contains_key(&channel_id) {
5269:             self.adopt_anchored(&channel_id).await;
5270:             self.refresh_anchored_authors(&channel_id).await;
5271:         }
5272:         let matches_epoch = match (
5273:             self.channels.get(&channel_id),
5274:             self.anchored.get(&channel_id),
5275:         ) {
5276:             (Some(shared), _) => shared.lock().await.epoch() == epoch,
5277:             (None, Some(state)) => state.lock().await.epoch() == epoch,
5278:             (None, None) => false,
5279:         };
5280: 
5281:         // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
5282:         // no log for it, most often — or at an epoch it is not at, returned here and let the streams
5283:         // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
5284:         // connection that died. Every push to an anchor that keeps no log for the room read as a
5285:         // network fault. A coded reset says what happened. (It does not recover time: a dropped
5286:         // stream already ended the initiator's session within milliseconds, measured; the long
5287:         // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
5288:         if !matches_epoch {
5289:             let (mut send, mut recv) = (send, recv);
5290:             crate::node::net::refuse_stream(&mut send, &mut recv);
5291:             return;
5292:         }
5293:         if !self.may_sync(&channel_id, &peer, epoch).await {
5294:             // Refused explicitly, with the same coded reset as a stream kind the peer may not
5295:             // open, rather than left to read for a frame that never comes.
5296:             let (mut send, mut recv) = (send, recv);
5297:             crate::node::net::refuse_stream(&mut send, &mut recv);
5298:             return;
5299:         }
5300:         let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
5301:         self.start_session(channel_id, peer, transport);
5302:     }
5303: 
5304:     /// Whether `peer` may reconcile `channel_id`'s log with this node.
5305:     ///
5306:     /// - An **admitted author** of that room. If it is not one yet, this node's own board is
5307:     ///   consulted first — local, so cheap — because a member that joined through somebody
5308:     ///   else is on the board before it is in this node's author table, and refusing it for
5309:     ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
5310:     ///   Admission there takes the same M17.6 evidence as everywhere else.
5311:     /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
5312:     ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
5313:     ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
5314:     ///   room's link is not an anchor of this one.
5315:     ///
5316:     /// For a room this node only anchors, the peer must be an author the board knows.
5317:     async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
5318:         if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
5319:             {
5320:                 let channel = shared.lock().await;
[0m
Transport claims confirmed. Now the `node/actor.rs` citations on 58fde36:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=5033 && NR<=5090 {printf "%d: %s\n", NR, $0}'
5033:             // 1. Learn who else has joined, or the first entry from a newer member kills the session
5034:             //    (ADR-008). A round trip, so it belongs here and not on the actor.
5035:             let epoch = match &target {
5036:                 SessionTarget::Channel(shared) => {
5037:                     let known = shared.lock().await.epoch();
5038:                     if let Some(pstore) = admit_store {
5039:                         if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
5040:                             {
5041:                                 let mut ch = shared.lock().await;
5042:                                 let _ = admit_board_records(
5043:                                     &mut ch,
5044:                                     &pstore,
5045:                                     &set.bundles,
5046:                                     ChannelState::MAX_ADMISSIONS_PER_SWEEP,
5047:                                     now,
5048:                                 )
5049:                                 .await;
5050:                             }
5051:                             // What the peer's board holds is filed on this node's own, so its board
5052:                             // carries the whole membership it knows. Bundles go first: they carry
5053:                             // the key an address record is verified with (M15.2a). Mirroring to the
5054:                             // anchors follows on the actor when `SyncDone` lands, because that needs
5055:                             // channel state.
5056:                             for wire in set
5057:                                 .bundles
5058:                                 .iter()
5059:                                 .map(MemberBundleRecord::to_wire)
5060:                                 .chain(set.members.iter().map(RendezvousRecord::to_wire))
5061:                             {
5062:                                 let _ = net.publish_local(&wire);
5063:                             }
5064:                             // **And the other way: what this node's board holds that the peer's
5065:                             // lacks.** A member who joined through this node is on this node's
5066:                             // board and no other, and the peer learned of it only when *it* next
5067:                             // read this board, on its own periodic sync: 24–28 s for a third
5068:                             // member to see a new one, measured. Offered here, a push that follows
5069:                             // a join carries the newcomer to every connected member at once.
5070:                             // Best-effort: a refusal (a record the peer's board already holds
5071:                             // newer) costs nothing, and the peer's own sync still reads this board.
5072:                             let missing = net.board_records_missing_from(&cid, known, &set);
5073:                             if !missing.is_empty() {
5074:                                 if let Ok(mut client) =
5075:                                     crate::nat::service::RendezvousClient::open(&conn).await
5076:                                 {
5077:                                     for wire in &missing {
5078:                                         if let Err(e) = client.put(wire).await {
5079:                                             if !matches!(e, Error::RendezvousRejected(_)) {
5080:                                                 break;
5081:                                             }
5082:                                         }
5083:                                     }
5084:                                     client.finish();
5085:                                 }
5086:                             }
5087:                         }
5088:                     }
5089:                     shared.lock().await.epoch()
5090:                 }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=5140 && NR<=5230 {printf "%d: %s\n", NR, $0}'
5140:                 })
5141:                 .await;
5142:         });
5143:         true
5144:     }
5145: 
5146:     /// Take the channel out of the actor's map and run a session on its own task,
5147:     /// returning it through [`NetEvent::SyncDone`].
5148:     fn start_session(
5149:         &mut self,
5150:         channel_id: Digest32,
5151:         peer: Digest32,
5152:         transport: crate::transport::quic::QuicStreamTransport,
5153:     ) {
5154:         let Some(store) = self.log_store() else {
5155:             return;
5156:         };
5157:         let target = match (
5158:             self.channels.get(&channel_id).map(Arc::clone),
5159:             self.anchored.get(&channel_id).map(Arc::clone),
5160:         ) {
5161:             (Some(shared), _) => SessionTarget::Channel(shared),
5162:             (None, Some(state)) => SessionTarget::Anchored(state),
5163:             (None, None) => return,
5164:         };
5165:         // Marked here, past both early returns above, so a session that never starts never
5166:         // leaves the room marked. Its caller used to mark it first.
5167:         self.syncing.insert((channel_id, peer));
5168:         let now = self.now();
5169:         let tx = self.net_tx.clone();
5170:         tokio::spawn(async move {
5171:             let joined = tokio::task::spawn_blocking(move || {
5172:                 // The room is locked inside each protocol step only, never across the
5173:                 // network (`sync_over_room`).
5174:                 let mut t = transport;
5175:                 match target {
5176:                     SessionTarget::Channel(shared) => {
5177:                         crate::node::channel::ChannelState::sync_over_room(
5178:                             &shared, &store, &mut t, now,
5179:                         )
5180:                     }
5181:                     SessionTarget::Anchored(state) => {
5182:                         crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
5183:                     }
5184:                 }
5185:             })
5186:             .await;
5187:             let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
5188:                 "sync session panicked",
5189:             )));
5190:             let _ = tx
5191:                 .send(NetEvent::SyncDone {
5192:                     channel_id,
5193:                     peer,
5194:                     outcome,
5195:                 })
5196:                 .await;
5197:         });
5198:     }
5199: 
5200:     /// Reconcile a channel with every member this node can reach, now (the `Sync`
5201:     /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
5202:     async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
5203:         if self.net.is_none() {
5204:             return Outcome::Failed(Fault::NotNetworked);
5205:         }
5206:         let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
5207:             return Outcome::Failed(Fault::UnknownChannel);
5208:         };
5209:         let peers: Vec<Digest32> = {
5210:             let channel = shared.lock().await;
5211:             let me = channel.me();
5212:             channel.members().into_iter().filter(|m| *m != me).collect()
5213:         };
5214:         let mut synced = 0usize;
5215:         for peer in peers {
5216:             if self.sync_one(channel_id, peer).await {
5217:                 synced += 1;
5218:             }
5219:         }
5220:         if synced == 0 {
5221:             return Outcome::Failed(Fault::Unreachable);
5222:         }
5223:         Outcome::Done
5224:     }
5225: 
5226:     /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
5227:     /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
5228:     /// Serve one sync session for a request that has **already been read**.
5229:     ///
5230:     /// The preamble is read on the per-connection stream task (`node::network`), not here: the
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | awk 'NR>=205 && NR<=235 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | grep -n "impl SessionRoom\|fn sync_over_room\|fn frontiers\|fn wants\|fn entries\|fn apply" | head -20
205:         // A governance payload is a struct-tagged frame, a sender-key message is
206:         // domain-prefixed. A payload that is neither, or a pruned one (which cannot
207:         // be classified at all), falls back to `Content` — the conservative choice,
208:         // since governance entries must retain their payload (ADR-008) and so are
209:         // never the pruned case.
210:         entry
211:             .payload
212:             .as_deref()
213:             .and_then(|p| classify_payload(p).ok())
214:             .unwrap_or(EntryKind::Content)
215:     }
216: }
217: 
218: /// What one [`ChannelState::sync_over`] session did.
219: #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
220: pub struct SyncOutcome {
221:     /// Entries the ADR-008 session applied to the log.
222:     pub applied: usize,
223:     /// How many of those were governance entries folded into the evaluator.
224:     pub governance: usize,
225:     /// How many of those were decrypted and rendered into the timeline.
226:     pub rendered: usize,
227: }
228: 
229: /// What [`ChannelState::accept_entry`] did with a peer's entry.
230: #[derive(Debug, Clone, Copy, PartialEq, Eq)]
231: pub enum Accepted {
232:     /// A governance entry: verified, stored, and folded into the evaluator.
233:     Governance,
234:     /// A content entry: verified and stored, but not readable — this node holds no
235:     /// sender key for that author yet, or that author has not consented to this
---
2102:    pub fn sync_over_room<T: Transport>(
2679:    fn frontiers(
2685:    fn wants(
2692:    fn entries(
2702:    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | awk 'NR>=560 && NR<=660 {printf "%d: %s\n", NR, $0}'
560: }
561: 
562: /// Map a DAG [`Rejected`] to the M0 wire application-error code.
563: #[must_use]
564: pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
565:     match rej {
566:         Rejected::NotAdmitted => WireError::EpochMismatch,
567:         Rejected::Verification(e) => wire_error_for(e),
568:         Rejected::Feed(_) => WireError::AuthenticatorInvalid,
569:         Rejected::Fork(_) => WireError::AuthenticatorInvalid,
570:         Rejected::GovernanceNotAttributable => WireError::AuthenticatorInvalid,
571:         // A duplicate is not a hard fail; callers handle it before mapping. If it
572:         // ever reaches here, treat as a benign authenticator-class rejection.
573:         Rejected::Duplicate => WireError::AuthenticatorInvalid,
574:     }
575: }
576: 
577: /// The outcome of applying a received `ENTRY` frame.
578: #[derive(Debug)]
579: #[non_exhaustive]
580: pub enum ApplyOutcome {
581:     /// The entry was newly stored.
582:     Stored,
583:     /// The entry was a duplicate (idempotent — already held).
584:     Duplicate,
585:     /// The entry conflicted with a stored one at the same `(author, seq)`: a fork.
586:     /// This is a *local security event*, NOT a wire-protocol violation — it is
587:     /// recorded/surfaced (an attributable fork freezes the author; a deniable one
588:     /// raises an alarm) and sync **continues**. The stream is not closed for a
589:     /// fork (ADR-008 §"Fork / equivocation handling").
590:     Fork,
591: }
592: 
593: /// Apply a received `ENTRY` wire frame to the local [`Dag`] under the full
594: /// acceptance predicate.
595: ///
596: /// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
597: /// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
598: /// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
599: /// (unknown tag, unsupported version, unknown algo, authenticator, …). A
600: /// **fork is not a wire fail**: it is surfaced and sync continues, so two
601: /// partitions can exchange conflicting heads and form the proof.
602: pub fn apply_entry<R: AuthorResolver>(
603:     dag: &mut Dag,
604:     resolver: &R,
605:     admission: &AdmissionPolicy,
606:     entry_wire: &[u8],
607: ) -> std::result::Result<ApplyOutcome, WireError> {
608:     let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
609:     let key = resolver
610:         .key_for(&entry.skeleton.author_id)
611:         .ok_or(WireError::AuthenticatorInvalid)?;
612:     let kind = resolver.kind_for(&entry);
613:     match dag.accept(entry, kind, &key, admission) {
614:         Ok(_) => Ok(ApplyOutcome::Stored),
615:         Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
616:         // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
617:         // not close the stream.
618:         Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
619:         Err(other) => Err(wire_error_for_rejected(&other)),
620:     }
621: }
622: 
623: /// Drive a complete **frontier-mode** session between two peers, each over its
624: /// own [`Transport`] endpoint, to convergence — exercising the real frame path
625: /// (`HELLO`/`HAVE`/`WANT`/`ENTRY`) over the abstract transport. `a` is the
626: /// initiator. `pump` moves frames between the two endpoints (for the in-memory
627: /// duplex it is [`DuplexTransport::pump`]; over QUIC the network is the pump).
628: /// Returns `(applied_into_a, applied_into_b)`.
629: ///
630: /// Protocol per side: send `HELLO` (offering frontier); both compute and send
631: /// `HAVE`; each replies `WANT` for what it lacks; each streams the requested
632: /// `ENTRY` frames; each applies the entries it receives under the full acceptance
633: /// predicate. A malformed/unknown frame or a hard acceptance failure closes the
634: /// transport with the mapped [`WireError`].
635: #[allow(clippy::too_many_arguments)]
636: pub fn frontier_session<TA, TB, R, P>(
637:     ta: &mut TA,
638:     tb: &mut TB,
639:     a: &mut Dag,
640:     b: &mut Dag,
641:     resolver: &R,
642:     admission: &AdmissionPolicy,
643:     pump: P,
644: ) -> std::result::Result<(usize, usize), WireError>
645: where
646:     TA: Transport,
647:     TB: Transport,
648:     R: AuthorResolver,
649:     P: FnMut(&mut TA, &mut TB) -> usize,
650: {
651:     // Centralized fail-and-close: ANY hard fail closes BOTH endpoints with the
652:     // exact coded reason (ADR-008 §"Abort / error signalling" — never a silent
653:     // downgrade, never an unclosed stream).
654:     match frontier_session_inner(ta, tb, a, b, resolver, admission, pump) {
655:         Ok(counts) => Ok(counts),
656:         Err(code) => {
657:             ta.close(code);
658:             tb.close(code);
659:             Err(code)
660:         }
[0m
Now `node/channel.rs` — SyncOutcome, SessionRoom lock granularity, and the apply path:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | awk 'NR>=2090 && NR<=2135 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | awk 'NR>=2650 && NR<=2740 {printf "%d: %s\n", NR, $0}'
2090:             }
2091:         }
2092:         // Reconciliation done; only now surface a session failure, with its coded
2093:         // reason preserved (ADR-008 never downgrades a failure silently).
2094:         Ok(out)
2095:     }
2096: 
2097:     /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
2098:     /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
2099:     ///
2100:     /// # Errors
2101:     /// The room is poisoned, a persist fails, or the session hard-fails.
2102:     pub fn sync_over_room<T: Transport>(
2103:         shared: &tokio::sync::Mutex<Self>,
2104:         store: &Store,
2105:         transport: &mut T,
2106:         now_secs: u64,
2107:     ) -> Result<SyncOutcome> {
2108:         let epoch = {
2109:             let ch = shared.blocking_lock();
2110:             if ch.poisoned {
2111:                 return Err(Error::Profile(
2112:                     "channel is poisoned after a failed persist; reopen it",
2113:                 ));
2114:             }
2115:             ch.epoch
2116:         };
2117:         let room = ChannelSessionRoom {
2118:             shared,
2119:             store,
2120:             now_secs,
2121:             epoch,
2122:             out: std::cell::RefCell::new(SyncOutcome::default()),
2123:             fatal: std::cell::RefCell::new(None),
2124:         };
2125:         let session = crate::log::sync::frontier_session_room(transport, &room);
2126:         if let Some(e) = room.fatal.take() {
2127:             return Err(e);
2128:         }
2129:         let mut out = room.out.into_inner();
2130:         match session {
2131:             Ok(n) => {
2132:                 out.applied = n;
2133:                 Ok(out)
2134:             }
2135:             Err(code) => Err(sync_failure(code)),
---
2650: /// lets go. See [`ChannelState::sync_over_room`].
2651: struct ChannelSessionRoom<'a> {
2652:     shared: &'a tokio::sync::Mutex<ChannelState>,
2653:     store: &'a Store,
2654:     now_secs: u64,
2655:     /// The epoch the session began at; a room that has moved on refuses what was staged for it.
2656:     epoch: u64,
2657:     out: std::cell::RefCell<SyncOutcome>,
2658:     /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
2659:     fatal: std::cell::RefCell<Option<Error>>,
2660: }
2661: 
2662: impl ChannelSessionRoom<'_> {
2663:     fn room(
2664:         &self,
2665:     ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
2666:     {
2667:         let ch = self.shared.blocking_lock();
2668:         if ch.poisoned {
2669:             return Err(crate::wire::WireError::TransportFailed);
2670:         }
2671:         if ch.epoch != self.epoch {
2672:             return Err(crate::wire::WireError::EpochMismatch);
2673:         }
2674:         Ok(ch)
2675:     }
2676: }
2677: 
2678: impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
2679:     fn frontiers(
2680:         &self,
2681:     ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
2682:         Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
2683:     }
2684: 
2685:     fn wants(
2686:         &self,
2687:         remote: &[crate::log::sync::FeedFrontier],
2688:     ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
2689:         Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
2690:     }
2691: 
2692:     fn entries(
2693:         &self,
2694:         wants: &[crate::log::sync::WantRange],
2695:     ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
2696:         Ok(crate::log::sync::entries_for_wants(
2697:             &self.room()?.dag,
2698:             wants,
2699:         ))
2700:     }
2701: 
2702:     fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
2703:         let mut guard = self.room()?;
2704:         let ch = &mut *guard;
2705:         let before = ch.heads();
2706:         // The resolver as it is *now*: an author revoked while this batch was on the wire is not
2707:         // an author of this room any more, and its entries are refused.
2708:         let resolver = ch.resolver();
2709:         // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
2710:         // at a time and stops at the first it refuses; those before it are already in the log.
2711:         // Returning the refusal first skipped persisting and rendering them, yet the log now held
2712:         // them, so every later session saw nothing to send and they were never shown: one joiner
2713:         // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
2714:         // refusal was the other joiner's entry, from an author this node had not admitted yet.
2715:         // `sync_over` always did it in this order ("reconciliation done; only now surface a
2716:         // session failure"); the per-step path lost it.
2717:         let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
2718:         match ch.absorb_arrived(self.store, &before, self.now_secs) {
2719:             Ok(got) => {
2720:                 let mut out = self.out.borrow_mut();
2721:                 out.rendered += got.rendered;
2722:                 out.governance += got.governance;
2723:                 stored
2724:             }
2725:             Err(e) => {
2726:                 *self.fatal.borrow_mut() = Some(e);
2727:                 Err(crate::wire::WireError::TransportFailed)
2728:             }
2729:         }
2730:     }
2731: }
[0m
[0m$ [0mawk 'NR>=210 && NR<=230 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs; echo ---; awk 'NR>=305 && NR<=330 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs
210:     pub fn authors(&self) -> Vec<Digest32> {
211:         let mut a: Vec<Digest32> = self.feeds.keys().copied().collect();
212:         a.sort_unstable();
213:         a
214:     }
215: 
216:     /// Whether `author` has been frozen by a fork proof.
217:     #[must_use]
218:     pub fn is_frozen(&self, author: &Digest32) -> bool {
219:         self.frozen.contains_key(author)
220:     }
221: 
222:     /// The recorded fork proof for a frozen author, if any.
223:     #[must_use]
224:     pub fn fork_proof(&self, author: &Digest32) -> Option<&ForkProof> {
225:         self.frozen.get(author)
226:     }
227: 
228:     /// Look up a stored entry by its 32-byte hash (the Negentropy key).
229:     #[must_use]
230:     pub fn get_by_hash(&self, hash: &Digest32) -> Option<&Entry> {
---
305:         // authenticator on a governance entry is rejected outright, so the
306:         // governance plane — and its fork attribution — stays intact even in
307:         // deniable channels.
308:         if matches!(kind, EntryKind::Governance) && !entry.authenticator.is_attributable() {
309:             return Err(Rejected::GovernanceNotAttributable);
310:         }
311: 
312:         // A frozen author's further entries are refused outright.
313:         if self.frozen.contains_key(&author) {
314:             return Err(Rejected::NotAdmitted);
315:         }
316: 
317:         // Idempotent duplicate.
318:         if self.by_hash.contains_key(&hash) {
319:             return Err(Rejected::Duplicate);
320:         }
321: 
322:         // Admission.
323:         if !admission.is_admitted(&channel, epoch, &author) {
324:             return Err(Rejected::NotAdmitted);
325:         }
326: 
327:         // Authenticator + structure (deniable verified via the M7 seam if given).
328:         // This precedes equivocation classification on purpose: only an entry
329:         // that is admitted AND authenticates may surface a fork proof / alarm.
330:         entry
[0m
[0m$ [0mawk 'NR>=95 && NR<=120 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/feed.rs; echo ---; awk 'NR>=190 && NR<=232 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/feed.rs
95:         if m != po3 {
96:             po3 = m;
97:         }
98:     }
99:     n - po3
100: }
101: 
102: /// A per-author hash-linked feed: the ordered entries `1..=len`, indexed by seq.
103: ///
104: /// The feed enforces single-writer append: every entry shares one `author_id`,
105: /// `seq` is contiguous from 1, and `prev_hash`/`lipmaa_backlink` must name the
106: /// hashes of the entries they point at. An entry after one whose `end_of_feed`
107: /// flag is set is rejected.
108: #[derive(Debug, Default, Clone)]
109: pub struct Feed {
110:     author_id: Option<Digest32>,
111:     /// seq -> entry. A `BTreeMap` keeps entries seq-ordered for iteration and
112:     /// makes the contiguity check a simple range walk.
113:     entries: BTreeMap<u64, Entry>,
114: }
115: 
116: impl Feed {
117:     /// An empty feed (no author bound yet).
118:     #[must_use]
119:     pub fn new() -> Self {
120:         Self {
---
190:     /// [`Error::MalformedJoin`]-free, log-specific errors on any violation.
191:     ///
192:     /// The caller is responsible for the *authenticator* (call [`Entry::verify`]
193:     /// before append, or use [`Feed::append_verified`]); this method enforces the
194:     /// structural feed invariants the signature does not cover.
195:     pub fn append(&mut self, entry: Entry) -> Result<()> {
196:         self.validate_next(&entry)?;
197:         let seq = entry.skeleton.seq;
198:         if self.author_id.is_none() {
199:             self.author_id = Some(entry.skeleton.author_id);
200:         }
201:         self.entries.insert(seq, entry);
202:         Ok(())
203:     }
204: 
205:     /// Validate that `entry` would be a legal next append — single author,
206:     /// contiguous monotonic `seq`, no append past end-of-feed, and correct
207:     /// `prev_hash`/`lipmaa_backlink` — **without** mutating the feed, so a caller
208:     /// can gate side effects on it before the insert and a later rejection never
209:     /// leaves partial state.
210:     pub fn validate_next(&self, entry: &Entry) -> Result<()> {
211:         let seq = entry.skeleton.seq;
212: 
213:         // Bound the sequence so the lipmaa power-of-three arithmetic stays
214:         // overflow-free (ADR-008; see [`MAX_SEQ`]).
215:         if seq > MAX_SEQ {
216:             return Err(Error::SizeLimitExceeded("feed seq exceeds MAX_SEQ"));
217:         }
218: 
219:         // Single-writer: every entry shares the feed's author.
220:         match self.author_id {
221:             None => {}
222:             Some(a) if a == entry.skeleton.author_id => {}
223:             Some(_) => return Err(Error::MalformedBundle("feed author mismatch")),
224:         }
225: 
226:         // Contiguous, monotonic from 1.
227:         let expected = self.max_seq() + 1;
228:         if seq != expected {
229:             return Err(Error::MalformedBundle("feed seq not contiguous"));
230:         }
231: 
232:         // No append past an end-of-feed marker.
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=3360 && NR<=3400 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=3440 && NR<=3470 {printf "%d: %s\n", NR, $0}'
3360:             }
3361:             NetEvent::PushRetry { channel_id, peer } => {
3362:                 self.pending_push.insert(channel_id);
3363:                 // The failed session carried nothing, so this peer is owed the room again.
3364:                 if let Some(to) = self.pushed_to.get_mut(&channel_id) {
3365:                     to.remove(&peer);
3366:                 }
3367:                 if let Some(schedule) = self.schedules.get_mut(&peer) {
3368:                     schedule.note_local_append();
3369:                 }
3370:                 self.owed_first.insert(peer);
3371:                 self.push_now = true;
3372:             }
3373:             NetEvent::SyncDone {
3374:                 channel_id,
3375:                 peer,
3376:                 outcome,
3377:             } => {
3378:                 self.syncing.remove(&(channel_id, peer));
3379:                 self.answer_pending_consents(|room, _| *room == channel_id, None)
3380:                     .await;
3381:                 // **A session that failed delivered nothing, so its push is owed again.**
3382:                 // `run_due_syncs` counts a push as done when the session *starts*, which is the
3383:                 // only thing it can know then; a session the peer refused — because its own
3384:                 // session for this room was running — or that died on the wire carried nothing, and
3385:                 // the entry waited for the peer's next 30s interval. Measured over a forced relay
3386:                 // once pushes went out at once instead of on the tick: median 40–110ms, and a tail
3387:                 // at exactly 30s (p95 29.7–30.0s) — the collisions an immediate push makes more
3388:                 // likely. Owed again, retried on the *next tick* and not at once: a peer that keeps
3389:                 // refusing must not be answered with a tight loop.
3390:                 //
3391:                 // **Owed to that peer only, and not for ever.** The first version re-owed the room to
3392:                 // *every* peer, every time any session failed. A peer whose sessions always fail —
3393:                 // an anchor that keeps no log for the room refuses every one — was then re-owed
3394:                 // every tick, sorted ahead of the member it shared the room with, took the room each
3395:                 // pass, and the member's owed push lost every round: the independent verdict
3396:                 // measured 2–3 relayed runs in 10 losing a message for 120s (vox-bc, #41). Now the
3397:                 // retry goes to the peer that failed, at most `MAX_PUSH_RETRIES` times running; past
3398:                 // that the pair waits for the periodic interval like any other.
3399:                 //
3400:                 // **After a short random wait, not the next tick.** The commonest failure is a
---
3440:                     // authors and mirrored records onto this node's board, and both change who may
3441:                     // reach whom and what the anchors should hold. `learn_members` used to do this
3442:                     // inline, which is how a round trip ended up on the single writer.
3443:                     //
3444:                     // **Only when the session actually brought something in**, which is the guard
3445:                     // the original had (`if learned > 0`, `if gained > 0`) and I dropped when moving
3446:                     // this out. Without it the actor did a publish round trip after *every* sync,
3447:                     // and syncs are frequent: measured, that turned a 0-1s crossing into 20s in
3448:                     // seven runs of ten while removing the losses. Losses gone is the right trade;
3449:                     // paying a publish per sync for it is not.
3450:                     if o.applied > 0 {
3451:                         self.note_local_append(&channel_id);
3452:                         self.refresh_reachers().await;
3453:                         self.publish_channel_to_anchors(&channel_id).await;
3454:                     }
3455:                     // **A newcomer this session admitted is consented to now, not on the tick.** Two
3456:                     // members who joined the same room learn of each other only here, from the board.
3457:                     // Under ForwardOnly a post sealed before the author consents to a reader is never
3458:                     // readable to it, so every tick of delay is a window of posts lost to the
3459:                     // newcomer. Measured in room_of_three_keys_proof: the joiners' keys to each other
3460:                     // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
3461:                     // close it, since nobody can consent to a member it has not yet heard of.
3462:                     if !self.trust.is_empty() {
3463:                         let trusted = self.trust.trusted();
3464:                         let owes = match self.channels.get(&channel_id).map(Arc::clone) {
3465:                             Some(shared) => !shared.lock().await.owed_consents(&trusted).is_empty(),
3466:                             None => false,
3467:                         };
3468:                         if owes {
3469:                             self.deliver_owed_consents(None).await;
3470:                         }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=4715 && NR<=4745 {printf "%d: %s\n", NR, $0}'; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs | awk 'NR>=85 && NR<=120 {printf "%d: %s\n", NR, $0}'
4715:             )
4716:             .await;
4717:         }
4718:         self.refresh_network_view().await;
4719:         self.note_local_append(channel_id);
4720:     }
4721: 
4722:     /// Whether a sync session with `peer` is running on `channel_id`: the collision a new
4723:     /// session with that peer for that room must not start into (see `syncing`).
4724:     fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
4725:         self.syncing.contains(&(*channel_id, *peer))
4726:     }
4727: 
4728:     /// Mark a channel as having a local append to push, and make every peer's
4729:     /// schedule due (ADR-016: "a push immediately after a local append").
4730:     fn note_local_append(&mut self, channel_id: &Digest32) {
4731:         if self.net.is_none() {
4732:             return;
4733:         }
4734:         self.push_now = true;
4735:         self.pending_push.insert(*channel_id);
4736:         // Something new: every peer is owed it again, including those that had the last one.
4737:         self.pushed_to.remove(channel_id);
4738:         for schedule in self.schedules.values_mut() {
4739:             schedule.note_local_append();
4740:         }
4741:     }
4742: 
4743:     /// Run whatever the ADR-016 sync schedule says is due. Returns whether anything
4744:     /// ran, so the caller only republishes the view when it might have changed.
4745:     ///
---
85: 
86:     /// Record a local append: the next check pushes it out without waiting for the
87:     /// interval.
88:     pub fn note_local_append(&mut self) {
89:         self.pending_append = true;
90:     }
91: 
92:     /// Record that a session ran at `now_secs`.
93:     pub fn note_synced(&mut self, now_secs: u64) {
94:         self.last_sync = now_secs;
95:         self.pending_append = false;
96:     }
97: 
98:     /// The trigger due at `now_secs`, if any. A local append wins over the
99:     /// interval, and the first call after [`SyncSchedule::connected`] is
100:     /// `Connected`.
101:     #[must_use]
102:     pub fn due(&self, now_secs: u64) -> Option<SyncTrigger> {
103:         if self.last_sync == 0 {
104:             return Some(SyncTrigger::Connected);
105:         }
106:         if self.pending_append {
107:             return Some(SyncTrigger::LocalAppend);
108:         }
109:         if now_secs.saturating_sub(self.last_sync) >= SYNC_INTERVAL_SECS {
110:             return Some(SyncTrigger::Periodic);
111:         }
112:         None
113:     }
114: }
115: 
116: impl Default for SyncSchedule {
117:     fn default() -> Self {
118:         Self::connected()
119:     }
120: }
[0m
[0m$ [0mawk 'NR>=5220 && NR<=5250 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs; echo ---; awk 'NR>=5295 && NR<=5320 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs
5220:         // exists to remove. A reset reaches it on the next read, and its schedule brings it
5221:         // back in a second.
5222:         //
5223:         // **Refused before the lock, not after.** A session holds this room's mutex for its whole
5224:         // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
5225:         // behind the very session this check exists to detect.
5226:         if self.syncing.contains(&channel_id) {
5227:             let (mut send, mut recv) = (send, recv);
5228:             if self.owed_a_reason(&channel_id, &peer, epoch) {
5229:                 // Busy: our own session for this room is running (with this peer, a collision, or
5230:                 // with another). Said to a room peer, so its session ends as `SessionBusy`, not as
5231:                 // a transport failure (#202).
5232:                 crate::node::net::refuse_stream_because(
5233:                     &mut send,
5234:                     &mut recv,
5235:                     crate::wire::WireError::SessionBusy,
5236:                 );
5237:             } else {
5238:                 crate::node::net::refuse_stream(&mut send, &mut recv);
5239:             }
5240:             return;
5241:         }
5242:         // Only a channel we hold open at that epoch — or keep as an anchor — can be
5243:         // reconciled. An anchor whose board just received the genesis adopts it here
5244:         // rather than making the member wait for the next tick.
5245:         if !self.channels.contains_key(&channel_id) {
5246:             self.adopt_anchored(&channel_id).await;
5247:             self.refresh_anchored_authors(&channel_id).await;
5248:         }
5249:         let matches_epoch = match (
5250:             self.channels.get(&channel_id),
---
5295:     ///   Admission there takes the same M17.6 evidence as everywhere else.
5296:     /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
5297:     ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
5298:     ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
5299:     ///   room's link is not an anchor of this one.
5300:     ///
5301:     /// For a room this node only anchors, the peer must be an author the board knows.
5302:     /// Whether a refusal may tell `peer` **why** (#202): it is this room's session partner, or it
5303:     /// has a member record for the room on the board. Decided without the room's lock, because
5304:     /// the refusals that ask run before it. Anyone else is refused with the uninformative code,
5305:     /// so a stranger who names a room learns nothing about whether this node holds it.
5306:     fn owed_a_reason(&self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
5307:         self.syncing_with.get(channel_id) == Some(peer)
5308:             || self.net.as_ref().is_some_and(|net| {
5309:                 net.board_bundles(channel_id, epoch)
5310:                     .iter()
5311:                     .any(|b| b.author_id == *peer)
5312:             })
5313:     }
5314: 
5315:     async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
5316:         if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
5317:             {
5318:                 let channel = shared.lock().await;
5319:                 if channel.is_author(peer)
5320:                     || channel.anchors().nodes().iter().any(|a| a.id == *peer)
[0m
Now the 202-tree citations:
[0m$ [0mawk 'NR>=825 && NR<=900 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs
825:             // compute identically; the class is the connection's own recorded fact (see
826:             // [`path_class`]), not a reading of a table that changes underneath it.
827:             if is_live(existing) && self.is_dead(existing) {
828:                 existing.close(WireError::Unresponsive);
829:             } else if is_live(existing) {
830:                 let existing = Arc::clone(existing);
831:                 let (new_class, held_class) = (
832:                     path_class(&self.endpoint, &conn),
833:                     path_class(&self.endpoint, &existing),
834:                 );
835:                 let newcomer_loses = new_class < held_class
836:                     || (new_class == held_class && tie_key(&conn) >= tie_key(&existing));
837:                 if newcomer_loses {
838:                     drop(map);
839:                     if !serve_loser {
840:                         conn.close(WireError::AuthenticatorInvalid);
841:                         return Filed {
842:                             kept: existing,
843:                             also_serve: None,
844:                         };
845:                     }
846:                     let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
847:                     let retired = Arc::new(conn);
848:                     lock(&self.retiring).push((Arc::clone(&retired), retire_at));
849:                     return Filed {
850:                         kept: existing,
851:                         also_serve: Some(retired),
852:                     };
853:                 }
854:                 let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
855:                 lock(&self.retiring).push((existing, retire_at));
856:             }
857:         }
858:         let conn = Arc::new(conn);
859:         // The baseline for its silence: it has just completed a handshake, so it was heard now.
860:         let _ = self.silent_for(&conn);
861:         map.insert(peer, Arc::clone(&conn));
862:         Filed {
863:             kept: conn,
864:             also_serve: None,
865:         }
866:     }
867: 
868:     /// How long a retired connection is kept readable before it is closed.
869:     #[must_use]
870:     pub fn retire_grace_secs(&self) -> u64 {
871:         self.retire_grace_secs
872:     }
873: 
874:     /// Close every retired connection whose grace has elapsed (or that the peer
875:     /// already closed). Returns how many were closed. The node's tick calls this.
876:     pub fn retire_expired(&self) -> usize {
877:         let now = (self.clock)();
878:         let mut retiring = lock(&self.retiring);
879:         let before = retiring.len();
880:         retiring.retain(|(conn, at)| {
881:             // **Still carried** means somebody other than this list holds the connection:
882:             // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
883:             // long as they run, so the strong count is the liveness signal, and it needs no
884:             // bookkeeping that could disagree with reality.
885:             //
886:             // The grace alone is not enough to close on. It is sized for a request finishing
887:             // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
888:             // file transfer is in flight for hours. Closing on the timer killed live sessions
889:             // mid-stream whenever a better path displaced the one they were on, which reached
890:             // the person as `Connection reset by peer` in the middle of their work.
891:             let still_carried = Arc::strong_count(conn) > 1;
892:             if (now >= *at && !still_carried) || !is_live(conn) {
893:                 conn.close(WireError::AuthenticatorInvalid);
894:                 false
895:             } else {
896:                 true
897:             }
898:         });
899:         before - retiring.len()
900:     }
[0m
[0m$ [0mawk 'NR>=1800 && NR<=1845 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs; echo ---; awk 'NR>=1930 && NR<=1950 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs
1800:     /// say otherwise.
1801:     ///
1802:     /// The remaining consenters are re-keyed by the caller (the node's tick, from
1803:     /// [`ChannelState::owed_rekeys`]); the rotation does not wait on that, because a
1804:     /// revocation that took effect only once everyone else was reachable would be no
1805:     /// revocation at all.
1806:     pub fn revoke_consent(
1807:         &mut self,
1808:         profile: &Profile,
1809:         target: Digest32,
1810:         now_secs: u64,
1811:     ) -> Result<ConsentRevocation> {
1812:         let me = self.me();
1813:         if target == me {
1814:             return Err(Error::MalformedGovernance(
1815:                 "an identity cannot revoke its own consent",
1816:             ));
1817:         }
1818:         if !MembershipView::new(&self.evaluator)
1819:             .readers_of(&me)
1820:             .contains(&target)
1821:         {
1822:             return Err(Error::MalformedGovernance("no consent to revoke"));
1823:         }
1824:         // Rotate first: the entry names the generation that excludes `target`, so
1825:         // that generation has to exist before the fact is signed.
1826:         let new_chain_id = self.rotate_sender(profile.store(), now_secs)?;
1827:         let signer = profile.signer()?;
1828:         let revocation =
1829:             issue_consent_revocation(signer, &self.channel_id, self.epoch, target, new_chain_id)?;
1830:         self.append_governance(profile, &revocation.to_wire(), now_secs)?;
1831:         // Nothing is owed to a revoked member; drop the row so a later re-consent
1832:         // starts from "holds nothing".
1833:         if self.delivered.remove(&target).is_some() {
1834:             self.persist_delivered(profile.store())?;
1835:         }
1836:         Ok(revocation)
1837:     }
1838: 
1839:     /// Forget that `target` holds this identity's current sender key, so the next
1840:     /// re-key round delivers it again (ADR-021 F12).
1841:     ///
1842:     /// For when the pairwise session a key was delivered over has been replaced by the
1843:     /// one both ends keep: what was sealed under the dropped session cannot be opened.
1844:     ///
1845:     /// # Errors
---
1930:     /// hashes accepted so far (ADR-007's causal relation is only ever *followed*,
1931:     /// never trusted for authority).
1932:     fn gov_heads(&self) -> std::collections::BTreeSet<Digest32> {
1933:         self.gov_entries.iter().map(|g| g.entry_hash).collect()
1934:     }
1935: 
1936:     /// The resolver ADR-008 sync needs: this channel's admitted authors and the
1937:     /// entry classification for `kind_for`.
1938:     #[must_use]
1939:     pub fn resolver(&self) -> ChannelAuthors {
1940:         ChannelAuthors {
1941:             authors: self.authors.clone(),
1942:         }
1943:     }
1944: 
1945:     /// Run one ADR-008 **frontier sync** session over `transport` against a peer,
1946:     /// then durably record and render whatever arrived (ADR-016 §"Sync
1947:     /// scheduling").
1948:     ///
1949:     /// Sync is ADR-008's business and applies entries to the log itself; this method
1950:     /// is the reconciliation the runtime owes afterwards. It snapshots each author's
[0m
[0m$ [0mawk 'NR>=2040 && NR<=2110 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs
(no output)
[0m
[0m$ [0mgrep -n "poisoned" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs | head -20; echo ---; grep -n "QUICK_PUSH_RETRIES\|MAX_PUSH_RETRIES\|backoff\|jitter\|20.*100\|8 s\|8s" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs | head -30
26://!   is marked **poisoned** and refuses further appends until reopened — the
312:    poisoned: bool,
325:            .field("poisoned", &self.poisoned)
821:            poisoned: false,
1009:            poisoned: false,
1224:            poisoned: false,
1351:            self.poisoned = true;
1396:            self.poisoned = true;
1494:            self.poisoned = true;
1514:            self.poisoned = true;
1620:        if self.poisoned {
1622:                "channel is poisoned after a failed persist; reopen it",
1665:            self.poisoned = true;
1867:            self.poisoned = true;
1886:        if self.poisoned {
1888:                "channel is poisoned after a failed persist; reopen it",
1915:            self.poisoned = true;
1975:        if self.poisoned {
1977:                "channel is poisoned after a failed persist; reopen it",
2051:                self.poisoned = true;
---
98:/// A channel's state, shared so a long-running ADR-008 session can hold it without
175:/// How many failed sessions in a row a `(room, peer)` push retries after a short random 20–100ms
178:const QUICK_PUSH_RETRIES: u32 = 3;
591:    /// A sender key written to `peer` was taken: any backoff on re-sending to it ends.
1664:    /// Per-peer ADR-008 sync clock (ADR-016 §"Sync scheduling").
1785:    key_backoff: BTreeMap<(Digest32, Digest32), (u32, u64)>,
1965:            key_backoff: BTreeMap::new(),
2492:    /// ADR-008 session then hard-fails on its first entry. A refusal is normal (the
3324:                let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
3363:                self.key_backoff.remove(&(channel_id, peer));
3419:                // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
3423:                // other six times in ~200ms, because their 20–100ms random waits kept landing within
3425:                // `QUICK_PUSH_RETRIES` keep the 20–100ms random wait, and past them the push is
3433:                    let jitter = crate::identity::rng::random_array::<2>()
3435:                    let wait = if *failures <= QUICK_PUSH_RETRIES {
3438:                        Duration::from_millis(20 + jitter % 81)
3444:                        let w = (200u64 << (*failures - QUICK_PUSH_RETRIES - 1).min(6)).min(
3449:                        Duration::from_millis(from + jitter % span.max(1))
4662:            // A member whose last keys were not taken waits out its backoff, unless a person asked.
4665:                    .key_backoff
4960:        // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
[0m
[0m$ [0mgrep -n "sync_slots\|SYNC_SLOTS\|Semaphore::new" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs | head; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "sync_slots\|Semaphore::new\|MAX_SYNC" | head
989:        let gate = Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_IN_FLIGHT));
1677:    sync_slots: Arc<tokio::sync::Semaphore>,
1946:            sync_slots: Arc::new(tokio::sync::Semaphore::new(SYNCS_IN_FLIGHT)),
1949:            join_slots: Arc::new(tokio::sync::Semaphore::new(JOINS_IN_FLIGHT)),
5010:        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
---
989:        let gate = Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_IN_FLIGHT));
1664:    sync_slots: Arc<tokio::sync::Semaphore>,
1938:            sync_slots: Arc::new(tokio::sync::Semaphore::new(SYNCS_IN_FLIGHT)),
1941:            join_slots: Arc::new(tokio::sync::Semaphore::new(JOINS_IN_FLIGHT)),
5023:        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
[0m
[0m$ [0mawk 'NR>=75 && NR<=115 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/streams.rs; echo ---; awk 'NR>=405 && NR<=425 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/anchor.rs
75:         let v = u8::try_from(d.uint()?).map_err(|_| Error::MalformedBundle("stream kind range"))?;
76:         d.finish()?;
77:         Self::from_u8(v).ok_or(Error::MalformedBundle("unknown stream kind"))
78:     }
79: }
80: 
81: /// Open a bi-stream on `conn` typed as `kind` (the kind frame is written first).
82: pub async fn open_typed(
83:     conn: &VoxConnection,
84:     kind: StreamKind,
85: ) -> Result<(SendStream, RecvStream)> {
86:     let (mut send, recv) = conn.open_stream().await?;
87:     write_frame(&mut send, &kind.frame()).await?;
88:     Ok((send, recv))
89: }
90: 
91: /// Accept the next bi-stream on `conn` and read its kind frame. A stream the peer
92: /// closes before typing it, or types with an unknown kind, is an error.
93: pub async fn accept_typed(conn: &VoxConnection) -> Result<(StreamKind, SendStream, RecvStream)> {
94:     accept_typed_on(conn.quinn()).await
95: }
96: 
97: /// [`accept_typed`] on the bare quinn handle, for a caller that must wait for streams
98: /// **without holding the [`VoxConnection`]** — the node's per-connection stream loop, which
99: /// would otherwise count as a user of the connection for as long as the connection lives.
100: pub async fn accept_typed_on(
101:     conn: &quinn::Connection,
102: ) -> Result<(StreamKind, SendStream, RecvStream)> {
103:     let (send, mut recv) = conn
104:         .accept_bi()
105:         .await
106:         .map_err(|_| Error::Unreachable("quic stream: the connection is closed"))?;
107:     let frame = read_frame(&mut recv, MAX_KIND_FRAME)
108:         .await?
109:         .ok_or(Error::MalformedBundle("stream closed before kind"))?;
110:     let kind = StreamKind::parse(&frame)?;
111:     Ok((kind, send, recv))
112: }
---
405:     store: &'a Store,
406:     epoch: u64,
407:     out: std::cell::RefCell<SyncOutcome>,
408:     fatal: std::cell::RefCell<Option<Error>>,
409: }
410: 
411: impl AnchorSessionRoom<'_> {
412:     fn copy(
413:         &self,
414:     ) -> std::result::Result<tokio::sync::MutexGuard<'_, AnchorState>, crate::wire::WireError> {
415:         let st = self.shared.blocking_lock();
416:         if st.poisoned {
417:             return Err(crate::wire::WireError::TransportFailed);
418:         }
419:         if st.epoch != self.epoch {
420:             return Err(crate::wire::WireError::EpochMismatch);
421:         }
422:         Ok(st)
423:     }
424: }
425:
[0m
[0m$ [0mgrep -n "SYNCS_IN_FLIGHT\s*:" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "SYNCS_IN_FLIGHT"; echo ---; awk 'NR>=5160 && NR<=5195 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs
240:const SYNCS_IN_FLIGHT: usize = 16;
130:/// time. One deadline for the whole view, not one per room: with `SYNCS_IN_FLIGHT` sessions each
240:const SYNCS_IN_FLIGHT: usize = 16;
253:/// queued** — the same rule as [`SYNCS_IN_FLIGHT`], and for a stronger reason here: a queue of
1663:    /// Slots for sync setups and sessions; see [`SYNCS_IN_FLIGHT`].
1938:            sync_slots: Arc::new(tokio::sync::Semaphore::new(SYNCS_IN_FLIGHT)),
---
5160:                     outcome,
5161:                 })
5162:                 .await;
5163:         });
5164:     }
5165: 
5166:     /// Reconcile a channel with every member this node can reach, now (the `Sync`
5167:     /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
5168:     async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
5169:         if self.net.is_none() {
5170:             return Outcome::Failed(Fault::NotNetworked);
5171:         }
5172:         let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
5173:             return Outcome::Failed(Fault::UnknownChannel);
5174:         };
5175:         let peers: Vec<Digest32> = {
5176:             let channel = shared.lock().await;
5177:             let me = channel.me();
5178:             channel.members().into_iter().filter(|m| *m != me).collect()
5179:         };
5180:         let mut synced = 0usize;
5181:         for peer in peers {
5182:             if self.sync_one(channel_id, peer).await {
5183:                 synced += 1;
5184:             }
5185:         }
5186:         if synced == 0 {
5187:             return Outcome::Failed(Fault::Unreachable);
5188:         }
5189:         Outcome::Done
5190:     }
5191: 
5192:     /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
5193:     /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
5194:     /// Serve one sync session for a request that has **already been read**.
5195:     ///
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=228 && NR<=260 {printf "%d: %s\n", NR, $0}'
228: /// `SYNC_FRAME_TIMEOUT`, so a peer that went quiet mid-setup stopped the node for twenty seconds and
229: /// it answered nobody — including the pushes it had just marked owed. Measured on an anchor, which is
230: /// the node it hurts most because it is the hop a message takes when two members are never online
231: /// together:
232: ///
233: /// ```text
234: /// vox node: took 1 entry for room 4yxukqstptuq
235: /// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
236: /// ```
237: ///
238: /// Past the cap a sync is **skipped, not queued**: the schedule comes round again, and a queue of
239: /// sessions for rooms whose state has since moved on is worse than none.
240: const SYNCS_IN_FLIGHT: usize = 16;
241: 
242: /// How many inbound joins this node answers at once.
243: ///
244: /// Answering a join is the one inbound thing a **stranger** can ask for: the passphrase is the
245: /// join credential, so anyone holding the address and the passphrase gets an exchange, and the
246: /// exchange waits on them three times and verifies their proof of work. Run on the actor, that
247: /// made one joiner — slow, malicious, or merely behind a bad link — able to stop a node from
248: /// answering anybody: no messages, no syncs, nothing, for as long as it cared to stall. An anchor
249: /// is the worst place for it, because the whole point of an anchor is being the node that is
250: /// always there.
251: ///
252: /// So the actor decides and a slot does the waiting. Past the cap a join is **refused, not
253: /// queued** — the same rule as [`SYNCS_IN_FLIGHT`], and for a stronger reason here: a queue of
254: /// half-finished exchanges is exactly the resource a flood wants to fill, and a joiner that is
255: /// told "no" now retries in a second, which is cheaper for both sides than a held stream.
256: ///
257: /// The count of joins actually in flight also feeds `Difficulty::adapted_for_load`, which raises
258: /// the proof-of-work a joiner must do as the load climbs. That knob existed all along and was
259: /// passed a hardcoded `0`, so it had never once adapted.
260: const JOINS_IN_FLIGHT: usize = 16;
[0m
[0m$ [0mgrep -n "max_concurrent\|max_concurrent_bidi\|stream_concurrency\|VarInt::from_u32(100)\|bidi" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs | head; echo ---; grep -rn "max_concurrent" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/ | head
7://! its own bidirectional stream ([`VoxConnection::open_stream`] /
199:/// [`STREAM_WINDOW`] a peer may open quinn's default 100 concurrent bidirectional streams, so an
764:    /// Open a fresh outbound bidirectional stream for a logical flow.
784:    /// Accept the next inbound bidirectional stream the peer opened.
---
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=4340 && NR<=4400 {printf "%d: %s\n", NR, $0}'
4340:             .is_some_and(|n| n.manager().existing(&target).is_some());
4341:         if connected {
4342:             // Started or not (a session with this same member may already be running), the retry
4343:             // rides the next `SyncDone` of a session **with the target**. Checking for any session
4344:             // on the room kept a consent waiting on sessions with other members, which, now that
4345:             // sessions are guarded per (room, peer), need never all end.
4346:             let _ = self.sync_one(&channel_id, target).await;
4347:             if !self.in_session_with(&channel_id, &target) {
4348:                 let _ = reply.send(outcome);
4349:                 return;
4350:             }
4351:         } else if attempts > 0 {
4352:             // A dial already landed once for this consent and the connection is gone again.
4353:             let _ = reply.send(outcome);
4354:             return;
4355:         }
4356:         self.pending_consents
4357:             .push((channel_id, target, reply, attempts.saturating_add(1)));
4358:     }
4359: 
4360:     /// Retry the explicit consents `matches` selects (`Dialed` passes its peer, `SyncDone` its
4361:     /// room), or answer them all with `failed` (`ReachFailed`).
4362:     async fn answer_pending_consents(
4363:         &mut self,
4364:         matches: impl Fn(&Digest32, &Digest32) -> bool,
4365:         failed: Option<Outcome>,
4366:     ) {
4367:         let (waiting, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_consents)
4368:             .into_iter()
4369:             .partition(|(room, target, _, _)| matches(room, target));
4370:         self.pending_consents = rest;
4371:         if waiting.is_empty() {
4372:             return;
4373:         }
4374:         for (channel_id, target, reply, attempts) in waiting {
4375:             match failed {
4376:                 Some(o) => {
4377:                     let _ = reply.send(o);
4378:                 }
4379:                 None => {
4380:                     // Still waiting on its dial: that is `Dialed`'s or `ReachFailed`'s to answer, not
4381:                     // a session with somebody else that happened to finish first.
4382:                     let connected = self
4383:                         .net
4384:                         .as_ref()
4385:                         .is_some_and(|n| n.manager().existing(&target).is_some());
4386:                     if !connected {
4387:                         self.pending_consents
4388:                             .push((channel_id, target, reply, attempts));
4389:                         continue;
4390:                     }
4391:                     let outcome = self.consent(&channel_id, target, false).await;
4392:                     self.settle_consent(channel_id, target, reply, outcome, attempts)
4393:                         .await;
4394:                 }
4395:             }
4396:         }
4397:         // The view reflects whatever was granted before anyone reads it.
4398:         self.publish().await;
4399:     }
4400:
[0m
[0m$ [0mawk 'NR>=5242 && NR<=5295 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs
5242:         // Only a channel we hold open at that epoch — or keep as an anchor — can be
5243:         // reconciled. An anchor whose board just received the genesis adopts it here
5244:         // rather than making the member wait for the next tick.
5245:         if !self.channels.contains_key(&channel_id) {
5246:             self.adopt_anchored(&channel_id).await;
5247:             self.refresh_anchored_authors(&channel_id).await;
5248:         }
5249:         let matches_epoch = match (
5250:             self.channels.get(&channel_id),
5251:             self.anchored.get(&channel_id),
5252:         ) {
5253:             (Some(shared), _) => shared.lock().await.epoch() == epoch,
5254:             (None, Some(state)) => state.lock().await.epoch() == epoch,
5255:             (None, None) => false,
5256:         };
5257: 
5258:         // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
5259:         // no log for it, most often — or at an epoch it is not at, returned here and let the streams
5260:         // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
5261:         // connection that died. Every push to an anchor that keeps no log for the room read as a
5262:         // network fault. A coded reset says what happened. (It does not recover time: a dropped
5263:         // stream already ended the initiator's session within milliseconds, measured; the long
5264:         // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
5265:         if !matches_epoch {
5266:             let (mut send, mut recv) = (send, recv);
5267:             if self.owed_a_reason(&channel_id, &peer, epoch) {
5268:                 crate::node::net::refuse_stream_because(
5269:                     &mut send,
5270:                     &mut recv,
5271:                     crate::wire::WireError::EpochMismatch,
5272:                 );
5273:             } else {
5274:                 crate::node::net::refuse_stream(&mut send, &mut recv);
5275:             }
5276:             return;
5277:         }
5278:         if !self.may_sync(&channel_id, &peer, epoch).await {
5279:             // Refused explicitly, with the same coded reset as a stream kind the peer may not
5280:             // open, rather than left to read for a frame that never comes.
5281:             let (mut send, mut recv) = (send, recv);
5282:             crate::node::net::refuse_stream(&mut send, &mut recv);
5283:             return;
5284:         }
5285:         let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
5286:         self.start_session(channel_id, peer, transport);
5287:     }
5288: 
5289:     /// Whether `peer` may reconcile `channel_id`'s log with this node.
5290:     ///
5291:     /// - An **admitted author** of that room. If it is not one yet, this node's own board is
5292:     ///   consulted first — local, so cheap — because a member that joined through somebody
5293:     ///   else is on the board before it is in this node's author table, and refusing it for
5294:     ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
5295:     ///   Admission there takes the same M17.6 evidence as everywhere else.
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-adr025 log --oneline -8 -- docs/adr/ADR-025-sync-scheduling-switch-not-hub.md; echo ---; git -C /opt/vox/.claude/worktrees/ac-adr025 log --oneline -4; echo ---; git -C /opt/vox/.claude/worktrees/ac-adr025 status --short | head
141dc11 docs(adr): ADR-025 revision 3 — full duplex (no busy refusals), request lifecycle, receive coverage, observable proofs; round-2 astra review
16951fe docs(adr): ADR-025 revision 2 — designated opener, observable completion, rebuilt proofs; round-1 reviews (astra BLOCK, glm REVISE, kimi REVISE)
8c4e347 docs(adr): ADR-025 draft — sync is scheduled like a switch, not a hub (for review)
---
141dc11 docs(adr): ADR-025 revision 3 — full duplex (no busy refusals), request lifecycle, receive coverage, observable proofs; round-2 astra review
16951fe docs(adr): ADR-025 revision 2 — designated opener, observable completion, rebuilt proofs; round-1 reviews (astra BLOCK, glm REVISE, kimi REVISE)
8c4e347 docs(adr): ADR-025 draft — sync is scheduled like a switch, not a hub (for review)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
---
?? docs/adr/ADR-025-reviews/review3-astra.md
?? docs/adr/ADR-025-reviews/review3-glm-5.3.md
?? docs/adr/ADR-025-reviews/review3-kimi-k3.md
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "push_now" | head -20; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "MAX_STAGED" ; grep -n "MAX_STREAM_FRAME" /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs | head -3
1754:    push_now: bool,
1950:            push_now: false,
3356:                self.push_now = true;
3371:                self.push_now = true;
3426:                    self.push_now = true;
4734:        self.push_now = true;
4788:        if std::mem::take(&mut self.push_now) && self.run_due_syncs().await {
---
847:pub const MAX_STAGED: usize = 256;
906:                if staged.len() >= MAX_STAGED {
59:pub const MAX_STREAM_FRAME: usize = crate::log::sync::MAX_ENTRY_WIRE + 4096;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=4786 && NR<=4830 {printf "%d: %s\n", NR, $0}'
4786:     /// posts go out back to back instead of one per tick.
4787:     async fn push_if_owed(&mut self) {
4788:         if std::mem::take(&mut self.push_now) && self.run_due_syncs().await {
4789:             self.publish().await;
4790:         }
4791:     }
4792: 
4793:     async fn run_due_syncs(&mut self) -> bool {
4794:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
4795:             return false;
4796:         };
4797:         let now = self.now();
4798:         let mut due: Vec<(Digest32, SyncTrigger)> = self
4799:             .schedules
4800:             .iter()
4801:             .filter_map(|(peer, s)| s.due(now).map(|t| (*peer, t)))
4802:             .collect();
4803:         // **Owed peers first.** `schedules` is keyed by fingerprint, so without this every pass
4804:         // visited peers in the same order, and one that sorted first and took the room each time
4805:         // left the rest skipped each time. A stable sort keeps fingerprint order within each group.
4806:         due.sort_by_key(|(peer, _)| !self.owed_first.contains(peer));
4807:         for (peer, _) in &due {
4808:             self.owed_first.remove(peer);
4809:         }
4810:         if due.is_empty() {
4811:             return false;
4812:         }
4813:         let mut ran = false;
4814:         // Which channels a local-append push actually got out. Everything else stays owed.
4815:         let mut pushed: std::collections::BTreeSet<Digest32> = std::collections::BTreeSet::new();
4816:         // Rooms any peer was skipped for because they were mid-session. Added to `pending_push`
4817:         // only **after** the `retain` below — see there.
4818:         let mut owed_rooms: std::collections::BTreeSet<Digest32> =
4819:             std::collections::BTreeSet::new();
4820:         for (peer, trigger) in due {
4821:             if net.manager().existing(&peer).is_none() {
4822:                 continue;
4823:             }
4824:             // Which channels this pass covers: a local-append push touches only the
4825:             // channels that changed; a connect or interval pass covers every channel
4826:             // shared with this peer.
4827:             let mut channels: Vec<Digest32> = Vec::new();
4828:             // Rooms this pass wanted with this peer but found **already mid-session**. See the
4829:             // `owed` handling after the loop: they are retried next tick, not forgotten.
4830:             let mut owed: Vec<Digest32> = Vec::new();
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "incoming_session_wins" | head -5; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | awk 'NR>=70 && NR<=80 {printf "%d: %s\n", NR, $0}'
74:fn incoming_session_wins(me: &Digest32, peer: &Digest32, existing_mine: bool) -> bool {
1793:    /// ends apply one rule and converge: [`incoming_session_wins`].
5384:                if !incoming_session_wins(&me, &peer, existing_mine) {
5517:                Some(me) => incoming_session_wins(&me, &peer, existing_mine),
---
70: ///
71: /// A second session from the same opener replaces the first: a peer only opens a
72: /// session when it holds none, so a new hello from the peer that opened ours means it
73: /// lost its state (a restart — sessions are not persisted), and the old one is dead.
74: fn incoming_session_wins(me: &Digest32, peer: &Digest32, existing_mine: bool) -> bool {
75:     !existing_mine || peer < me
76: }
77: 
78: /// Command queue depth (commands beyond it apply backpressure to the client).
79: const COMMAND_QUEUE: usize = 64;
80: /// Event buffer depth, per subscriber (ADR-020 §7).
[0m
[0m# [0mTodos
[✓] Read ADR-025 revision 3 document
[✓] Read prior reviews (astra round 1+2+3, glm-5.3, kimi-k3)
[✓] Verify code claims against 58fde36 and 8436100 trees
[✓] Verify round-2 findings against rev 3 (RESOLVED/PARTIAL/NOT)
[✓] Attack Option C (full duplex) for corruption/deadlock/starvation
[✓] Check D2/D3/D5/D6/epoch rules and proof table
[•] Write review: BLOCKER/MAJOR/MINOR/NIT + VERDICT
[0m
Review of ADR-025 revision 3 (`141dc11`), against the round-1/2/3 reviews and the trees at `58fde36` (`180:`) and `8436100` (`202:`). Paths are relative to `crates/vox-core/src/`. Read-only; everything below is static analysis I verified by line-reading the cited code.

## Round-2 finding dispositions

**1. Turnover busy refusals — PARTIAL.** The refusal is genuinely removed (D4: admit ≤2, hold past that). But holding is only safe if admission beats the opener's per-frame timeout (20 s, `202:transport/stream_transport.rs:29`), and a running inbound attempt can legitimately occupy the port far longer (SERVE_BUDGET 30 s + DRAIN_BUDGET 30 s, `180:log/sync.rs:73,95`, plus setup RTTs). A held correct-peer stream that waits >20 s ends as a *transport failure* on the peer's side → D5 backoff. So C replaces some busy refusals (today recovered in 20–100 ms) with failure+backoff (recovered in ≤8 s) in exactly the turnover case `INBOUND_PER_PORT=2` exists to cover. Bounded, but "no collision, no random wait" is not established for slow sessions; no held-admission deadline is specified.

**2. Request lifecycle — PARTIAL.** Capture-at-admission / consume-at-completion (D2) is exact and sound; `BackoffExpired` and the manual-sync override answer the wakeup and override cases. Unspecified: the *resource* lifecycle of stale attempts (see BLOCKER 1); what resets `backoff.failures` (the analog today is removal on success, e.g. `202:node/actor.rs:3363`); what purges `held` on epoch/incarnation change; and what wakes the scheduler when a store bumps generation — D3's last row ("any `stored` … makes every other port need a session") fixes round-1's partial-apply gap only if some pass *evaluates* ports at that moment, and no trigger for that pass is named.

**3. Coverage / permanent prefix — PARTIAL.** Position matching + fork-head hash + classes + per-epoch excluded set address both named holes in principle. Three residuals: (a) "a set of requested positions: `(author, seq)` over each range" is not computable as written — `max_seq` is a wire `u64` (`180:log/sync.rs:316–330`), so one HAVE can imply an astronomical range; the serve side already avoids range-proportional work (`180:log/sync.rs:478–539`) and the receive side must too (interval sets, not enumeration). (b) `excluded` = "an author revoked or frozen" has no code referent for "revoked": consent revocation rotates keys and leaves the admitted-author map intact (`202:node/channel.rs:1806–1836`; resolver uses `authors`, 1936–1943); the code has only frozen (`202:log/dag.rs:216–225`) and not-admitted, and both return `Rejected::NotAdmitted` (313–315, 322–324). (c) unfilled positions raise a request "fetched at once" (ADR:221) while D5 backs off only failures and unadmitted-no-progress (ADR:251–255) — a peer whose serves always truncate keeps this end in an immediate, *justified*, unbounded session loop (see finding 5).

**4. Anchors / preparation / commands / capacity — PARTIAL.** C restores outbound preparation on both ends (`180:node/actor.rs:5033–5089` confirmed: `fetch_channel` + `admit_board_records`), keeps adoption before the membership check (5265–5271), keeps `sync_channel` semantics (5202–5223), adds the per-peer cap. Remaining: consent attribution is still by room alone (`180:node/actor.rs:3379`) over a tuple with no token (4356–4357, 4367–4369) — the ADR's "keys on (room, target) and the token" cites that code as if it did it (see Tree accuracy); and the aggregate-stall case (4 stalled peers × 4 slots = 16) is misdescribed by the "seventeenth stalled peer" disclaimer.

**5. Amplification — PARTIAL.** The notify amplifier is gone with notify. But holding's only stated bound is "the peer's own frame timeout" — voluntary for a malicious member; the ADR specifies no receiver-side held count, deadline, or purge-on-connection-death (physical backstops exist but are never invoked: quinn's default 100 bidi streams — Vox sets no `max_concurrent_bidi_streams` — and the 32 MiB `CONNECTION_WINDOW`, `202:transport/quic.rs:195–203`). And the unfilled-positions immediate retry (3c) is an unbounded authenticated work loop that P1's "every session justified" clause does not catch — each session *is* justified by a real request.

**6. Proofs — PARTIAL.** S0b + CANNOT-MEASURE + S0c is the right shape, but several rows cannot work as fielded (see Proof table below): P3's byte-leg precondition is arithmetically unmeetable, P7's and P8's named mutants stay green, and S0b's field list cannot observe P1/P2/P5/P8/P9's preconditions.

**7. Exact atomic D2 — PARTIAL (close).** `gH + nP` at completion in the same epoch is computable (`frontiers` under one lock, `180:node/channel.rs:2679–2683`; `apply_staged` counts `Stored`, `180:log/sync.rs:919–938`); completions serialize on the actor, so atomicity is free. But the fallback `done_gen = gH` is not max-guarded: an older attempt completing after a newer one regresses `done_gen` → one redundant session. Bounded, not a lost update; one-line fix (`max`).

**8. Citations — RESOLVED.** I re-checked every load-bearing citation: `180:log/sync.rs` 501–506, 888–890, 899–914, 880–884 (the session body is 869–917; the ADR's "869–922" over-ranges by 5 lines); `180:node/channel.rs:218–227`; `180:node/actor.rs` 237–239, 4983–4984, 5023–5024, 4933–4934, 5095–5098, 5033–5089, 5148–5197, 5202–5223, 5260–5263, 5265–5313, 3373–3380, 4362–4393; `202:log/dag.rs:317–320`; `202:transport/stream_transport.rs:20–29`; `202:transport/quic.rs:764–781`; `due()` gating at `180:node/syncstream.rs:93–113` and `180:node/actor.rs:4801`. All correct. One prefix omission (NIT).

**Nit ("exactly one")** — RESOLVED in the text; the options table still understates the envelope (ADR:130 "at most two").

## BLOCKER

**B1. The stale rule wedges the port: result-filtering is specified, resource retirement is not.** D1: a `SyncDone` "whose token is not in `out` or `inbound`, or whose `conn` or `epoch` is stale, changes nothing except a `stale` counter." On a reconnect, "attempts on the old one become stale" — but if the old attempt remains in `out`, then "has no `out`" (D4's outbound condition) is false forever, its `SyncDone` is stale and clears nothing, and **the port never opens an outbound again** until epoch change or restart: permanent (room, peer) silence, with requests accumulating. Same leak in `inbound`: two stale inbound completions exhaust `INBOUND_PER_PORT=2` and every later inbound is held forever. If instead incarnation change is meant to *clear* those fields, the old worker then runs beside its replacement — unaddressed. This is not hypothetical: the connection manager deliberately keeps displaced connections served (`202:node/net.rs:839–852`, 874–898), so old-incarnation streams are routine, and room workers fence epoch, not incarnation (`180:node/channel.rs:2662–2675`; `180:node/anchor.rs:411–422`). Specify cancellation/retirement: purge `out`/`inbound`/`held` on epoch/incarnation change, release permits exactly once independent of result disposition, and state the old-worker-vs-replacement concurrency rule.

**B2. Bilateral backlog deadlocks at flow control; the ADR neither lists nor covers it, and its own scope rule now requires one of those.** Both sides serve their whole batch before either drains (`180:log/sync.rs:886–896`); a batch approaches 64 MiB (`180:log/sync.rs:88`, 501–506) against a 16 MiB stream window and 32 MiB connection window (`202:transport/quic.rs:191–203`, 280–282). Two members each holding >16 MiB of new entries (≈16 1-MiB posts each while partitioned — unremarkable at family scale) both block in `write_all` (`202:transport/framing.rs:15–23`), both die at the 20 s frame timeout (`202:transport/stream_transport.rs:88–113`) with **zero applied on either side**, both re-owe, and the loop repeats at ≤8 s D5 backoff with no durable progress, forever. Option C doesn't cause this, but duplex makes simultaneous large serves the common case, P3 is one-directional (the empty side drains while the full side serves — the one shape that works), and the ADR's Scope asserts the v0.2.10 defect list under the every-known-defect rule. Now known; must be claimed or explicitly deferred with its own item.

**B3. Unbounded zero-progress loop on the receive-coverage path.** D3 row 2: unfilled positions → "raises a request: the rest is fetched at once" with the `truncated` counter. A clean-`Ok` truncated serve consumes nothing it didn't cover, raises a fresh request, and D5 never engages (its entry conditions are failures, refusals, open failures, and unadmitted-no-progress — ADR:251–255). A member that advertises a tail it never serves puts the peer in an immediate, infinite, fully "justified" session loop; P1's justification assertion is blind to it. Pace *all* no-progress completions, not only `unadmitted`.

**B4. The proof table still cannot discriminate, and S0b cannot observe what the proofs need.** Verified against the field list (ADR:294–302) and the code:
- **P3:** 70 × 1 MiB vs 64 MiB `MAX_SERVE_BYTES` yields exactly **one** truncated session, then a complete suffix — "at least 2 truncated sessions" is unmeetable on the byte leg; the correct build reports CANNOT MEASURE.
- **P7:** the mutant "tokens ignored at `SyncDone`" survives: the unchanged incarnation check still rejects the old completion, so `stale ≥ 1` still passes and `out` discipline is unaffected. Mutate the whole stale guard, or force a same-incarnation token supersession.
- **P8:** the mutant ("`BackoffExpired` removed") survives: on Bob's return the new incarnation raises a request on *Bob's* port (D2's own connect trigger), Bob opens the outbound, and Bob's pull delivers Alice's post well inside 9 s. With real binaries you cannot stop Bob initiating; assert on the *direction* of the delivering session in Alice's log (Alice outbound within 9 s), or the mutant is green.
- **S0b field gaps:** P1's justification predicate needs `req_gen`/`req_done`/`done_gen`/gen at admission and completion — not listed. P2's base precondition is invisible twice over: no skip event (a slot-cap skip at `180:node/actor.rs:5023–5024` leaves no trace) and no slot-occupancy field ("4 of that peer's slots" is a change-side concept; the base observable would be 16/16 + skip). P5's "did not carry that post" needs entry identity — "received by class" is counts. P8's precondition ("backoff entered") has no backoff field. P9's discrimination needs the per-session outcome/reason and the sender's served-entry identity — neither listed. And the last-64 window cannot support "every session" over 40 duplex rounds on one pair (≈80 endpoint records; overflow undetectable).

## MAJOR

**M1. Held-stream safety is asserted, not specified.** Beyond the >20 s conversion above: `held: VecDeque` has no bound, no deadline, no purge on connection death or incarnation change; the design's own tree argues the opposite for joins — "a queue of half-finished exchanges is exactly the resource a flood wants to fill … cheaper for both sides than a held stream" (`180:node/actor.rs:252–255`). D4 never answers that argument. Add receiver-side count/deadline/purge, or justify against 252–255.

**M2. D3's classes are not computable as named.** Missing resolver key collapses to `AuthenticatorInvalid` (`180:log/sync.rs:609–611`); `NotAdmitted` maps to wire `EpochMismatch` (566); frozen and ordinary non-admission are indistinguishable (`202:log/dag.rs:312–324`); "revoked" doesn't exist (above). And `persist-failed` is not a backoff case: a failed persist poisons the room and later syncs refuse until a person reopens it (`202:node/channel.rs:1351,1396,1494,1514,1620–1622,1665,1867,1886–1888,1915,1975–1977,2051`) — D3 row 4 would retry a poisoned room every ≤8 s forever. Also, classes must be defined at the durable boundary: a partial batch is absorbed and persisted *before* the session returns only the error (`180:node/channel.rs:2702–2729`), so "stored" must mean stored-and-persisted, with the prefix retained across the error.

**M3. The scheduler's evaluation points are unspecified.** Ports replace `push_now` et al., but nothing says when ports are evaluated: on a gen bump (needed for D3's last row to be prompt), on `SyncDone`, on slot release, on request raise. Today's equivalent wake is explicit (`180:node/actor.rs:3450–3453`, 4730–4740, 4788–4801). Without it the claimed partial-apply fix can still wait 30 s, and D7's no-proof-passes-by-the-tick rule is unenforceable for propagation.

## MINOR

- **m1.** `done_gen` fallback not max-guarded (finding 7) — regression on out-of-order completions; bounded redundancy.
- **m2.** D5 never says what resets `failures`; and a permanently-refusing peer (anchor keeping no log → `EpochMismatch`) is retried every ≤8 s forever — chattier than today's 3 quick retries then 30 s pacing (`180:node/actor.rs:175–178`, 3433–3449), an unmentioned regression in exactly the case the rewritten #202 proof exercises.
- **m3.** ADR:130 "at most two when both need one" understates the envelope: 2 inbound + 1 outbound admitted, plus held (and double-reconnect legitimately produces a third concurrent inbound via still-served retired connections, `202:node/net.rs:839–852`).
- **m4.** The #202-replacement proof omits the authorization precondition: `EpochMismatch` is disclosed only when `owed_a_reason` holds (`202:node/actor.rs:5265–5275`, 5306–5312); "an anchor that keeps no log" alone does not produce the named reason.
- **m5.** P2's "both fingerprint orientations" is a leftover from designated-opener thinking; orientation is meaningless under C.
- **m6.** S0b needs loss-detectable collection (sequence numbers / overflow flag), not just a bound.

## NIT

- ADR:67 cites `node/syncstream.rs 93–113` without the `180:` prefix the document's own convention requires.
- "869–922" over-ranges; the session body is `180:log/sync.rs:869–917`.
- The revision table's "3 (this) — not yet reviewed" is stale: `review3-astra.md` (reviewing `141dc11`) sits untracked in the worktree.
- "C needs no new state beyond tokens" (ADR:141) — plus the inbound set, held queue, generations, excluded set.

**Trees / planned-as-done:** every code citation I re-checked is accurate to the named tree. One wording violation of the planned-vs-done rule: "A consent's retry keys on (room, target) and the token, not on the room alone (`180:node/actor.rs` 3373–3380, 4362–4393)" cites the code that does the room-only keying it claims to replace — it must read as replacing that behavior. The same diligence applies to D5's "wakes itself" and the epoch rules, which are correctly framed as proposal.

## VERDICT

**BLOCK.**

The three changes I would most insist on:

1. **Specify the port's full resource lifecycle, not just result-filtering:** purge/retire rules for `out`/`inbound`/`held` on epoch and incarnation change with exactly-once permit release; old-worker-vs-replacement concurrency; receiver-side held bounds and deadlines; monotonic (max-guarded) `done_gen`; `failures` reset; terminal handling for a poisoned room; named scheduler evaluation points on generation bumps.
2. **Bound the retry and receive machinery, and own the inherited stall:** pace *every* no-progress completion (unfilled positions included), specify coverage as interval sets with classes defined against the actual predicates (frozen vs not-admitted; drop or define "revoked"), and either pull the bilateral serve-before-drain flow-control deadlock into v0.2.10 scope with a fix direction and a bilateral proof, or explicitly defer it as a known defect — silence is not available under the ADR's own every-known-defect rule.
3. **Rebuild S0b and the proof table as one artifact:** add the missing fields (request/generation state at admission and completion, per-session outcome and reason, skip/queue/slot-occupancy events, backoff enter/expire, served-entry identity, loss-detectable collection), then fix the rows those fields expose: P3's byte-leg precondition (one truncation, not two), P7's mutant (whole stale guard or same-incarnation supersession), and P8's assertion (the direction of the delivering session, since Bob's own reconnect request will otherwise keep the mutant green).
