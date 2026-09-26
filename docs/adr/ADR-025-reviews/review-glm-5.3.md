[0m
> build · glm-5.3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline -5 && git -C /opt/vox/.claude/worktrees/ac-adr025 log --oneline -5
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
885d2f5 ci(ui): the TUI names proof runs in CI, as a cargo test, with a pinned pyte (#198)
d9f4b48 test(relay): the direct control's bound is RETIRE_GRACE_SECS + 15 s, and it says which way the pair was direct
8c4e347 docs(adr): ADR-025 draft — sync is scheduled like a switch, not a hub (for review)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
885d2f5 ci(ui): the TUI names proof runs in CI, as a cargo test, with a pinned pyte (#198)
d9f4b48 test(relay): the direct control's bound is RETIRE_GRACE_SECS + 15 s, and it says which way the pair was direct
[0m
[0m$ [0mwc -l /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs
6838 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs
    1138 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs
    2723 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs
     167 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs
   10866 total
[0m
[0m✱ [0mGrep "fn (run_due_syncs|sync_one|start_session|run_sync_session|owed_a_reason|incoming_session_wins|note_local_append|note_new_members)"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs · 8 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=700, offset=4700][0m
[0m✱ [0mGrep "NetEvent::(SyncDone|PushRetry)|QUICK_PUSH_RETRIES|MAX_PUSH_RETRY_WAIT|push_failures"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs · 23 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=180, offset=3340][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=130, offset=160][0m
[0m✱ [0mGrep "SERVE_BUDGET|MAX_SERVE|fn frontier_session_room_inner|struct SessionRoom|impl SessionRoom|fn (take|room|enter|leave)"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs · 15 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs[90m [limit=130, offset=30][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs[90m [limit=240, offset=460][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs[90m [limit=440, offset=700][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 33da864 --stat && git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36 --stat
commit 33da864e66e916912fdefc76ed359f987c9be885
Author: Robert E. Lee <robert@loveathome.us>
Date:   Fri Sep 25 23:05:41 2026 +0200

    fix(sync): one dead member no longer stalls a room for everyone — sync sessions are guarded per room and peer
    
    What was seen (log-scale, with shipped daemons): with one member's process dead, the room
    converged 29.5 s and 21.9 s late for the members still alive.
    
    Cause: a push reconciles the room with a member and waits for its answer. A member that died
    without closing its connections answered nothing until the connection was declared dead
    (SILENCE_IS_DEATH, 30 s). The session guard `syncing` was keyed by room, so for that whole wait
    every other member's session for the room was refused and every push to them was owed. The whole
    room waited behind one member who was gone.
    
    Fix: the guard is keyed by (room, peer). What it prevents is a pair colliding, both ends
    reconciling the same room with each other at once. Sessions with different peers run side by
    side; each takes the room's lock inside one protocol step at a time, never across the network
    (ChannelState::sync_over_room). in_session_with guards a new session with a given peer.
    room_in_session is for the work that must not wait on a room any session holds: the anchor
    publish, note_new_members, and a consent's retry.
    
    Proof: crates/vox-tui/tests/a_dead_member_does_not_stall_the_room_proof.rs, a real `vox node` and
    three real `vox daemon`s. Once all three read each other, Carol's daemon is killed by PID. Alice
    posts five messages, each timed from `vox room post` returning to Bob's `vox room read` showing it,
    bound 1 s (PRD-001 R40): 56–65 ms each, 3 runs.
    - Mutation, guard keyed by room again: 30.0 s and 29.3 s, red.
    Not covered: a member that restarts under the same identity while the old session still waits
    is the same pair and is refused until that session ends. restart-probe's held-connection probe
    (582f18a) closes the dead connection when the newcomer is filed.
    
    R40 on this commit: relayed p95 38.8 ms; direct network p95 19.2 ms and end to end p95 31.9 ms.

 crates/vox-core/src/node/actor.rs                  |  48 ++-
 .../a_dead_member_does_not_stall_the_room_proof.rs | 325 +++++++++++++++++++++
 docs/adr/ADR-016-node-runtime.md                   |  20 ++
 3 files changed, 381 insertions(+), 12 deletions(-)
commit 58fde3650bf17cef8ad212b175116a0dcdc2cce8
Author: Robert E. Lee <robert@loveathome.us>
Date:   Sat Sep 26 09:35:43 2026 +0200

    fix(sync): owed publish and new-member pushes no longer wait for a session-free room (#180)
    
    agent_comms's review of 33da864: publish_channel_to_anchors and note_new_members were owed
    while ANY session ran on the room, and drained only when none did. Once sessions are guarded per
    (room, peer) and overlap, a busy room need never be session-free, so the anchor publish could
    wait indefinitely while joiners read a stale board. The deferral existed because a session held
    the room's lock for its whole run; since 3f95b57 a session locks per step, never across I/O, so
    the actor now waits at most one step and publishes at once. publish_owed, growth_owed and
    room_in_session are removed. An explicit consent's retry rides a SyncDone of a session with its
    TARGET (in_session_with), not of any session on the room.
    
    Not gated red-first: on today's tree the anchor learns a joiner from its own log, so no
    anchor-visible change depends on a busy member's publish (a busy-room gate was green 5/5 on
    33da864 and 69aaff5; it can bite after ADR-023 M23.5). Regression checks, release, shipped
    binaries, one at a time under the timing lock (load 20-64): a_dead_member_does_not_stall_the_room
    1/1, a_new_member_is_seen_promptly 1/1, node_m15_anchor_gate 3/3, room_of_three_keys 2/2,
    a_room_admits_the_passphrase_and_authors_decide_readers 1/1, trust_before_join 1/1,
    node_m19_trust_gate 4/4, sec_no_consent_without_a_ring_entry 1/1. fmt, clippy -D warnings clean;
    debug workspace 84 suites, 48 passed, 0 failed. ADR-016 updated.

 crates/vox-core/src/node/actor.rs | 57 +++++++++------------------------------
 docs/adr/ADR-016-node-runtime.md  | 13 +++++++--
 2 files changed, 24 insertions(+), 46 deletions(-)
[0m
Now the #180 commits and the channel/syncstream code.
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 33da864 -- crates/vox-core/src/node/actor.rs | head -160
(no output)
[0m
[0m✱ [0mGrep "fn sync_over_room|impl SessionRoom for|struct ChannelSessionRoom|fn frontiers|fn wants|fn entries|fn apply|room_in_session|in_session_with"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs · 14 matches[0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 33da864 -- 'crates/vox-core/src/node/actor.rs' | wc -l; git -C /opt/vox/.claude/worktrees/ac-fix202 show 33da864 | grep -n 'syncing\|in_session\|room_in_session' | head -60
166
12:    (SILENCE_IS_DEATH, 30 s). The session guard `syncing` was keyed by room, so for that whole wait
19:    (ChannelState::sync_over_room). in_session_with guards a new session with a given peer.
20:    room_in_session is for the work that must not wait on a room any session holds: the anchor
42:-    syncing: std::collections::BTreeSet<Digest32>,
53:+    syncing: std::collections::BTreeSet<(Digest32, Digest32)>,
61:-        if self.syncing.contains(channel_id) {
62:+        if self.room_in_session(channel_id) {
70:-                self.syncing.remove(&channel_id);
71:+                self.syncing.remove(&(channel_id, peer));
79:-            if !self.syncing.contains(&channel_id) {
80:+            if !self.room_in_session(&channel_id) {
88:-        if self.syncing.contains(channel_id) {
89:+        if self.room_in_session(channel_id) {
98:+    /// session with that peer for that room must not start into (see `syncing`).
99:+    fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
100:+        self.syncing.contains(&(*channel_id, *peer))
103:+    /// Whether any sync session, with any peer, is running on `channel_id` (see `syncing`).
104:+    fn room_in_session(&self, channel_id: &Digest32) -> bool {
105:+        self.syncing
118:-                if self.syncing.contains(cid) || self.publishing.contains(&(*cid, peer)) {
119:+                if self.in_session_with(cid, &peer) || self.publishing.contains(&(*cid, peer)) {
127:-                if self.syncing.contains(cid) {
128:+                if self.in_session_with(cid, &peer) {
136:-        if self.syncing.contains(channel_id) {
138:+        if self.in_session_with(channel_id, &peer) {
144:-        self.syncing.insert(*channel_id);
145:+        self.syncing.insert((*channel_id, peer));
153:-        self.syncing.insert(channel_id);
154:+        self.syncing.insert((channel_id, peer));
162:-        if self.syncing.contains(&channel_id) {
163:+        if self.in_session_with(&channel_id, &peer) {
509:+  30 s). The session guard (`syncing`) was keyed by room, so for the whole wait every other member's
517:+    asks `room_in_session`.
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [limit=120, offset=2085][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [limit=90, offset=2635][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36 | grep -n '^[+-].*\(in_session_with\|room_in_session\|publish_owed\|syncing\)' | head -40
35:-    publish_owed: std::collections::BTreeSet<Digest32>,
41:-    /// session's `SyncDone` lands, like `publish_owed`.
50:-            publish_owed: std::collections::BTreeSet::new(),
70:-        if self.room_in_session(channel_id) {
71:-            self.publish_owed.insert(*channel_id);
88:-                if self.publish_owed.remove(&channel_id) {
108:-            if !self.room_in_session(&channel_id) {
109:+            if !self.in_session_with(&channel_id, &target) {
118:-        if self.room_in_session(channel_id) {
130:-    /// Whether any sync session, with any peer, is running on `channel_id` (see `syncing`).
131:-    fn room_in_session(&self, channel_id: &Digest32) -> bool {
132:-        self.syncing
150:-    asks `room_in_session`.
157:+    (`in_session_with`), not of any session on the room.
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=45, offset=60][0m
[0m✱ [0mGrep "SYNC_FRAME_TIMEOUT\s*[:=]|const SYNC_FRAME_TIMEOUT"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src · 1 match[0m
[0m
[0m$ [0mls /opt/vox/.claude/worktrees/ac-fix202/crates/vox-tui/tests/ 2>/dev/null | head -40; git -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline --all | grep -i '202\|41' | head
a_circuit_carries_an_ipv6_daemon_proof.rs
a_daemon_follows_its_anchor.rs
a_large_room_reads_whole_proof.rs
a_long_room_reopens_proof.rs
a_member_of_one_room_is_not_served_another_proof.rs
a_relayed_host_restart_is_reached_again_proof.rs
a_room_admits_the_passphrase_and_authors_decide_readers.rs
a_room_not_on_the_board_is_named_proof.rs
a_second_joiner_is_not_locked_out.rs
a_sync_failure_names_its_reason_proof.rs
a_watchdog_abort_leaves_nothing_running_proof.rs
adapter_stream_proof.rs
agent_hook_proof.rs
agent_rehearsal_proof.rs
anchors_config_proof.rs
attach_names_its_error_proof.rs
claim_lost_proof.rs
codex_trust_proof.rs
cross_process_join_proof.rs
daemon_proof.rs
daemon_shutdown_proof.rs
drain_self_filter_proof.rs
file_exchange_proof.rs
install_sh_proof.rs
interrupt_proof.rs
it_just_works_with_a_daemon_running.rs
opencode_plugin_proof.rs
perf_r40_chat_latency_proof.rs
perf_r40_relayed_chat_proof.rs
perf_r41_tunnel_throughput_proof.rs
pty
read_render_proof.rs
remote_interrupt_proof.rs
result_unread_proof.rs
room_of_three_keys_proof.rs
room_verbs_proof.rs
service_rehearsal_proof.rs
shell_setup_proof.rs
shutdown_releases_the_profile_proof.rs
skill_cli_proof.rs
86949be test: only real use of the product is a test — the 36 in-process test files are deleted (decider, 2026-09-26)
8290560 merge: #202 — a sync failure names its real reason, not 'malformed governance'
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
03afbc7 Merge remote-tracking branch 'origin/fix/push-retry-v0210' into dbg/180-with-41
dbbafd9 docs(release): v0.2.10 — V210-29, a sync failure names its real reason (#202)
25c94fd diag: QUIC path stats in R41 on macOS vs ubuntu runners (throwaway, never merged)
265c41c ci: macOS runners stop Spotlight indexing before the tests
91a4fe0 fix(r41): calibration paces its sender by sleeping, never forgiving a backlog, and a refusal names each window and what competed for the CPU
946a62a merge: #41 — a colliding push backs off desynchronised and is never left to the 30 s interval
6710766 diag: R41 with and without Spotlight on macOS runners (throwaway)
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/anchor.rs[90m [limit=140, offset=320][0m
[0m✱ [0mGrep "struct SyncOutcome|pub applied|pub rendered|pub governance"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs · 4 matches[0m
[0m
[0m$ [0mgrep -n '40\|rounds\|barrier\|SessionBusy\|did not complete\|assert' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-tui/tests/a_sync_failure_names_its_reason_proof.rs | head -40
1://! V210-29 (#202) — **a sync that did not complete says why**, through the shipped binary.
13://! What this asserts, on both daemons' stderr:
19://! If no collision happened in all the rounds, the run proves nothing, and it fails as CANNOT
42:const ROUNDS: usize = 40;
44:/// What a collision reads as, from the coded reason `SessionBusy`.
97:/// The daemon's reports of syncs that did not complete.
101:        .filter(|l| l.contains("did not complete"))
134:        assert!(ok, "vox id: {err}");
140:        assert!(ok, "vox trust add {name}: {out}{err}");
151:    assert!(ok, "vox room create: {out}{err}");
153:    assert!(ok, "vox room list: {err}");
161:    assert!(ok, "vox room invite: {err}");
167:    assert!(ok, "bob joins: {out}{err}");
169:    // Both members read each other before the rounds, so every failure below is between two
176:    assert!(ok, "alice posts: {err}");
182:        assert!(
184:            "CANNOT MEASURE: bob never read alice before the rounds"
188:    // What was reported before the rounds is not what this measures.
193:    let barrier = Arc::new(Barrier::new(2));
195:        let (barrier, room) = (Arc::clone(&barrier), room.clone());
198:                barrier.wait();
230:        "[proof] {} failed-sync report(s) over {ROUNDS} simultaneous rounds: {collisions} named as a \
238:    assert!(
243:    assert!(
245:        "no failed sync was reported as a collision over {ROUNDS} simultaneous rounds (reports: \
[0m
[0m$ [0mgrep -rn 'refuse_stream_because' /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs | head -5; grep -n 'fn refuse_stream_because' -A 20 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs | head -30
/opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs:1004:pub fn refuse_stream_because(send: &mut SendStream, recv: &mut RecvStream, why: WireError) {
1004:pub fn refuse_stream_because(send: &mut SendStream, recv: &mut RecvStream, why: WireError) {
1005-    let code = close_code(why);
1006-    let _ = send.reset(code);
1007-    let _ = recv.stop(code);
1008-}
[0m
I read the ADR, `actor.rs`, `log/sync.rs`, `channel.rs`, `syncstream.rs`, `anchor.rs`, the `net.rs` refusal path, the #202 proof, and both #180 commits (33da864, 58fde36). Measurements attributed to vox-0e/V29-06/#202 runs are taken on trust (read-only; not re-runnable here); every mechanism claim below was checked against the tree at 8436100.

## BLOCKER

**B1. The proof plan fails its own mutation standard — 4 of 6 proofs cannot go red on their named mutants, and P6 is red on the design itself.**
- **P6** asserts "zero refusals between the pair in steady state", but D4's own glare row produces **exactly one** `SessionBusy` refusal per simultaneous round (the lower refuses the higher's inbound; ADR lines 222–223, 241). The gate is "both posting at once, 60 rounds" — every round glares. P6 is unpassable on D4, not on the mutant. It must assert ≤1 refusal/round and zero retries (or zero `SyncFailed` reports, per D4 line 252–253).
- **P1's second mutant ("D4 with both ends accepting") is green by construction.** Accept-both has zero refusals, zero retries, zero `did not complete`, and delivers within bound — nothing in P1's assertion list distinguishes it from D4. S0b gives session counts; P1 must assert them (e.g., sessions started ≤ rounds + ε) or the mutant check is void.
- **P4 asserts a property its mutant cannot affect.** The higher end's post reaching a *third* member rides that pair's port, which is independent of the stuck `Awaiting` port for the SIGSTOPped lower end. And SIGSTOP is the wrong tool: a frozen process keeps its sockets open, so the keeper's in-flight session doesn't die — it stalls up to `SYNC_FRAME_TIMEOUT` = 20 s (stream_transport.rs:29) and, on SIGCONT, *completes*, clearing `Awaiting` even in the no-deadline mutant. P4 needs: kill the keeper before its stream arrives (real death, sockets close), then assert the *pair* converges within `AWAIT_KEEPER` + bound — red at ~30 s on the no-deadline mutant (tick-only recovery).
- **P3's 2 s bound is likely green on base and mutant.** The skipped rooms are re-armed within one session duration: `pending_push` retains them (actor.rs:4962, 4972) and every `SyncDone` sets `push_now` while anything is owed (actor.rs:3459–3466). 24 quick sessions all land well under 2 s with `try_acquire`-or-skip. The ADR's own claim 2 (line 61–64) says this bookkeeping "decides" the recovery — the proof must then bound it tightly enough to discriminate, or count tick-armed deliveries.
- **P2's mutant is ambiguous and likely green.** "done_gen set at session start" (charitably: still cleared on failure) makes ports strictly *dirtier* than `gen_at_have` (start ≤ HAVE), producing redundant sessions, not lost posts. It only goes red if the mutant also keeps `done_gen` on failure — a different mutant. Name it precisely and inject a failure, or drop it.
- **P5** is the one sound new proof (mutant: `done_gen` = gen at `SyncDone` → the post waits for the tick → red), but "within 250 ms of the keeper's `SyncDone`" needs a `SyncDone` timestamp in the shipped binary; S0b specifies counts only. Bound it end-to-end instead.

## MAJOR

**M1. D3's "completed (serve not cut short)" is not observable — the design's core invariant has no mechanism.** A budget-cut serve still returns `Ok`: the break at log/sync.rs:888–890 falls through to `t.finish()` (893) and the drain (896–916), so `frontier_session_room` returns `Ok(applied)` (860–866) and `SyncOutcome` is only `{applied, governance, rendered}` (channel.rs:212–218) — nothing reports whether the serve was cut by `SERVE_BUDGET` (30 s, log/sync.rs:95) or `MAX_SERVE_ENTRIES`/`MAX_SERVE_BYTES` (1024/64 MB, log/sync.rs:82, 88 — applied inside `entries_for_wants`, log/sync.rs:501–509, invisible on the wire). S1 (ADR line 327) adds only `gen_at_have` to `SyncOutcome`. As written, `done_gen = gen_at_have` **will** be recorded on cut-short serves. What actually saves you is D2's `o.applied > 0` → mark dirty (mirroring actor.rs:3492–3493), which recovers the cut-short case whenever ≥1 entry arrived — and `entries_for_wants` always serves ≥1 if any matched (log/sync.rs:501–509). The residual hole: a serve that sends **zero** entries (deadline hit before the first send) plus a peer that applied nothing → both ports clean, nobody re-owes, tick-only. Also: one side can record `Ok` while the peer's session fails — the peer FINs its send side *before* its drain (log/sync.rs:793–804), so our drain can complete cleanly before the peer's apply refusal kills its end. Our port goes clean; the peer's stays dirty and retries — liveness holds, but D3's "both directions drained" is per-side knowledge, not joint. Fix: add a served-complete/cut-short flag to `SyncOutcome` in S1, or restate D3's guarantee honestly (delivered up to gen *modulo serve bounds*, recovered by the applied>0 rule and the tick) and prove the >1024-entry catch-up (see M7).

**M2. D4's state machine is unspecified for the common event ordering — the literal text breaks the one-session-per-port invariant.** The refusal of the higher end's outbound exists only *after* the lower processes the higher's stream; the lower's keeper stream is crossing the wire at the same time. So the higher's port is typically already `Running{In}` when the outbound's `SyncDone(Err, SessionBusy)` arrives. D4's literal instruction — "the port moves to `Awaiting`" (ADR line 226–228) — would drop `Running{In}`, and since ordinary sessions run 5–30 s (`SERVE_BUDGET` = 30 s), a 2 s `AWAIT_KEEPER` **will** fire during legitimate keepers, queueing a redundant outbound while the inbound still runs: two live streams for one pair initiated by the higher end — exactly what the port model exists to prevent, and exactly the go-libp2p #79 class the ADR cites (line 117–121). The transition must be written: an outbound `SyncDone(SessionBusy)` while `Running{In}` is a **no-op**; `Awaiting` is entered only from `Running{Out}`. Related, in the current code this ordering is concretely hazardous: the outbound's `SyncDone` removes the guard (actor.rs:3382–3383) while the inbound session from `start_session` still holds the room (actor.rs:5132–5133 inserts; nothing re-inserts), and `syncing_with` (used by `owed_a_reason`, actor.rs:5306–5313) points at whichever session inserted last. The ADR's open question 3 asks "does anything assume one?" — yes: the guard, `owed_a_reason`, and (post-58fde36) the consent retry that rides `in_session_with`. Answer it in the Decision, not the questions.

**M3. Factual error about the tree it builds on: `room_in_session` does not exist in #180's final state.** ADR line 274: "The anchor publish, `note_new_members` and a consent's retry keep `room_in_session` from #180 unchanged." 58fde36 **removed** `room_in_session` and `publish_owed` (commit message: "publish_owed, growth_owed and room_in_session are removed"; diff removes the function and the `publish_owed` set). Post-#180, the anchor publish and `note_new_members` wait on no session at all, and a consent's retry rides `in_session_with` (its target's session). The ADR cites 33da864's intermediate state as #180's final state. Under the standing rule about describing the tree accurately, this must be corrected before the decider reads it.

**M4. D6's defect framing is a selective quote, and the argument that answers the code is missing.** The code's full position is that skipping is *better*: "a queue of sessions for rooms whose state has since moved on is worse than none" (actor.rs:238–239). The ADR quotes "skipped, not queued. The schedule comes round again." (~5010, actor.rs:5010–5011) and, in Scope (line 295–297), cites it as the code's "own account" of a defect. The design actually answers the staleness argument — a queued *port* that became clean never opens, so a queue of stale sessions cannot happen under D1 — but the ADR never makes that argument. Without it, D6 is a fairness improvement, not a defect fix: the skipped pass is recovered within ~one session duration (actor.rs:4962, 4972, 3459–3466), and the real residual (16 slots hogged by slow peers, `SYNC_FRAME_TIMEOUT` 20 s each) is *not* fixed by a queue — a queued port waits for a slot either way.

**M5. Accept-both is rejected on an unmeasured claim, and the strongest argument against it is unused; designated-initiator is not discussed at all.** The stated reason — "it keeps the redundant session as the normal case" (ADR line 288–290) — is wrong: with accept-both, a redundant session occurs only on glare, which is the rare case (the ADR's own numbers: ~1 glare per simultaneous round; normal traffic is one session per post). The argument that actually holds is in-tree: #180's `in_session_with` consumers (a consent's retry rides a `SyncDone` of a session with its *target*, 58fde36) and D3's own `done_gen` bookkeeping assume one session per pair — accept-both would run two live sessions per pair on glare and the port model cannot represent it. Make that argument. The designated-initiator design (one end initiates; the other sends a tiny notify) is silently absent; it is genuinely ruled out by the ADR's own "no wire change" constraint (line 173–174) — a notify needs a frame — and by R40 (without a notify, the non-initiator's posts wait for the initiator's next session). Say so. The persistent-stream deferral, by contrast, is well argued (line 142–153, 284–287).

## MINOR

**m1. Claim 3's implication is overstated (item 3).** The quote is real (actor.rs:4970–4971), but "nothing re-owes an entry stored after the session's `HAVE`" misstates the recovery: every append re-owes the room to every peer (actor.rs:4717–4728), a mid-session append is caught by the `syncing` check (actor.rs:4850–4852) and re-armed on every `SyncDone` (actor.rs:3459–3466). The residual defect is the start→failure accounting window and the six-maps complexity (claim 4), not a lost entry. Weakens the D3-as-defect case for v0.2.10; the generation machinery is a precision/simplification win, not a loss fix.

**m2. D4's "The same side wins here as there" (ADR line 219–220) is self-contradictory as sequenced.** BGP keeps the *higher* identifier's connection (quoted correctly at line 105–106); D4 and `incoming_session_wins` (actor.rs:74–76, `peer < me`) keep the *lower* fingerprint's (confirmed). "There" can only mean the Vox pairwise rule, but as written it reads as BGP. Given FRR#1219 is cited as the wiring-bug caution, state the difference cleanly.

**m3. `AWAIT_KEEPER` (open question 1): measure from the refusal's `SyncDone`.** The actor never sees frames (the session runs on a slot task; the actor sees only `SyncDone`, actor.rs:5100–5106, 5156–5162), so "from the last frame" requires new plumbing and is a timing heuristic — the #79 lesson. 2 s is tolerable because a premature expiry costs one cheaply-refused outbound (the lower is still `Running{Out}`); no proof covers the relayed glare where the keeper's first frame legitimately exceeds 2 s (P4 is SIGSTOP, not relay; R40 is not a glare test). Add one or justify 2 s against 33da864's relayed p95 of 38.8 ms.

**m4. Missing proofs (item 5):** (a) no proof exercises the serve bounds at all — a >1024-entry catch-up must converge, and its mutant must disable *both* the `done_gen` rule and the `applied>0` re-owing, or it will stay green via the safety net (this is the proof that exposes M1); (b) restart-under-same-identity during glare (flagged as not covered in 33da864's own message); (c) D6 fairness across passes (P3 covers the cap only).

**m5. D4 interleavings I could not break (item 2):** no both-refuse (the higher never refuses on glare); no both-`Awaiting` for one pair (only the higher enters it); no lost post (post-after-`HAVE` is caught by the re-queue on both ends); a lost keeper costs one bounded wait; a clean restart closes sockets so the zombie inbound dies promptly — the frozen-peer case is bounded by `SYNC_FRAME_TIMEOUT` (20 s) + budgets, same as today; anchors run the identical session (anchor.rs:349 uses `frontier_session_room`), and a log-less anchor's `EpochMismatch` refusal (actor.rs:5265–5277) lands in D5 backoff, correctly. The one gap is M2's ordering, and the table's row 4 "impossible" needs a footnote: it is possible after a restart (port state is in-memory), with recovery bounded by the frame timeouts, not `AWAIT_KEEPER`.

**m6. Scope (item 6):** D1–D3 + D5-deletion + D7 are defensible as one v0.2.10 item (D3's "known and not fixed" comment is a real confession; the jitter becomes dead code inside the new structure). D6 is the creep-iest, defensible only as nearly-free-once-ports-exist — not as a standalone defect fix (M4). S0b is new product surface justified by the "a proof counts only what the shipped binary shows" rule; keep it to counts. `Port.dirty_gen` is redundant as specified (dirty is defined as `room.gen > done_gen`, ADR line 186–191) — two sources of truth for one bit; drop one.

## NIT

- Claim 1's "finds its own session with that peer running (~5226)" — in the cited tree the check is room-keyed (`self.syncing.contains(&channel_id)`, actor.rs:5226); pair-keying arrives with #180. The ADR assumes #180 (line 7–8) but the citation as phrased doesn't match the cited tree. Claims 1 (mechanism: actor.rs:4717–4728, 4774–4778, 5226–5241, 3430–3455, 174, 178), 2 (5010–5011, 240), 4 (4785–4793, 4722, 4914, 3431, 5007/5013, 3382; the three defect comments at 4922–4935, 4963–4968, 3406–3413) and 5 (33da864 diff) are otherwise CONFIRMED at the cited lines; the measured numbers (35–47, 1,397, 703/702, 0 late) are not verifiable here.
- Context line 26–27 ("the only thing a session cannot carry…") is stated unconditionally but is false in the serve-cut-short case that D3 itself excludes; reconcile with one sentence.
- Open question 2 has a simple answer: on `SyncDone`-Ok with `applied > 0`, mark every port for the room dirty *except* the session's own peer — entries applied from P were sent by P, so P holds them; third-member propagation is unchanged.

## VERDICT

**REVISE**

1. **Rewrite the proof table so every proof discriminates its mutant** (B1): P6 → ≤1 refusal per glare round and zero retries; P4 → kill (not SIGSTOP) the keeper before arrival and assert pair convergence, red at ~30 s on no-deadline; P1 → assert session counts (S0b) so accept-both goes red; P3 → a bound that actually excludes the `pending_push` re-arm path, or count tick-armed deliveries; P2 → name the mutant precisely (done_gen set at start *and* kept on failure) with a failure injector; add the >1024-entry catch-up proof with a mutant that disables the `applied>0` safety net.
2. **Specify D4's full transition table for out-of-order events** (M2): inbound accepted before the outbound's refusal lands is the *common* ordering; an outbound `SyncDone(SessionBusy)` while `Running{In}` is a no-op; `Awaiting` entered only from `Running{Out}`; two `SyncDone`s for one pair defined. Answer open question 1 (from the refusal's `SyncDone`) and open question 3 in the Decision.
3. **Make D3's "completed" observable or restate it honestly** (M1): a served-complete flag in `SyncOutcome` alongside `gen_at_have`, or an explicit "modulo serve bounds, recovered by `applied>0` and the tick" with the catch-up proof. In the same pass, fix the `room_in_session` factual error (M3) and re-argue D6 and accept-both without the selective quote (M4, M5).
