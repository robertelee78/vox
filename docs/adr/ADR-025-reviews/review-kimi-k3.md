[0m
> build · kimi-k3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline -5 2>&1 | head -20; echo ---; git -C /opt/vox/.claude/worktrees/ac-adr025 log --oneline -3 2>&1
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
885d2f5 ci(ui): the TUI names proof runs in CI, as a cargo test, with a pinned pyte (#198)
d9f4b48 test(relay): the direct control's bound is RETIRE_GRACE_SECS + 15 s, and it says which way the pair was direct
---
8c4e347 docs(adr): ADR-025 draft — sync is scheduled like a switch, not a hub (for review)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
[0m
[0m$ [0mwc -l /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs 2>&1
6838 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs
    1138 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs
    2723 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs
     167 /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs
   10866 total
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline -3; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show --stat 33da864 | head -30; echo ---; git -C /opt/vox/.claude/worktrees/ac-fix202 show --stat 58fde36 | head -30
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
---
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
---
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
[0m✱ [0mGrep "fn (run_due_syncs|sync_one|start_session|run_sync_session|owed_a_reason|incoming_session_wins|note_local_append|in_session_with|room_in_session)"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs · 8 matches[0m
[0m✱ [0mGrep "SyncDone|PushRetry|QUICK_PUSH_RETRIES|MAX_PUSH_RETRY_WAIT|SYNCS_IN_FLIGHT|try_acquire|skipped, not queued|pushed means"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs · 45 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=60, limit=60][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=160, limit=140][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=560, limit=110][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=4700, limit=300][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=5000, limit=340][0m
[0m✱ [0mGrep "syncing|syncing_with|in_session_with|pending_push|pushed_to|owed_first|push_failures"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs · 55 matches[0m
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git merge-base --is-ancestor 33da864 8436100 && echo "33da864 IS ancestor" || echo "33da864 NOT ancestor"; git merge-base --is-ancestor 58fde36 8436100 && echo "58fde36 IS ancestor" || echo "58fde36 NOT ancestor"; echo ---; git log --oneline --all --graph | head -40
33da864 NOT ancestor
58fde36 NOT ancestor
---
* 86949be test: only real use of the product is a test — the 36 in-process test files are deleted (decider, 2026-09-26)
*   8290560 merge: #202 — a sync failure names its real reason, not 'malformed governance'
|\  
| * 8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
* | 9b7d05e fix(integration): the merges of #196/#189 with #181/#42 compile
* |   d92a130 merge: #180 — a new member reaches the room when it joins; one dead member no longer stalls a room
|\ \  
* \ \   2a663f3 merge: #189 — the room list and the trust keyring are paged; no count can outgrow a frame
|\ \ \  
| * | | 44efad8 test(ipc): the V210-16 gate crosses a frame with rooms and goes red on main; pagers refuse a page that does not advance
| * | | 362f55f fix(ipc): the room list and the trust keyring are paged — no count of rooms or trusted identities can outgrow a frame (V210-16)
* | | |   c4e8a2f merge: #197 — an IPv6-only member reaches its board at once, not after 20 s
|\ \ \ \  
| * | | | 48aaa3c fix(join): an IPv6-only member reaches its board at once, not after 20s (#197)
| |/ / /  
* | | |   7a8d759 merge: #196 and #199 — failures say what went wrong and what to do; passphrase checks run off the actor, at most two at once
|\ \ \ \  
| |_|_|/  
|/| | |   
| * | |   396889e Merge remote-tracking branch 'origin/fix/v210-26-verify-off-actor' into port/error-messages-keyring
| |\ \ \  
| | * | | 5627103 fix(node): at most two passphrase checks run at once — a flood of wrong ones cannot exhaust memory (V210-26)
| * | | | d89432a test(errors): failure_reasons_proof case (9) fills the keyring eight at a time (#196)
| * | | | 9b75d1c Merge remote-tracking branch 'origin/fix/v210-26-verify-off-actor' into port/error-messages-keyring
| |\| | | 
| | * | | 8fcb28c fix(node): checking the identity passphrase no longer stalls the node (V210-26)
| * | | | a648ace fix(errors): a full trust keyring says so, not "longer than this field allows" (#196)
| * | | | a096735 fix(errors): the common failures say what went wrong and what to do, not an enum token
| | |/ /  
| |/| |   
| | | | * 8c4e347 docs(adr): ADR-025 draft — sync is scheduled like a switch, not a hub (for review)
| |_|_|/  
|/| | |   
* | | |   1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
|\ \ \ \  
| * | | | 3a6ac6d test(watchdog): an aborted gate leaves nothing running — the watchdog kills the test's descendants first (V210-28)
| | |/ /  
| |/| |   
* | | |   2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
|\ \ \ \
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git log --oneline 8436100 --grep='180' ; echo ---; git branch -a --contains 33da864 2>/dev/null | head; echo ---; git log --oneline -20 8436100
4ba861f fix(drain): no posting hint; the live proof names a model miss as CANNOT PROVE and has a fixture per tree
d9b136c fix(ipc): a room's history is read in pages — a room past 256 KiB could not be read, tailed or board'ed at all
705d9d8 docs(adr): open gaps tracked for v0.2.10 — ADR-021 F18–F20, ADR-020 M19.11 live-turn gap
---
+ dbg/180-sessions
+ dbg/180-with-41
+ fix/180-no-defer
+ integrate/v0.2.10
  prd1/prompt-sync
+ test/two-member-collisions
+ wip/180-busy-room-gate
  remotes/origin/dbg/180-sessions
  remotes/origin/dbg/180-with-41
  remotes/origin/fix/180-no-defer
---
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
885d2f5 ci(ui): the TUI names proof runs in CI, as a cargo test, with a pinned pyte (#198)
d9f4b48 test(relay): the direct control's bound is RETIRE_GRACE_SECS + 15 s, and it says which way the pair was direct
265c41c ci: macOS runners stop Spotlight indexing before the tests
91a4fe0 fix(r41): calibration paces its sender by sleeping, never forgiving a backlog, and a refusal names each window and what competed for the CPU
1094d62 test(relay): a direct control waits out a retired circuit's grace instead of counting it once
f9c42f8 test: R40 relayed chat on the shipped binary, with the relay asserted and a direct control (V29-07, #42)
3a6ac6d test(watchdog): an aborted gate leaves nothing running — the watchdog kills the test's descendants first (V210-28)
acf11b4 test(ui): the TUI names a trusted member by its name and anyone else by 26 characters, marked (#198)
946a62a merge: #41 — a colliding push backs off desynchronised and is never left to the 30 s interval
d5cf677 merge: #191 — a failed attach says why, in a person's words (a stale socket, an early close, another process)
69244a9 test(profile): a profile is free the moment Shutdown answers Done, proved through the shipped binary (#51, V29-16)
40076eb fix(ui): a member is named past the reach of key grinding, or by the name you gave it (#198)
d78e2b2 fix(agent-hook): the drain says the messages were posted in the room, not that other agents posted them
c355176 merge: #195 — one author cannot forge another's row in the agent drain, and a backlog does not flood a turn
d63bf7e merge: #40 — a restarted peer is reached again at once; with V29-15 (#50) and #173 (relay circuits on IPv6)
464212e test(agent-hook): the forgery gate sends a row through every line break, not three
7874f7e merge: #164 — install_sh_proof survives a slow python start and names why when it cannot
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git show fix/180-no-defer:crates/vox-core/src/node/actor.rs > /tmp/actor_180.rs 2>/dev/null; wc -l /tmp/actor_180.rs; grep -n 'syncing\b\|syncing_with\|in_session_with\|room_in_session' /tmp/actor_180.rs | head -40
6837 /tmp/actor_180.rs
269:        NodeCommand::Sync { .. } => "syncing",
1729:    syncing: std::collections::BTreeSet<(Digest32, Digest32)>,
1943:            syncing: std::collections::BTreeSet::new(),
3378:                self.syncing.remove(&(channel_id, peer));
3609:        // other operation on that room queued behind it: sending a message, syncing,
4347:            if !self.in_session_with(&channel_id, &target) {
4723:    /// session with that peer for that room must not start into (see `syncing`).
4724:    fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
4725:        self.syncing.contains(&(*channel_id, *peer))
4863:                if self.in_session_with(cid, &peer) || self.publishing.contains(&(*cid, peer)) {
4908:                if self.in_session_with(cid, &peer) {
5020:        if self.in_session_with(channel_id, &peer) {
5026:        self.syncing.insert((*channel_id, peer));
5096:            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
5167:        self.syncing.insert((channel_id, peer));
5260:        if self.in_session_with(&channel_id, &peer) {
[0m
#180 is NOT in the tree the ADR cites. This is important. Let me check the #180 branch's actual guard:
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git show 33da864 -- crates/vox-core/src/node/actor.rs | head -250
(no output)
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git show 33da864 --stat; echo ===; git show 33da864 | head -400
(no output)
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git show 33da864 -- crates/vox-core/src/node/actor.rs > /tmp/180_diff.txt; wc -l /tmp/180_diff.txt
166 /tmp/180_diff.txt
[0m
[0m→ [0mRead /tmp/180_diff.txt
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=160, offset=3340][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=140, offset=1660][0m
Now let me read the SyncDone/PushRetry handlers and the remaining pieces:
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs
Now the sync protocol itself:
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs
[0m✱ [0mGrep "fn sync_over_room|struct SyncOutcome|applied|SessionRoom for|fn frontiers|fn wants|fn entries|fn apply"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs · 37 matches[0m
Now syncstream.rs and the channel-side plumbing:
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [limit=80, offset=195][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [limit=120, offset=2060][0m
Let me read the SyncOutcome and the sync_over_room / SessionRoom impl in channel.rs:
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [limit=54, offset=2660][0m
[0m✱ [0mGrep "SessionBusy|0x0[Bb]|EpochMismatch"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/wire.rs · 12 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [limit=40, offset=2713][0m
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git log --oneline --all --grep='b6545e5' ; git cat-file -t b6545e5 2>&1; ls crates/vox-tui/tests/ | grep -i 'sync\|collision\|dead_member' ; ls test/ 2>/dev/null | head -30
3bb6ca1 test(sync): two members posting at once, with no other path, never wait out the 30 s interval
commit
a_sync_failure_names_its_reason_proof.rs
[0m
[0m✱ [0mGrep "fn finish|fn close|fn recv|fn send|SILENCE|struct QuicStreamTransport"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs · 13 matches[0m
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && sed -n '1,80p' crates/vox-tui/tests/a_sync_failure_names_its_reason_proof.rs
//! V210-29 (#202) — **a sync that did not complete says why**, through the shipped binary.
//!
//! Alice and Bob are real `vox daemon`s in one room, behind a real `vox node` anchor. They post
//! at the same moment, [`ROUNDS`] times, so their pushes collide: each end's session for the room
//! is running when the other's arrives, and each refuses the other. That collision is the
//! commonest failure between two live members, and the push retry resolves it.
//!
//! Before #202 the daemon said nothing about a failed sync. Inside, every one was wrapped as
//! "malformed governance struct: sync failed: transport": the refusal was sent with the code for
//! an invalid authenticator, and the initiator never read the code at all. So a collision could
//! not be told from a dead path, and whatever reported it pointed at corrupt data.
//!
//! What this asserts, on both daemons' stderr:
//! 1. at least one failed sync is reported **as a collision**: "the peer was busy syncing this
//!    room";
//! 2. no failed sync between the two members is reported as a governance or malformed-data
//!    error, or as an invalid authenticator.
//!
//! If no collision happened in all the rounds, the run proves nothing, and it fails as CANNOT
//! MEASURE rather than passing.
//!
//! Mutations: the old governance wrapper in `sync_failure` breaks (2); a collision refused with the
//! uninformative code breaks (1) and (2).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// Rounds of both members posting at once.
const ROUNDS: usize = 40;
const TIMEOUT: Duration = Duration::from_secs(90);
/// What a collision reads as, from the coded reason `SessionBusy`.
const COLLISION: &str = "the peer was busy syncing this room";

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs[90m [limit=110, offset=30][0m
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git cat-file -t 582f18a && git log -1 --format='%s' 582f18a; grep -rn 'SILENCE_IS_DEATH' crates/vox-core/src --include='*.rs' -l | head -3
commit
fix(net): a restarted peer is reachable through its anchor as soon as it is back
crates/vox-core/src/node/net.rs
crates/vox-core/src/node/actor.rs
crates/vox-core/src/wire.rs
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=80, offset=960][0m
Let me check the inbound stream path and slot accounting (line ~994), plus the pairwise incoming_session_wins usage:
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && grep -n 'incoming_session_wins' -r crates/ | head; grep -n 'SyncRequest' crates/vox-core/src/node/actor.rs | head
crates/vox-core/src/node/actor.rs:74:fn incoming_session_wins(me: &Digest32, peer: &Digest32, existing_mine: bool) -> bool {
crates/vox-core/src/node/actor.rs:1801:    /// ends apply one rule and converge: [`incoming_session_wins`].
crates/vox-core/src/node/actor.rs:5382:                if !incoming_session_wins(&me, &peer, existing_mine) {
crates/vox-core/src/node/actor.rs:5515:                Some(me) => incoming_session_wins(&me, &peer, existing_mine),
284:        NetEvent::SyncRequest { .. } => "answering a sync",
557:    SyncRequest {
897:                            .send(NetEvent::SyncRequest {
3251:            NetEvent::SyncRequest {
3537:                        // `NetEvent::SyncRequest` once the preamble is read.
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && git show 58fde36 -- crates/vox-core/src/node/actor.rs > /tmp/58_diff.txt && wc -l /tmp/58_diff.txt
140 /tmp/58_diff.txt
[0m
[0m→ [0mRead /tmp/58_diff.txt
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [limit=70, offset=3251][0m
[0m
[0m$ [0mcd /opt/vox/.claude/worktrees/ac-fix202 && grep -rn 'SYNC_FRAME_TIMEOUT' crates/vox-core/src --include='*.rs' | grep -v '//' | head -5; grep -n 'SILENCE_IS_DEATH' crates/vox-core/src/node/net.rs | head -3
crates/vox-core/src/transport/stream_transport.rs:29:pub const SYNC_FRAME_TIMEOUT: Duration = Duration::from_secs(20);
crates/vox-core/src/transport/stream_transport.rs:55:        Self::with_timeout(handle, send, recv, SYNC_FRAME_TIMEOUT)
336:pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);
394:    /// sampled, and when that count last moved. The evidence [`SILENCE_IS_DEATH`] reads.
445:    /// [`SILENCE_IS_DEATH`] is not handed out, because what is behind it is a process that has
[0m
Review complete. I read the ADR, the cited tree at 8436100 (`fix/202-sync-failure-reason`), the two #180 commits (33da864, 58fde36), the `fix/180-no-defer` tree, and the wire/transport layers. One structural fact shapes several findings: **8436100 does not contain #180** (`git merge-base --is-ancestor` says neither 33da864 nor 58fde36 is an ancestor; #180 landed separately in d92a130). In the cited tree `syncing` is `BTreeSet<Digest32>` — room-keyed (actor.rs:1732) — and both guards (actor.rs:5007, 5226) are room-wide. The per-(room,peer) guard exists only on the #180 branch.

---

## BLOCKER

None. The design direction is sound; everything below is repairable in the document.

## MAJOR

**M1 (Q2). D1's port cannot represent the state D4 mandates, and `SyncDone` cannot be attributed to a session.** D4 requires the higher end to run two streams for one (room, peer) pair at once (ADR line 226–228), but `Port::Running { dir: Out | In, ... }` (line 180) holds exactly one direction, and `NetEvent::SyncDone` carries only `{channel_id, peer, outcome}` (actor.rs:583–590) — no direction, no session token. Consequences, against the #180 structures the ADR says it keeps:
- Both sessions insert the same `syncing` key; the first `SyncDone` removes it (33da864's actor.rs:3378 equivalent), so the still-running second session is unguarded — a third session can start into the pair (`sync_one`/`run_sync_session` both key off that guard).
- If the inbound's completion `SyncDone` lands before the outbound's refusal `SyncDone`, the port cannot tell which ended. The stale refusal then either forces a clean port into `Awaiting` (a spurious ≤2 s delay plus an empty session) or misattributes the refusal to a *new* outbound.
- The transition `Awaiting` + inbound-arrives (keeper landing after the refusal, the normal relayed case) is not in the interleaving table at all.
Open question 3 gestures at this, but it is not an open question: it is the center of the design, and the safety claim "Two sessions can't run to completion at once" (line 246) is asserted for bookkeeping that does not yet exist. Fix: `SyncDone` gains direction (or a nonce); `Running` becomes `{ out: Option<..>, in: Option<..> }`; the table gains the `Awaiting`+inbound and stale-refusal rows.

**M2 (Q1). D3's "completed" is judged locally, but the peer's apply outcome is invisible after FIN — and a failed inbound on a clean port regresses a shipped defect scenario to the 30 s tick.** In `frontier_session_room_inner` each side calls `t.finish()` after serving, *before* its drain/apply (sync.rs:893 vs 896–916). So when the initiator I serves entries R refuses (the documented case: an author R hasn't admitted — `key_for` → None → `AuthenticatorInvalid`, sync.rs:611; this exact failure shipped once, channel.rs:2701–2708), I's drain ends at R's FIN and I returns `Ok` while R is still applying; R then fails (`apply_staged` → Err propagates, channel.rs:2709 → sync.rs:907). Result: I's `SyncDone` is Ok → D3 sets `done_gen = gen_at_have` — falsely, for the refused tail. R stored zero entries (refused the first), so R's `room.gen == done_gen`: R's port is clean, and D3's "failed ⇒ still dirty" (line 208) is only true if the port was dirty before. Nothing re-runs on either side until the 30 s tick. Today this recovers in 20–100 ms precisely because the `SyncDone` failure path is direction-blind (actor.rs:3430–3455 → PushRetry → R re-initiates → `sync_one` step 1 admits the author via `fetch_channel`, actor.rs:5026–5052). ADR-025 deletes that path and does not replace it. Fix: *any* non-completed session — failed or truncated, inbound or outbound — must leave the port dirty (paced by D5 `Backoff`), i.e. dirtiness is `room.gen > done_gen` *or* last session not completed. D7's "no proof may pass because of the tick" is otherwise violated by design.

**M2b (Q1). The serve-truncation signal D3 depends on does not exist and is not in the plan.** D3 sets `done_gen` only if "serve not cut short by `SERVE_BUDGET`/`MAX_SERVE_*`" (line 206), but `entries_for_wants` truncates silently (sync.rs:501–506), the serve loop breaks silently (sync.rs:888–890), and `SyncOutcome` is `{applied, governance, rendered}` (channel.rs:211–219) — no truncation flag. S1 adds `gen_at_have` to `SyncOutcome` but not this. Without it, a >1024-entry (or >64 MiB, or >30 s) backlog marks falsely clean; today's safety net is the module-doc rule "applied something ⇒ syncs again at once" (sync.rs:43–48) riding `o.applied > 0` (actor.rs:3492), which fails when the cut happens before any *new* entry lands. Also: Context line 27's "the **only** thing a session opened by Alice cannot carry from Bob is an entry Bob stored after Bob computed his `HAVE`" is false under the serve bounds the ADR itself cites — a pre-`HAVE` backlog past the caps is not carried either.

Separately on Q1's sub-questions: the peer's `WANT` is a pure function of the received `HAVE` frame (`wants_for`, sync.rs:450–476), so no mismatch window there — *provided* S1 reads the gen counter inside the same lock acquisition as `frontiers()` (channel.rs:2671–2675). A drain cut short fails the session loudly (sync.rs:901, though `SyncModeUnsupported` is a bizarre code for it) — that side is fine.

**M3 (Q5). Four of six proof rows fail the project's red-first/mutation rules.**
- **P1's second named mutant stays green.** "D4 with both ends accepting" yields zero refusals, zero retries, zero not-completed, fast delivery — none of P1's three assertions (line 310) distinguish D4 from accept-both. Counts are printed but not asserted (line 318–319). P1 needs an asserted session-count bound (the ADR's own pitch is "one session per collision", line 255).
- **P3 is likely green on the base.** With both members posting, collisions are guaranteed, and each refusal's `PushRetry` re-marks the peer's schedule (actor.rs:3371–3373), which rescues the slot-cap-skipped rooms within ~100 ms — under the 2 s bound. Only single-direction posting (Alice posts in 24 rooms, Bob silent) removes that accidental recovery path and makes the base red (skip → schedule cleared by unconditional `note_synced`, actor.rs:4920–4921 → 30 s wait).
- **P4 tests the wrong pair.** SIGSTOPping the lower end, then asserting the higher end's post reaches *a third member or the anchor* (line 313) exercises the (room, third-member) port — which #180 already decoupled (`a_dead_member_does_not_stall_the_room_proof`). The named mutant ("Awaiting with no deadline") changes nothing on that port: green on the mutant, and green on the base. The SIGSTOP mechanism itself is sound (a stopped process sends no reset; streams hang), but the assertion must be on the keeper's pair: after SIGCONT, L reads H's post within a bound, and H's port leaves `Awaiting` without waiting for the tick.
- **P5 cannot be red-first on the base — the ADR's own claim 3 says so.** The base already recovers a post-stored-after-`HAVE` via `pending_push` + the `SyncDone` re-arm (actor.rs:4850, 4940–4944, 3463–3466): the follow-up fires immediately at `SyncDone`, well inside "250 ms of the keeper's `SyncDone`". Claim 3 (lines 66–69) describes exactly this path. P5 is a valid *mutant* guard (mutant → 30 s → red) but the header rule "each red-first on the base" (line 306) is unmet. Re-scope it honestly.
- **Missing proofs:** (a) serve truncation (room with >`MAX_SERVE_ENTRIES` entries, or a shrunk `SERVE_BUDGET`): `done_gen` must not advance and catch-up must complete without the tick; (b) glare quiescence for M1: after the barrier, assert via S0b counters that sessions started == completed + failed and no port sits `Running`/`Awaiting`; (c) the M2 scenario (post from a not-yet-admitted author reaches the refuser promptly, tick excluded). P2's mutant-redness is statistical (needs a failed sole-carrier session); with measured ~2.3 refusals/round over 40 rounds it is overwhelming, but say so.

## MINOR

**m1 (Q7). D6's "The anchor publish, `note_new_members` and a consent's retry keep `room_in_session` from #180 unchanged" (lines 274–275) is false about the tree.** 58fde36 *removed* `room_in_session`, `publish_owed` and `growth_owed`; publish and `note_new_members` no longer defer at all, and the consent retry rides `in_session_with` (58fde36 diff, actor.rs hunk at 4339–4347 on the #180 tree). The ADR read 33da864 but not its follow-up. Per the standing rule, this must be corrected.

**m2 (Q3). Claim 1's citation doesn't support its wording on the cited tree.** "Finds its own session **with that peer** running (`run_sync_session`, the `syncing` check, ~5226)" — at 8436100:5226 the check is `self.syncing.contains(&channel_id)`, room-wide; per-peer is `in_session_with` on the #180 branch only. The outcome for the two-party case is identical and the #180 assumption is disclosed (line 8), but the cite is from the wrong tree.

**m3 (Q2). AWAIT_KEEPER: needed, 2 s defensible, and it must be measured from the refusal.** The refusal is the only deterministic local event; open question 1's alternative ("last frame seen on the keeper's session") has no anchor in exactly the case the deadline exists for (the keeper never sends a frame). 2 s is ~50× the measured relayed p95 (38.8 ms, per 33da864's own R40 note) — generous but harmless *except* that the lost-keeper path then costs ≥2 s, exceeding PRD-001 R40's 1 s by design; P4's bound (`AWAIT_KEEPER`+1 s) already concedes 3 s. State the R40 exception explicitly instead of discovering it in review. Also note: a refusal from a *lower* end that is `Running{In}` (still draining your previous session) misfires the keeper-signal semantics — bounded by the same 2 s, but worth one row in the table.

**m4 (Q4). The designated-initiator + "I have news" notify alternative is never discussed.** It kills glare entirely (no `Awaiting` needed) and is the obvious simpler design; its costs are (a) a wire change, violating the ADR's own constraint (line 174), and (b) notify reliability — which the ADR's own prior-art section already supplies the argument against (ssb-ebt#77/#61: "a long-lived stream still needs a reliable there-is-news signal", lines 144–146). One paragraph and the rejection writes itself; its absence is a hole given the review brief.

**m5 (Q4). The accept-both rejection is thin.** Accept-both also removes the random wait (both sessions run concurrently; inbound sessions take no slot — `start_session` has no `try_acquire`, actor.rs:5113–5164 vs 5010 — so slot pressure equals today's glare), and is correct now that locks are per-step (actor.rs:5079–5081, channel.rs:2089–2117). The honest residual arguments are duplicate bytes/work per collision and forfeiting the one-session-per-pair invariant the v0.3.0 stream design wants. Defensible, but "keeps the redundant session as the normal case" (line 289) alone doesn't carry it.

## NIT

- n1: Claim 3 cites "~4960" for "pushed means started"; the comment is actor.rs:4970–4971.
- n2: "The two ends can never refuse each other" (line 245) is overstated: epoch and membership refusals remain symmetric (actor.rs:5265–5284) and are paced by D5 `Backoff`. Say "never refuse *for busy*".
- n3: D1's migration list omits `syncing_with` (actor.rs:1738) and `push_now` (actor.rs:1762), both subsumed by the port.
- n4: Gen semantics across an epoch change are unspecified (frontiers reset; does gen?).
- n5: Under ADR-025, #202's proof loses its mutation checks too ("refused with the uninformative code breaks (1) and (2)" — `a_sync_failure_names_its_reason_proof.rs`), not just its collision assertion "replaced" (line 316).
- n6: Table row 5's "the second runs only if H was dirty" (line 243) conflates "runs" with "delivers"; the second session runs regardless, possibly empty.
- n7: The measured figures (35–47/40; 1,397; 703/702; 29.7 s) are not verifiable from these trees — they are harness outputs from `dbg/180-sessions` / vox-0e runs. The #202 harness exists and matches its description (ROUNDS=40, barrier-synchronised). Noted, not confirmed.

## Answers to the remaining numbered questions, compactly

- **Q3 claims 1–5:** 1 CONFIRMED modulo m2 (parts: 4717–4728 + 4774–4778; 5226; 3377–3455; constants at 174/178). 2 CONFIRMED (5010–5011, 240) and it **is** a real defect, not always promptly recovered: a slot-cap skip leaves the peer's schedule cleared (4920–4921) and `due()` gates every pass (4785–4789, syncstream.rs:102–113); the `SyncDone` re-arm (3463–3466) only sets `push_now`, which still hits the `due()` gate — absent a new append or a `PushRetry` re-mark (3371–3373), the skip waits out the 30 s interval. 3 CONFIRMED (comment 4970–4971; retry 3430–3455; the pending_push path recovers at `SyncDone`, faster than "when the room is busy at the next append" suggests — wording garbled, substance right). 4 CONFIRMED (six maps: 1665/1667/1675/1732/1772/1781 — plus `syncing_with` 1738; the three recorded disagreements at 4922–4935, 4963–4968, 3406–3413). 5 CONFIRMED (33da864 diff; room-wide guard still visible at 8436100:1732/5007/5226).
- **Q2 liveness, otherwise:** both- refuse and both-`Awaiting` are unreachable on the `SessionBusy` path (only L refuses; `Awaiting` requires a refusal of your outbound, and H's outbound is the only one refused). No port sticks forever absent the tick: `Awaiting` is bounded, hung sessions die at `SYNC_FRAME_TIMEOUT` 20 s (stream_transport.rs:29, 111–113), zombie sessions after a same-identity restart die when the dead connection is filed (582f18a, per 33da864's note). The restart-under-glare case converges within ~one `AWAIT_KEEPER` plus zombie clearance.
- **Q6 scope:** defensible. D3/D6 are defects by the code's own admission (4970–4971, 238–239); D4/D5 are honestly labelled an improvement and the release call is left to the decider (lines 298–303); S0b's `vox status --json` is new surface but is the project rule's price of measurable proofs. No unrelated creep in D1–D7.

## VERDICT

**REVISE.** The diagnosis is accurate and the switch shape is right, but the decision section is unsound at its two load-bearing points and the proof table does not yet meet the project's own red-first/mutation rule. The three changes I would most insist on:

1. **Make D4 representable:** `SyncDone` carries direction (or a session nonce), `Port` holds inbound and outbound concurrently, and the interleaving table gains the `Awaiting`+inbound-arrives and stale-refusal rows (fixes M1).
2. **Make D3 sound:** any non-completed session — failed *or* serve-truncated, in either direction — leaves the port dirty (fixes the clean-port failed-inbound regression to the 30 s tick, M2), and S1 ships the serve-truncation flag in `SyncOutcome`, not just `gen_at_have` (M2b).
3. **Rebuild the proof table:** P1 asserts a session-count bound (else the both-accept mutant is green); P3 posts single-direction (else the base is green via `PushRetry`); P4 asserts on the keeper's pair, not a third member; P5 is re-scoped as a mutant guard since claim 3 already explains why the base passes it; add the serve-truncation and glare-quiescence proofs (M3).
