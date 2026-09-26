[0m
> build · gpt-6-astra
[0m
[0m⚙ [0mak_skill_search {"query":"github-work-accountability","limit":1}
[0m→ [0mSkill "github-work-accountability"
[0m✱ [0mGlob "**/AGENTS.md"[90m in . · 0 matches[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 33da864
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

diff --git a/crates/vox-core/src/node/actor.rs b/crates/vox-core/src/node/actor.rs
index 249eccd..725d26e 100644
--- a/crates/vox-core/src/node/actor.rs
+++ b/crates/vox-core/src/node/actor.rs
@@ -1711,7 +1711,17 @@ pub struct Node {
     /// by *its* initiated session. Nothing breaks it but `SYNC_FRAME_TIMEOUT`. Measured as a user, a
     /// message posted right after a join crossed in 20s or 40s — one and two frame timeouts — instead
     /// of the 0-1s it takes when the rooms are free.
-    syncing: std::collections::BTreeSet<Digest32>,
+    ///
+    /// **Per room and peer, not per room.** Keyed by room alone, one session made the whole room
+    /// wait: a push to a member whose process had died waited for an answer until the connection
+    /// was declared dead (`SILENCE_IS_DEATH`, 30 s), and for all that time every other member's
+    /// session for the room was refused and every push to them was owed. One dead member stalled a
+    /// room for everyone (measured by log-scale, and in `a_dead_member_does_not_stall_the_room`).
+    /// What this guards against is a *pair* colliding, both ends reconciling the same room with
+    /// each other at once, so that is what it keys on. Sessions with different peers run side by
+    /// side: each takes the room's lock inside one protocol step at a time, never across the
+    /// network (`ChannelState::sync_over_room`).
+    syncing: std::collections::BTreeSet<(Digest32, Digest32)>,
     /// Rooms this node is joining right now (their join is on a `Joiner` task).
     joining: std::collections::BTreeSet<Digest32>,
     /// Pairwise streams for a room still being joined, held until the join reports back: see
@@ -2933,7 +2943,7 @@ impl Node {
         //
         // Owed instead, and run the moment that session's `SyncDone` lands — still on the actor, so
         // anything that follows a publish still follows it.
-        if self.syncing.contains(channel_id) {
+        if self.room_in_session(channel_id) {
             self.publish_owed.insert(*channel_id);
             return;
         }
@@ -3364,7 +3374,7 @@ impl Node {
                 peer,
                 outcome,
             } => {
-                self.syncing.remove(&channel_id);
+                self.syncing.remove(&(channel_id, peer));
                 self.answer_pending_consents(|room, _| *room == channel_id, None)
                     .await;
                 // **A session that failed delivered nothing, so its push is owed again.**
@@ -4337,7 +4347,7 @@ impl Node {
             // Started or not (the room may be mid-session with somebody else), the retry rides the
             // room's next `SyncDone`.
             let _ = self.sync_one(&channel_id, target).await;
-            if !self.syncing.contains(&channel_id) {
+            if !self.room_in_session(&channel_id) {
                 let _ = reply.send(outcome);
                 return;
             }
@@ -4683,7 +4693,7 @@ impl Node {
     /// because a board that already holds the record does not grow.
     async fn note_new_members(&mut self, channel_id: &Digest32) {
         // Never wait on a room a session holds; see `publish_channel_to_anchors`.
-        if self.syncing.contains(channel_id) {
+        if self.room_in_session(channel_id) {
             self.growth_owed.insert(*channel_id);
             return;
         }
@@ -4716,6 +4726,20 @@ impl Node {
         self.note_local_append(channel_id);
     }
 
+    /// Whether a sync session with `peer` is running on `channel_id`: the collision a new
+    /// session with that peer for that room must not start into (see `syncing`).
+    fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
+        self.syncing.contains(&(*channel_id, *peer))
+    }
+
+    /// Whether any sync session, with any peer, is running on `channel_id` (see `syncing`).
+    fn room_in_session(&self, channel_id: &Digest32) -> bool {
+        self.syncing
+            .range((*channel_id, [0u8; 32])..=(*channel_id, [0xFFu8; 32]))
+            .next()
+            .is_some()
+    }
+
     /// Mark a channel as having a local append to push, and make every peer's
     /// schedule due (ADR-016: "a push immediately after a local append").
     fn note_local_append(&mut self, channel_id: &Digest32) {
@@ -4851,7 +4875,7 @@ impl Node {
                 {
                     continue;
                 }
-                if self.syncing.contains(cid) || self.publishing.contains(&(*cid, peer)) {
+                if self.in_session_with(cid, &peer) || self.publishing.contains(&(*cid, peer)) {
                     owed.push(*cid);
                     continue;
                 }
@@ -4896,7 +4920,7 @@ impl Node {
                 {
                     continue;
                 }
-                if self.syncing.contains(cid) {
+                if self.in_session_with(cid, &peer) {
                     owed.push(*cid);
                     continue;
                 }
@@ -5008,13 +5032,13 @@ impl Node {
         if matches!(target, SessionTarget::Anchored(_)) {
             self.refresh_anchored_authors(channel_id).await;
         }
-        if self.syncing.contains(channel_id) {
-            return false; // a session already has this room; a second would deadlock against it
+        if self.in_session_with(channel_id, &peer) {
+            return false; // a session with this peer already has this room
         }
         let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
             return false; // past the cap: skipped, not queued. The schedule comes round again.
         };
-        self.syncing.insert(*channel_id);
+        self.syncing.insert((*channel_id, peer));
         let admit_store = self.profile.as_ref().map(Profile::store_handle);
         let cid = *channel_id;
         let now = self.now();
@@ -5155,7 +5179,7 @@ impl Node {
         };
         // Marked here, past both early returns above, so a session that never starts never
         // leaves the room marked. Its caller used to mark it first.
-        self.syncing.insert(channel_id);
+        self.syncing.insert((channel_id, peer));
         let now = self.now();
         let tx = self.net_tx.clone();
         tokio::spawn(async move {
@@ -5248,7 +5272,7 @@ impl Node {
         // **Refused before the lock, not after.** A session holds this room's mutex for its whole
         // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
         // behind the very session this check exists to detect.
-        if self.syncing.contains(&channel_id) {
+        if self.in_session_with(&channel_id, &peer) {
             let (mut send, mut recv) = (send, recv);
             crate::node::net::refuse_stream(&mut send, &mut recv);
             return;
diff --git a/crates/vox-tui/tests/a_dead_member_does_not_stall_the_room_proof.rs b/crates/vox-tui/tests/a_dead_member_does_not_stall_the_room_proof.rs
new file mode 100644
index 0000000..aa2ffe4
--- /dev/null
+++ b/crates/vox-tui/tests/a_dead_member_does_not_stall_the_room_proof.rs
@@ -0,0 +1,325 @@
+//! **One member whose process died does not stall the room for everyone else**, through the
+//! shipped binaries: a real `vox node` anchor and three real `vox daemon`s.
+//!
+//! A push to a member reconciles the room with it and waits for its answer. When that member's
+//! process has died without closing its connections (a crash, a kill, a laptop lid), nothing
+//! answers. The connection is declared dead only after `SILENCE_IS_DEATH` (30 s). The node used to
+//! hold the whole *room* for that session: every other member's session for the room was refused,
+//! and every push to them was owed, so a post between two live members waited up to 30 s behind a
+//! member who was gone (log-scale measured it: 29.5 s and 21.9 s to converge).
+//!
+//! Here Carol's daemon is killed by its PID once the three read each other. Alice then posts
+//! [`POSTS`] messages, and each one's crossing to Bob is timed. From `vox room post` returning to
+//! Bob's `vox room read` showing it, each must be within PRD-001 R40's chat bar, [`BOUND`].
+//!
+//! Mutation: key the session guard by room again (the pre-fix behaviour), and posts wait behind
+//! the push to the dead member.
+
+#![cfg(unix)]
+
+#[path = "../../vox-core/tests/support/watchdog.rs"]
+mod watchdog;
+
+use std::io::Write as _;
+use std::path::{Path, PathBuf};
+use std::process::{Child, Command, Stdio};
+use std::time::{Duration, Instant};
+
+const VOX: &str = env!("CARGO_BIN_EXE_vox");
+const ID_PASS: &str = "an identity passphrase";
+const ROOM_PASS: &str = "the room passphrase";
+
+struct Proc(Child);
+impl Drop for Proc {
+    fn drop(&mut self) {
+        let _ = self.0.kill();
+        let _ = self.0.wait();
+    }
+}
+
+struct Member {
+    name: &'static str,
+    data: PathBuf,
+    cfg: PathBuf,
+    pass: PathBuf,
+}
+
+impl Member {
+    fn new(root: &Path, name: &'static str) -> Self {
+        let (data, cfg) = (root.join(name).join("data"), root.join(name).join("cfg"));
+        std::fs::create_dir_all(&cfg).unwrap();
+        let pass = root.join(format!("{name}.pass"));
+        std::fs::write(&pass, ID_PASS).unwrap();
+        Self {
+            name,
+            data,
+            cfg,
+            pass,
+        }
+    }
+
+    fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
+        let mut cmd = Command::new(VOX);
+        cmd.args(args)
+            .env("VOX_DATA_DIR", &self.data)
+            .env("VOX_CONFIG_DIR", &self.cfg)
+            .env_remove("VOX_ROOM")
+            .env_remove("VOX_SESSION")
+            .env_remove("CLAUDE_CODE_SESSION_ID")
+            .env_remove("CODEX_THREAD_ID")
+            .stdin(if stdin.is_some() {
+                Stdio::piped()
+            } else {
+                Stdio::null()
+            })
+            .stdout(Stdio::piped())
+            .stderr(Stdio::piped());
+        let mut child = cmd.spawn().expect("spawn vox");
+        if let Some(s) = stdin {
+            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
+        }
+        let out = child.wait_with_output().unwrap();
+        let r = (
+            out.status.success(),
+            String::from_utf8_lossy(&out.stdout).into_owned(),
+            String::from_utf8_lossy(&out.stderr).into_owned(),
+        );
+        eprintln!(
+            "[receipt] {} vox {} -> {} {}",
+            self.name,
+            args.join(" "),
+            r.0,
+            r.2.trim()
+        );
+        r
+    }
+
+    fn fingerprint(&self) -> String {
+        let (ok, out, err) = self.vox(
+            &[
+                "id",
+                "--identity-passphrase-file",
+                self.pass.to_str().unwrap(),
+            ],
+            None,
+        );
+        assert!(ok, "{} id: {err}", self.name);
+        out.trim().to_owned()
+    }
+
+    fn daemon(&self, anchor: &str, err: &Path) -> Proc {
+        let child = Command::new(VOX)
+            .args([
+                "daemon",
+                "--listen",
+                "127.0.0.1:0",
+                "--anchor",
+                anchor,
+                "--passphrase-file",
+            ])
+            .arg(&self.pass)
+            .env("VOX_DATA_DIR", &self.data)
+            .env("VOX_CONFIG_DIR", &self.cfg)
+            .stdin(Stdio::null())
+            .stdout(Stdio::null())
+            .stderr(Stdio::from(std::fs::File::create(err).unwrap()))
+            .spawn()
+            .expect("spawn vox daemon");
+        let deadline = Instant::now() + Duration::from_secs(60);
+        while !self.vox(&["room", "list"], None).0 {
+            assert!(
+                Instant::now() < deadline,
+                "{}'s daemon never answered",
+                self.name
+            );
+            std::thread::sleep(Duration::from_millis(500));
+        }
+        Proc(child)
+    }
+}
+
+fn spawn_anchor(root: &Path) -> (Proc, String) {
+    let (a_data, a_cfg) = (root.join("anchor/data"), root.join("anchor/cfg"));
+    std::fs::create_dir_all(&a_cfg).unwrap();
+    let anchor_out = root.join("anchor.out");
+    let anchor = Proc(
+        Command::new(VOX)
+            .args(["node", "--listen", "127.0.0.1:0"])
+            .env("VOX_DATA_DIR", &a_data)
+            .env("VOX_CONFIG_DIR", &a_cfg)
+            .stdout(Stdio::from(std::fs::File::create(&anchor_out).unwrap()))
+            .stderr(Stdio::null())
+            .spawn()
+            .expect("spawn vox node"),
+    );
+    let deadline = Instant::now() + Duration::from_secs(60);
+    loop {
+        let text = std::fs::read_to_string(&anchor_out).unwrap_or_default();
+        if let Some(s) = text
+            .split_whitespace()
+            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
+        {
+            return (anchor, s.to_owned());
+        }
+        assert!(
+            Instant::now() < deadline,
+            "the anchor never printed its spec"
+        );
+        std::thread::sleep(Duration::from_millis(250));
+    }
+}
+
+/// PRD-001 R40: a message is readable by the other members within a second.
+const BOUND: Duration = Duration::from_secs(1);
+/// Posts timed after Carol dies.
+const POSTS: usize = 5;
+
+#[test]
+#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
+fn a_dead_member_does_not_stall_the_room() {
+    watchdog::arm();
+    let tmp = tempfile::tempdir().unwrap();
+    let root = tmp.path();
+    let (_anchor, spec) = spawn_anchor(root);
+    let members = [
+        Member::new(root, "alice"),
+        Member::new(root, "bob"),
+        Member::new(root, "carol"),
+    ];
+    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
+    for (i, m) in members.iter().enumerate() {
+        for (j, other) in members.iter().enumerate() {
+            if i != j {
+                let (ok, _, err) = m.vox(
+                    &[
+                        "trust",
+                        "add",
+                        &fps[j],
+                        "--name",
+                        other.name,
+                        "--identity-passphrase-file",
+                        m.pass.to_str().unwrap(),
+                    ],
+                    None,
+                );
+                assert!(ok, "{} trusts {}: {err}", m.name, other.name);
+            }
+        }
+    }
+    let mut daemons: Vec<Proc> = members
+        .iter()
+        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
+        .collect();
+    let [alice, bob, carol] = &members;
+    let (ok, _, err) = alice.vox(&["room", "create", "--name", "mission"], Some(ROOM_PASS));
+    assert!(ok, "create: {err}");
+    let room = alice
+        .vox(&["room", "list"], None)
+        .1
+        .split_whitespace()
+        .next()
+        .expect("a room")
+        .to_owned();
+    let link = alice
+        .vox(&["room", "invite", &room], None)
+        .1
+        .trim()
+        .to_owned();
+    for m in [bob, carol] {
+        let mut joined = false;
+        for attempt in 1..=6 {
+            if m.vox(
+                &["room", "join", &link, "--name", "mission"],
+                Some(ROOM_PASS),
+            )
+            .0
+            {
+                joined = true;
+                eprintln!("[receipt] {} joined on attempt {attempt}", m.name);
+                break;
+            }
+            std::thread::sleep(Duration::from_secs(5));
+        }
+        assert!(
+            joined,
+            "{} never joined, which is not what this proves",
+            m.name
+        );
+    }
+    // Everyone reads everyone before Carol dies: keys have flowed and every pair has a session.
+    let mut pending: Vec<(&str, &str)> = Vec::new();
+    for r in &members {
+        for w in &members {
+            if r.name != w.name {
+                pending.push((r.name, w.name));
+            }
+        }
+    }
+    let start = Instant::now();
+    let mut round = 0u32;
+    while !pending.is_empty() {
+        assert!(
+            start.elapsed() < Duration::from_secs(90),
+            "CANNOT MEASURE: {pending:?} still unread after 90 s, before anyone died"
+        );
+        round += 1;
+        for w in &members {
+            if pending.iter().any(|(_, pw)| *pw == w.name) {
+                let (ok, _, err) = w.vox(
+                    &["room", "post", &room, &format!("warm-{}-{round}", w.name)],
+                    None,
+                );
+                assert!(ok, "{} posts: {err}", w.name);
+            }
+        }
+        std::thread::sleep(Duration::from_secs(1));
+        for r in &members {
+            let (_, out, _) = r.vox(&["room", "read", &room], None);
+            pending.retain(|(pr, pw)| !(*pr == r.name && out.contains(&format!("warm-{pw}-"))));
+        }
+    }
+    eprintln!("everyone reads everyone after {:?}", start.elapsed());
+
+    // Carol's process dies without closing anything.
+    let pid = daemons[2].0.id();
+    let _ = daemons[2].0.kill();
+    let _ = daemons[2].0.wait();
+    eprintln!("[test] carol's daemon, pid {pid}, killed and reaped");
+    daemons.truncate(2);
+
+    let mut took = Vec::new();
+    for i in 1..=POSTS {
+        let text = format!("after-carol-{i}");
+        let (ok, _, err) = alice.vox(&["room", "post", &room, &text], None);
+        assert!(ok, "alice posts: {err}");
+        let posted = Instant::now();
+        let seen = loop {
+            let (_, out, _) = bob.vox(&["room", "read", &room], None);
+            if out.contains(&text) {
+                break Some(posted.elapsed());
+            }
+            if posted.elapsed() > Duration::from_secs(40) {
+                break None;
+            }
+            std::thread::sleep(Duration::from_millis(50));
+        };
+        eprintln!(
+            "post {i} after carol died: bob read it {}",
+            seen.map_or("never within 40 s".to_owned(), |d| format!(
+                "{d:?} after it was posted"
+            ))
+        );
+        took.push(seen);
+    }
+    let late: Vec<String> = took
+        .iter()
+        .enumerate()
+        .filter(|(_, t)| t.is_none_or(|d| d > BOUND))
+        .map(|(i, t)| format!("post {}: {t:?}", i + 1))
+        .collect();
+    assert!(
+        late.is_empty(),
+        "with carol dead, alice's posts reached bob beyond {BOUND:?}: {late:?} — a push to the dead \
+         member held the room for everyone"
+    );
+}
diff --git a/docs/adr/ADR-016-node-runtime.md b/docs/adr/ADR-016-node-runtime.md
index 86852e1..df51234 100644
--- a/docs/adr/ADR-016-node-runtime.md
+++ b/docs/adr/ADR-016-node-runtime.md
@@ -951,6 +951,26 @@ These record the concrete decisions made building this ADR (`crates/vox-core/src
   prompt push: 27.1 s and 21.7 s, red. Mutation, no board offer: 27.6 s and 26.4 s, red. R40 is
   unaffected: relayed p95 64 ms, direct p95 31 ms.
 
+- **One dead member no longer stalls a room for everyone (2026-09-25, v0.2.10).** A push reconciles
+  the room with a member and waits for its answer. When that member's process died without closing
+  its connections, nothing answered until the connection was declared dead (`SILENCE_IS_DEATH`,
+  30 s). The session guard (`syncing`) was keyed by room, so for the whole wait every other member's
+  session for the room was refused and every push to them was owed. log-scale measured it with
+  shipped daemons: converged 29.5 s and 21.9 s after a member returned.
+  - The guard is now keyed by **room and peer**. What it prevents is a pair colliding, both ends
+    reconciling the same room with each other at once, and a pair is what it keys on.
+  - Sessions with different peers run side by side. Each takes the room's lock inside one protocol
+    step at a time, never across the network (`ChannelState::sync_over_room`).
+  - Work that must not wait on a room held by any session (the anchor publish, `note_new_members`)
+    asks `room_in_session`.
+
+  Gate `crates/vox-tui/tests/a_dead_member_does_not_stall_the_room_proof.rs` (a real anchor and three
+  real daemons; Carol's daemon killed by PID; five posts from Alice timed to Bob's `vox room read`,
+  bound 1 s, R40): 56–65 ms each, 2 runs. Mutation, guard keyed by room again: posts waited 30.0 s and
+  29.3 s, red. Not covered here: a member that restarts under the **same** identity while the old
+  session still waits is refused as the same pair until that session ends. restart-probe's held-
+  connection probe (582f18a) closes the dead connection when the newcomer is filed.
+
 ## Links
 **Depends on**: ADR-002, ADR-003, ADR-005, ADR-006, ADR-007, ADR-008, ADR-010, ADR-011, ADR-012,
 ADR-013, ADR-015.
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36
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

diff --git a/crates/vox-core/src/node/actor.rs b/crates/vox-core/src/node/actor.rs
index 8aa9785..395f57c 100644
--- a/crates/vox-core/src/node/actor.rs
+++ b/crates/vox-core/src/node/actor.rs
@@ -1738,16 +1738,10 @@ pub struct Node {
         quinn::SendStream,
         quinn::RecvStream,
     )>,
-    /// Rooms whose anchor publish found them mid-session: run when that session's `SyncDone`
-    /// lands. See `publish_channel_to_anchors`.
-    publish_owed: std::collections::BTreeSet<Digest32>,
     /// Per room, the members this node's board has held a bundle record for. A record from an
     /// author not in it is a member this node has just learned of, which is what
     /// `note_new_members` passes on at once; a refresh of a known member's record is not.
     board_authors: BTreeMap<Digest32, std::collections::BTreeSet<Digest32>>,
-    /// Rooms whose board grew while a session held them: `note_new_members` runs when that
-    /// session's `SyncDone` lands, like `publish_owed`.
-    growth_owed: std::collections::BTreeSet<Digest32>,
     /// `(room, board)` publish rounds in flight on their own tasks; see `publish_channel_to_anchor`.
     publishing: std::collections::BTreeSet<(Digest32, Digest32)>,
     /// Publishes asked for while that `(room, board)` round was in flight: run when it ends.
@@ -1949,9 +1943,7 @@ impl Node {
             syncing: std::collections::BTreeSet::new(),
             joining: std::collections::BTreeSet::new(),
             held_pairwise: Vec::new(),
-            publish_owed: std::collections::BTreeSet::new(),
             board_authors: BTreeMap::new(),
-            growth_owed: std::collections::BTreeSet::new(),
             publishing: std::collections::BTreeSet::new(),
             publish_again: std::collections::BTreeSet::new(),
             publish_waiters: Vec::new(),
@@ -2949,20 +2941,13 @@ impl Node {
         let Some(net) = self.net.as_ref().map(Arc::clone) else {
             return;
         };
-        // **Never wait on a room a session holds.** Building the records takes the room's lock, and
-        // a sync session holds that lock for its whole run on a blocking thread — bounded only by
-        // the 20s frame timeout when the peer is slow. Measured through the real binaries with the
-        // wait timed: `publish waited 19.9987s for the ROOM lock`, against `busy 20005ms — passing on
-        // a record that landed on our board`, while every put on the wire took under 22ms. It was
-        // also half of a cycle: this actor waiting on its room, whose session waited on a peer
-        // whose actor was waiting the same way, broken only by the frame timeout.
-        //
-        // Owed instead, and run the moment that session's `SyncDone` lands — still on the actor, so
-        // anything that follows a publish still follows it.
-        if self.room_in_session(channel_id) {
-            self.publish_owed.insert(*channel_id);
-            return;
-        }
+        // **Not deferred while a session runs.** This used to be owed until the room had no
+        // session at all, because a session held the room's lock for its whole run (measured:
+        // `publish waited 19.9987s for the ROOM lock`). Since 3f95b57 a session takes the lock
+        // per protocol step and never across I/O, so the wait here is one step. Deferring had
+        // become the hazard instead: with sessions guarded per (room, peer) (#180), sessions
+        // with different members overlap, a busy room is never session-free, and the owed
+        // publish could wait indefinitely while joiners read a stale board.
         let anchors: Vec<Arc<VoxConnection>> = self
             .anchor_ids
             .iter()
@@ -3440,12 +3425,6 @@ impl Node {
                     // A push that found this room mid-session is owed; the room is free now.
                     self.push_now = true;
                 }
-                if self.publish_owed.remove(&channel_id) {
-                    self.publish_channel_to_anchors(&channel_id).await;
-                }
-                if self.growth_owed.remove(&channel_id) {
-                    self.note_new_members(&channel_id).await;
-                }
                 self.refresh_network_view().await;
                 if let Ok(o) = outcome {
                     // **Event, not interval.** Propagation was event-driven in one direction only:
@@ -4360,10 +4339,12 @@ impl Node {
             .as_ref()
             .is_some_and(|n| n.manager().existing(&target).is_some());
         if connected {
-            // Started or not (the room may be mid-session with somebody else), the retry rides the
-            // room's next `SyncDone`.
+            // Started or not (a session with this same member may already be running), the retry
+            // rides the next `SyncDone` of a session **with the target**. Checking for any session
+            // on the room kept a consent waiting on sessions with other members, which, now that
+            // sessions are guarded per (room, peer), need never all end.
             let _ = self.sync_one(&channel_id, target).await;
-            if !self.room_in_session(&channel_id) {
+            if !self.in_session_with(&channel_id, &target) {
                 let _ = reply.send(outcome);
                 return;
             }
@@ -4708,11 +4689,7 @@ impl Node {
     /// member per join, over the connections it already holds, with nothing forwarded twice
     /// because a board that already holds the record does not grow.
     async fn note_new_members(&mut self, channel_id: &Digest32) {
-        // Never wait on a room a session holds; see `publish_channel_to_anchors`.
-        if self.room_in_session(channel_id) {
-            self.growth_owed.insert(*channel_id);
-            return;
-        }
+        // Not deferred while a session runs; see `publish_channel_to_anchors`.
         let (Some(net), Some(shared)) = (
             self.net.as_ref().map(Arc::clone),
             self.channels.get(channel_id).map(Arc::clone),
@@ -4748,14 +4725,6 @@ impl Node {
         self.syncing.contains(&(*channel_id, *peer))
     }
 
-    /// Whether any sync session, with any peer, is running on `channel_id` (see `syncing`).
-    fn room_in_session(&self, channel_id: &Digest32) -> bool {
-        self.syncing
-            .range((*channel_id, [0u8; 32])..=(*channel_id, [0xFFu8; 32]))
-            .next()
-            .is_some()
-    }
-
     /// Mark a channel as having a local append to push, and make every peer's
     /// schedule due (ADR-016: "a push immediately after a local append").
     fn note_local_append(&mut self, channel_id: &Digest32) {
diff --git a/docs/adr/ADR-016-node-runtime.md b/docs/adr/ADR-016-node-runtime.md
index 1a90ceb..695955c 100644
--- a/docs/adr/ADR-016-node-runtime.md
+++ b/docs/adr/ADR-016-node-runtime.md
@@ -976,8 +976,17 @@ These record the concrete decisions made building this ADR (`crates/vox-core/src
     reconciling the same room with each other at once, and a pair is what it keys on.
   - Sessions with different peers run side by side. Each takes the room's lock inside one protocol
     step at a time, never across the network (`ChannelState::sync_over_room`).
-  - Work that must not wait on a room held by any session (the anchor publish, `note_new_members`)
-    asks `room_in_session`.
+  - The anchor publish and `note_new_members` are **not** deferred while sessions run. They used to
+    be owed until the room had no session at all, which was right while a session held the lock for
+    its whole run. Once sessions lock per step and overlap per peer, a busy room need never be
+    session-free, and the owed publish could wait indefinitely while joiners read a stale board
+    (agent_comms's review of 33da864). The deferral is removed; the actor waits at most one step.
+    An explicit consent's retry rides the next `SyncDone` of a session **with its target**
+    (`in_session_with`), not of any session on the room.
+    - Not gated red-first. On today's tree the anchor learns a joiner from its own copy of the log,
+      so no anchor-visible change depends on a busy member's publish: a busy-room gate stayed green
+      before and after (5 of 5 on 33da864 and 69aaff5). It can bite once anchors store nothing
+      (ADR-023 M23.5). The regression checks are the dead-member and new-member gates.
 
   Gate `crates/vox-tui/tests/a_dead_member_does_not_stall_the_room_proof.rs` (a real anchor and three
   real daemons; Carol's daemon killed by PID; five posts from Alice timed to Bob's `vox room read`,
[0m
[0m$ [0mawa status --json
{"host": "github.com", "managed": true, "managed_issue_count": 197, "repository": "robertelee78/vox", "schema": "agent-work-accountability/status-v1", "transport": "github-rest-search"}
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/syncstream.rs
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs
[0m✱ [0mGlob "AGENTS.md"[90m in /opt/vox · 0 matches[0m
[0m✱ [0mGrep "sync_over_room|ChannelSessionRoom|fn apply|frontiers|SyncOutcome"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs · 41 matches[0m
[0m
[0m$ [0mgit rev-parse HEAD && git diff -- docs/adr/ADR-025-sync-scheduling-switch-not-hub.md && git -C /opt/vox/.claude/worktrees/ac-fix202 rev-parse HEAD && git -C /opt/vox/.claude/worktrees/ac-fix202 diff -- crates/vox-core/src/node/actor.rs crates/vox-core/src/log/sync.rs crates/vox-core/src/node/channel.rs crates/vox-core/src/node/syncstream.rs
8c4e3473bc20d1b0b6a308b5e1c63b41d60b4d6d
843610005df17ecac6d3d803adeed12491f21654
[0m
[0m$ [0mgh issue list --repo robertelee78/vox --state all --search '"ADR-025"' --json number,title,body --limit 20
[]
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=3340, limit=260][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/anchor.rs[90m [offset=320, limit=180][0m
[0m✱ [0mGrep "incoming_session_wins|owed_a_reason|run_due_syncs|push_now|SYNCS_IN_FLIGHT|QUICK_PUSH_RETRIES|MAX_PUSH_RETRY_WAIT"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node · 34 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=2080, limit=90][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=2640, limit=155][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=4670, limit=740][0m
D3’s completion claim is not supported by the current protocol: each side sends FIN before draining and applying the peer’s entries, so local success does not establish remote acceptance. I also found a baseline distinction: `8436100` still has the room-wide guard; the ADR assumes #180 is integrated, and #180’s second commit removes the `room_in_session` behavior D6 says to retain.
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-tui/tests/a_sync_failure_names_its_reason_proof.rs
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=60, limit=25][0m
[0m✱ [0mGrep "impl Transport|fn finish|fn close|SYNC_FRAME_TIMEOUT|fn send\(|fn recv\("[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport · 6 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=2030, limit=95][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=1670, limit=110][0m
[0m
[0m$ [0mgit worktree list --porcelain
worktree /opt/vox
HEAD 671527ad2c10983718ea62b7a304678e0d5a5120
branch refs/heads/main

worktree /opt/vox-work-accountability-vocabulary
HEAD 175a78d0ecf60daa1d8125b84421a62c8ad7fb4d
branch refs/heads/docs/work-accountability-vocabulary-20260924

worktree /opt/vox/.claude/worktrees/ac-adr025
HEAD 8c4e3473bc20d1b0b6a308b5e1c63b41d60b4d6d
branch refs/heads/docs/adr-025-sync-switch

worktree /opt/vox/.claude/worktrees/ac-fix202
HEAD 843610005df17ecac6d3d803adeed12491f21654
branch refs/heads/fix/202-sync-failure-reason

worktree /opt/vox/.claude/worktrees/adr021-impl
HEAD a3937b1206d5e042518dd1da86dd2a7980a2999a
branch refs/heads/feat/adr021-work-interop

worktree /opt/vox/.claude/worktrees/agent-a27cba890933ab4f5
HEAD 2657f1689c55baf80f6796f3994503837d8d3ef8
branch refs/heads/fix/f12-joiners-read-each-other

worktree /opt/vox/.claude/worktrees/agent-a9c32daf69b87fb9a
HEAD abcf07378ee9a1efce346c22f22a2adca8b88bf3
branch refs/heads/fix/f14-say-rate-limited

worktree /opt/vox/.claude/worktrees/agentcomms-adr024
HEAD 02f07ce84b7e05b0f22b25c710a7b16f6052e5bc
branch refs/heads/docs/adr-024-tapered-congestion-control

worktree /opt/vox/.claude/worktrees/agentcomms-bbr
HEAD 1b5efd9acc323b83a3ddb6f7ded04fde94383dec
branch refs/heads/agentcomms/exp-bbr

worktree /opt/vox/.claude/worktrees/agentcomms-bench
HEAD e7f6a4f33da78ddb8b80317293505685f9bcee9e
detached

worktree /opt/vox/.claude/worktrees/agentcomms-c4198d1b
HEAD 4198d1b8439936421cf132a944fc300e63135552
detached

worktree /opt/vox/.claude/worktrees/agentcomms-m241
HEAD b09c8154c5b355bfd6ea7c93f9242b6329a7f032
branch refs/heads/agentcomms/spike-m241-loss-aware

worktree /opt/vox/.claude/worktrees/agentcomms-mainmerge
HEAD 10204f7aca52cb1aec734148651ab9d3d8cf8dab
detached

worktree /opt/vox/.claude/worktrees/agentcomms-noq
HEAD d3b35dbea8a304cda0b6b975ff856bcced609185
branch refs/heads/agentcomms/exp-noq

worktree /opt/vox/.claude/worktrees/agentcomms-noqc
HEAD 84578cc7b30083a55fc25ce0f2a07b5aac1a3caa
branch refs/heads/agentcomms/exp-noq-cubic

worktree /opt/vox/.claude/worktrees/agentcomms-splice
HEAD cf659849c971fbe9f19aac2ace7900b3b1111ca3
branch refs/heads/agentcomms/splice-chunks

worktree /opt/vox/.claude/worktrees/agentcomms-tputA
HEAD d69fd2e32f63f22729d80aa60690f79e478bf965
detached

worktree /opt/vox/.claude/worktrees/agentcomms-v028
HEAD 56db6b1ac3774bdd938a819be6dba2040fc9fe6e
detached

worktree /opt/vox/.claude/worktrees/agentcomms-v2903
HEAD 5612274a4fa622c7cf0ae8b859483b11e03114c2
branch refs/heads/test/v29-03-non-member-sync-real

worktree /opt/vox/.claude/worktrees/approve
HEAD 652eceb621e83039e361c7faf75eb2087f98ec69
branch refs/heads/docs/approve-prd001-adr022-023

worktree /opt/vox/.claude/worktrees/chk-app
HEAD e4e2ff9bdfbec6f4903467029eaeccdcc29ad60c
detached

worktree /opt/vox/.claude/worktrees/chk-ret
HEAD 85fb55e82e645f25343f85c80f1574d396a8641c
detached

worktree /opt/vox/.claude/worktrees/d180
HEAD dddd316c78e3c27d4049df5233f862b5d115783c
branch refs/heads/dbg/180-sessions

worktree /opt/vox/.claude/worktrees/d180b
HEAD 03afbc7ee31a061360ab3745ec4247fef050b7a3
branch refs/heads/dbg/180-with-41

worktree /opt/vox/.claude/worktrees/del
HEAD 82905606992ce7d7118fcd4a66388f5fe7ceb807
detached

worktree /opt/vox/.claude/worktrees/diag-mac
HEAD 25c94fd94aa4fab3b49eb35bd498666f7d1bfbcb
detached

worktree /opt/vox/.claude/worktrees/drain-base
HEAD b22aaeedfbb24f6b7a355286e56245f315b1fb74
branch refs/heads/fix/adapter-stream-lag-by-bytes

worktree /opt/vox/.claude/worktrees/drain-ctl
HEAD 91da36eced54f0b47235ca85aeb85d730372f17d
detached

worktree /opt/vox/.claude/worktrees/e196
HEAD 396889ed2795813013649d78f33db6b13aee1f23
branch refs/heads/port/error-messages-keyring

worktree /opt/vox/.claude/worktrees/f15
HEAD 2ed69a8cc1fed81115823356c41e15eb1fc39bbd
branch refs/heads/fix/f15-daemon-wakes-on-sync

worktree /opt/vox/.claude/worktrees/f18
HEAD e98c88201b042e2d404e40e67072d276130d9626
branch refs/heads/fix/f18-adapter-stream-bimodal

worktree /opt/vox/.claude/worktrees/f19
HEAD 2807cc88e6c94ad60ac81c493b0f13b5c0996068
branch refs/heads/test/f19-order-survives-restart

worktree /opt/vox/.claude/worktrees/fix-attach-names-its-error
HEAD 0dcf7a334faba7b31c822283d3f029f8292e7dae
branch refs/heads/fix/attach-names-its-error

worktree /opt/vox/.claude/worktrees/fix179
HEAD 693ffba66274d9f9aff6c9486b760538eeaf756d
branch refs/heads/fix/absorb-one-transaction

worktree /opt/vox/.claude/worktrees/hang
HEAD 61d3a3632e8ca4f045d59024ea76d0573c88ab04
branch refs/heads/fix/190-dial-cannot-spin

worktree /opt/vox/.claude/worktrees/hang-m15
HEAD 30375255da7213ea75940014c97db074298c5bff
detached

worktree /opt/vox/.claude/worktrees/integrate
HEAD 3292a19f97ab156459f3b57a335409534037d15c
branch refs/heads/v29/no-unreal-tests

worktree /opt/vox/.claude/worktrees/land-029
HEAD d9b136cb0b33a3c63d7e78e9d4a2d14359742761
detached

worktree /opt/vox/.claude/worktrees/land-adr
HEAD 705d9d823e7009ec18c0d3ba4d82d082e43537e5
detached

worktree /opt/vox/.claude/worktrees/plan-v29
HEAD 509ac3231109393498c50a6c3ce5ba19eef8ef9f
branch refs/heads/docs/release-hardening-plan

worktree /opt/vox/.claude/worktrees/port-err
HEAD a096735e0dbf05ed0add5bc4de1cd52e9c9d51af
branch refs/heads/port/error-messages

worktree /opt/vox/.claude/worktrees/port-get
HEAD ea7a08504539104033b4fb8a12c18c54a792145f
branch refs/heads/wip/194-followups

worktree /opt/vox/.claude/worktrees/port-hook
HEAD 464212e0e8bb9b6fca02eb94e4eeb58af0c0f9e9
branch refs/heads/port/agent-hook-forged-rows

worktree /opt/vox/.claude/worktrees/post-readback
HEAD 3b130e1fa117096705cb56188e3afa1c89aa2f73
branch refs/heads/fix/drain-frames-room-as-data

worktree /opt/vox/.claude/worktrees/pqrecord
HEAD 922c6818d2b31f055af6392e298f9ad7d473e2b3
branch refs/heads/fix/say-what-is-observed

worktree /opt/vox/.claude/worktrees/prd
HEAD 9cb5b6c0f7f6fdd92dc0fafbd7d3acd3f370831a
branch refs/heads/docs/prd-transport-legitimacy

worktree /opt/vox/.claude/worktrees/prd1-161
HEAD 91da36eced54f0b47235ca85aeb85d730372f17d
branch refs/heads/prd1/connect-setup-161

worktree /opt/vox/.claude/worktrees/prd1-adr022
HEAD e236382d4aba61273af4c5bd562799f933f32d77
branch refs/heads/prd1/adr022-datagram-flows

worktree /opt/vox/.claude/worktrees/prd1-agentcomms-safety
HEAD 0e2d2695108faa11076f7a60c95f26bdf25bfbeb
branch refs/heads/prd1/key-packages-v029

worktree /opt/vox/.claude/worktrees/prd1-calls
HEAD e8f703d83495bfedbabd224fe6b67e937eab2b76
branch refs/heads/wip/calls-receiver-drop

worktree /opt/vox/.claude/worktrees/prd1-datagram
HEAD dd3f23308c603c036b642a863119dd21a2dfffcb
branch refs/heads/prd1/family-lan

worktree /opt/vox/.claude/worktrees/prd1-integrate
HEAD 7296b6bb4fcf452a72e19364b205ca18783bb5fc
branch refs/heads/prd1/integrate

worktree /opt/vox/.claude/worktrees/prd1-liveness
HEAD 3d7ab3f5d7de744c9f58c82c62de96b290cef9ee
branch refs/heads/prd1/restart-probe

worktree /opt/vox/.claude/worktrees/prd1-log-scale
HEAD c748ba6e7d109f817dbd5ed0ee73b473ba5b6cf0
branch refs/heads/prd1/log-scale

worktree /opt/vox/.claude/worktrees/prd1-main-v028
HEAD 3cac220a1d7d1230fe1b6fa730ae5bc73fc177a6
detached

worktree /opt/vox/.claude/worktrees/prd1-maxskip
HEAD 22c5748c439681031c913c1124bbac28952a33af
branch refs/heads/prd1/maxskip-bracket

worktree /opt/vox/.claude/worktrees/prd1-order
HEAD b78a6d99b5e4f83cf7ed18b12e1d8cceab2f9bad
branch refs/heads/prd1/causal-order

worktree /opt/vox/.claude/worktrees/prd1-order-abA
HEAD 3f9110944c0634b933711fad1f5e66389e2fe925
detached

worktree /opt/vox/.claude/worktrees/prd1-order-abB
HEAD 3f9110944c0634b933711fad1f5e66389e2fe925
detached

worktree /opt/vox/.claude/worktrees/prd1-perftight
HEAD d55c1fe069f35530203df8e647aaa8904838975e
branch refs/heads/prd1/perf-gates-tight

worktree /opt/vox/.claude/worktrees/prd1-publish
HEAD a6582b926d766082a4258c282ab1588097c60b45
branch refs/heads/prd1/publish-retries

worktree /opt/vox/.claude/worktrees/prd1-remove-deniability
HEAD b0f82185f3a0b791a03a540eb9d9107208bbe6d1
branch refs/heads/prd1/remove-deniability

worktree /opt/vox/.claude/worktrees/prd1-roomboard
HEAD 99249644fca53f3cace4be926306999959e3c508
branch refs/heads/prd1/join-room-not-on-board

worktree /opt/vox/.claude/worktrees/prd1-rulecheck
HEAD 0d4884a895bc040f68dd1df831a3a3368ca5945e
detached

worktree /opt/vox/.claude/worktrees/prd1-tiebreak
HEAD 5ad3ebd21ee7d17d4afbda54de5b2cc0a261dbb2
branch refs/heads/prd1/restart-tie-break

worktree /opt/vox/.claude/worktrees/prd1-tunnel-honesty
HEAD a6079c6039bc488c970fe573d98e735c410d62f0
branch refs/heads/wip/180-busy-room-gate

worktree /opt/vox/.claude/worktrees/prd1-v030
HEAD c64c3e32b52321dcff5c42a0579e90db51af6394
branch refs/heads/prd1/v030

worktree /opt/vox/.claude/worktrees/prd1-v6board
HEAD 48aaa3cfb57639869ab319515428607d3321e550
branch refs/heads/fix/197-v6-board

worktree /opt/vox/.claude/worktrees/pre40
HEAD aef2a9efe9bac23cf4dabb753df90b139fec6d7e
detached

worktree /opt/vox/.claude/worktrees/r15r17
HEAD 2342585800de6a3502c3dc5241307a816dd44fba
branch refs/heads/feat/prd1-r15-r17

worktree /opt/vox/.claude/worktrees/r41fix
HEAD 671076646aa4ce2d5dccbd91afba2b2c37f375e1
detached

worktree /opt/vox/.claude/worktrees/rejectreason
HEAD bad12185a385e1a03ef390f6527e4fd922a27910
branch refs/heads/fix/say-which-check-refused

worktree /opt/vox/.claude/worktrees/relaycarry
HEAD aef2a9efe9bac23cf4dabb753df90b139fec6d7e
branch refs/heads/fix/v210-relay-carryover

worktree /opt/vox/.claude/worktrees/relayed-restart
HEAD 9ff315d0a413d2049087bca7a44d28fd5ef3341a
branch refs/heads/test/relayed-restart-reached-again

worktree /opt/vox/.claude/worktrees/sock-len
HEAD 1c3b84c7bbc99996d04408a7d55a4daa74a4f965
branch refs/heads/worktree-sock-len

worktree /opt/vox/.claude/worktrees/trackplan
HEAD 7447dd2fcd0529b86c0c81aa4b73c920b005302e
detached

worktree /opt/vox/.claude/worktrees/updatefix
HEAD adbeca2407d63a430063c9780195a84408a63973
branch refs/heads/fix/update-works-on-linux

worktree /opt/vox/.claude/worktrees/v-F2
HEAD 0f45bb407b7ce3bfb405e8604ed4f306839e12a8
detached

worktree /opt/vox/.claude/worktrees/v0210
HEAD 82905606992ce7d7118fcd4a66388f5fe7ceb807
branch refs/heads/integrate/v0.2.10

worktree /opt/vox/.claude/worktrees/v0210-41
HEAD b6545e5e2af9fb885ee7c6c9185b5f8fe6dd709b
branch refs/heads/fix/push-retry-v0210

worktree /opt/vox/.claude/worktrees/v0210-w
HEAD 0ce67e42e174f15adb500ffa6dd0084cc1d68d54
detached

worktree /opt/vox/.claude/worktrees/v028-base
HEAD 56db6b1ac3774bdd938a819be6dba2040fc9fe6e
detached

worktree /opt/vox/.claude/worktrees/v030-patch
HEAD 6e38b3c225274c7ce3df030526f6a279d66d1ae4
detached

worktree /opt/vox/.claude/worktrees/v202
HEAD 843610005df17ecac6d3d803adeed12491f21654
detached

worktree /opt/vox/.claude/worktrees/v202-base
HEAD 1aab21aff126c4a8296555b44b0b5b794259762b
detached

worktree /opt/vox/.claude/worktrees/v210-160-164
HEAD e1ee944db4dd618acb2eafa8b58c307012eca418
branch refs/heads/wip/160-join-cut-short

worktree /opt/vox/.claude/worktrees/v21016
HEAD 44efad8bc2910d7897251d24358896069cbaa816
branch refs/heads/fix/v210-16-page-rooms-trusted

worktree /opt/vox/.claude/worktrees/v21026
HEAD 5627103f94872187bcb97cb40f2f13468e810be6
branch refs/heads/fix/v210-26-verify-off-actor

worktree /opt/vox/.claude/worktrees/v21027
HEAD 97d4a720237a0e936d240039ba96b87c05db3598
branch refs/heads/test/v210-27-simultaneous-session-race

worktree /opt/vox/.claude/worktrees/v21028
HEAD 3a6ac6d1b89313e476906655631e9a6170af3b31
branch refs/heads/fix/v210-28-watchdog-kills-children

worktree /opt/vox/.claude/worktrees/v21030
HEAD 97d4a720237a0e936d240039ba96b87c05db3598
branch refs/heads/fix/v210-30-consent-key-at-trust

worktree /opt/vox/.claude/worktrees/v2914-cand
HEAD e4ba09a879b59e0d35a9b1643f5b5e06a6ab6013
branch refs/heads/ci/v29-14-unskip-relayed-retry

worktree /opt/vox/.claude/worktrees/v2915
HEAD 7fec4a8939d87b7018ce8db9ce9484c266cd00b4
branch refs/heads/fix/v29-15-duplicate-tiebreak

worktree /opt/vox/.claude/worktrees/v40-C
HEAD 3d7ab3f5d7de744c9f58c82c62de96b290cef9ee
detached

worktree /opt/vox/.claude/worktrees/v41ctl
HEAD b112991e284edd6d59b29bad19f62af287f5d7f8
detached

worktree /opt/vox/.claude/worktrees/v41fix
HEAD 40097b764d977a82bf8ee01f0a908ca60efa9b33
detached

worktree /opt/vox/.claude/worktrees/v42
HEAD aef2a9efe9bac23cf4dabb753df90b139fec6d7e
detached

worktree /opt/vox/.claude/worktrees/v49
HEAD 0583154fa1b498aba8ea1115f5247ed193b5be39
detached

worktree /opt/vox/.claude/worktrees/v49-m
HEAD 0583154fa1b498aba8ea1115f5247ed193b5be39
detached

worktree /opt/vox/.claude/worktrees/v51
HEAD aaa72cf0cc7b705ae5c8a35471cd367aca4bc6a7
detached

worktree /opt/vox/.claude/worktrees/v51-m
HEAD aaa72cf0cc7b705ae5c8a35471cd367aca4bc6a7
detached

worktree /opt/vox/.claude/worktrees/verify29
HEAD e7f6a4f33da78ddb8b80317293505685f9bcee9e
detached

worktree /opt/vox/.claude/worktrees/verify40
HEAD 3d7ab3f5d7de744c9f58c82c62de96b290cef9ee
detached

worktree /opt/vox/.claude/worktrees/verify41
HEAD dc64e306072c1e0dbcccf0263cc8f9ce317f17cc
detached

worktree /opt/vox/.claude/worktrees/verify41i
HEAD 1c8fd030e7dc33cec37a23da4e1ac9189196ba74
detached

worktree /opt/vox/.claude/worktrees/verify41m
HEAD c9610787e8ec72d944676f84cb60f69137f3b333
detached

worktree /opt/vox/.claude/worktrees/verify41p
HEAD 1c8fd030e7dc33cec37a23da4e1ac9189196ba74
detached

worktree /opt/vox/.claude/worktrees/verify41r
HEAD 7cd01d99781b899a15bb8dc60e17496bc10066db
detached

worktree /opt/vox/.claude/worktrees/vox-absorb
HEAD fbd4890f37413d41dd46171eaae66b8e3c11b56f
branch refs/heads/fix/staged-apply-absorbs-before-failing

worktree /opt/vox/.claude/worktrees/vox-bbr
HEAD 1b5efd9acc323b83a3ddb6f7ded04fde94383dec
detached

worktree /opt/vox/.claude/worktrees/vox-bisect
HEAD c9f286afa9d893b165bf44168580b9d492dcb566
detached

worktree /opt/vox/.claude/worktrees/vox-bisect2
HEAD d69fd2e32f63f22729d80aa60690f79e478bf965
detached

worktree /opt/vox/.claude/worktrees/vox-cand
HEAD fa44a546a8d338f1a9b9bc9594e6bea5cef485af
detached

worktree /opt/vox/.claude/worktrees/vox-comb
HEAD a19e22802edb6b7d26f20c6b29eeab6589eba385
detached

worktree /opt/vox/.claude/worktrees/vox-ctl
HEAD 9c01ff404a51323d71a28a5b982721658635fc8d
detached

worktree /opt/vox/.claude/worktrees/vox-d5
HEAD ce4a55f239f65fe279a4c44e00012d666d5c6a3f
branch refs/heads/fix/push-only-to-this-rooms-anchors

worktree /opt/vox/.claude/worktrees/vox-doc2
HEAD 285dc76b77b1e1d4279a8ae0ab0f0f6271c9328d
branch refs/heads/fix/rustdoc-private-links-2

worktree /opt/vox/.claude/worktrees/vox-doc3
HEAD 6f59d8c5a39d89b8421cebd89abdd532461685bc
branch refs/heads/fix/rustdoc-private-links-3

worktree /opt/vox/.claude/worktrees/vox-docfix
HEAD 0046b24958bb62f540acc12bf6e5af8a217f62f2
branch refs/heads/fix/rustdoc-private-links

worktree /opt/vox/.claude/worktrees/vox-final
HEAD eedfffd43ec840413907b31da99d077e2901a32b
detached

worktree /opt/vox/.claude/worktrees/vox-int029
HEAD e7f6a4f33da78ddb8b80317293505685f9bcee9e
detached

worktree /opt/vox/.claude/worktrees/vox-joinerkey
HEAD 73ff7cfd72ff4738f2fdebfb3f553f37c9e4368d
branch refs/heads/fix/joiner-releases-its-key-at-admission

worktree /opt/vox/.claude/worktrees/vox-lockstep
HEAD 3f95b5767deb14a4de602c96dbf479ea2dd8b5dc
branch refs/heads/fix/sync-lock-per-step

worktree /opt/vox/.claude/worktrees/vox-lockstep-chk
HEAD 4c612a763b38dfdd428eac9c7fbfb4c0cbd2019e
detached

worktree /opt/vox/.claude/worktrees/vox-main-chk
HEAD 3cac220a1d7d1230fe1b6fa730ae5bc73fc177a6
detached

worktree /opt/vox/.claude/worktrees/vox-noqA
HEAD cf659849c971fbe9f19aac2ace7900b3b1111ca3
detached

worktree /opt/vox/.claude/worktrees/vox-noqB
HEAD 84578cc7b30083a55fc25ce0f2a07b5aac1a3caa
detached

worktree /opt/vox/.claude/worktrees/vox-noqC
HEAD d3b35dbea8a304cda0b6b975ff856bcced609185
detached

worktree /opt/vox/.claude/worktrees/vox-owed-peer
HEAD 3d28ecbcecb43a2a26e050a650b73cd77eaba3b9
branch refs/heads/fix/owed-push-per-peer

worktree /opt/vox/.claude/worktrees/vox-pub-bound
HEAD 0f39449e8f0b29880d549bbd4b2553aa6c4cf85b
branch refs/heads/fix/anchor-publish-off-actor

worktree /opt/vox/.claude/worktrees/vox-r40-a
HEAD 1c8fd030e7dc33cec37a23da4e1ac9189196ba74
detached

worktree /opt/vox/.claude/worktrees/vox-r40-b
HEAD 466f42518c8533523fd829f8de14649b89dddcc2
detached

worktree /opt/vox/.claude/worktrees/vox-r41
HEAD c5581d334759719f37a6bea20f560de643edd457
branch refs/heads/test/r41-over-an-emulated-link

worktree /opt/vox/.claude/worktrees/vox-release
HEAD fe6131ff19ca8e3458b613f2d7cc24ca521c1c66
detached

worktree /opt/vox/.claude/worktrees/vox-reply-view
HEAD b4a3585b3987b9bd0dd801bcb8ef3e7ea798909d
branch refs/heads/fix/reply-after-the-view

worktree /opt/vox/.claude/worktrees/vox-responder
HEAD 3a5bd0ce03aee68aa25a18993d68adde546c5007
branch refs/heads/fix/joiner-accepts-its-responders-key

worktree /opt/vox/.claude/worktrees/vox-retry
HEAD 40097b764d977a82bf8ee01f0a908ca60efa9b33
branch refs/heads/fix/push-retry-desynchronised

worktree /opt/vox/.claude/worktrees/vox-ryw
HEAD 0f45bb407b7ce3bfb405e8604ed4f306839e12a8
branch refs/heads/fix/view-reads-its-own-writes

worktree /opt/vox/.claude/worktrees/vox-ryw-base
HEAD 59b9c80988d8b98e60854f9d90c8eb592dd41d91
detached

worktree /opt/vox/.claude/worktrees/vox-seq
HEAD bb35c6dbe0c716434dfcbb39359eb2efbad5a22b
branch refs/heads/fix/record-seq-survives-restart

worktree /opt/vox/.claude/worktrees/vox-splice
HEAD 8f2ff2ea119623ef61dcb7f1d6e7535e2d7beeb2
detached

worktree /opt/vox/.claude/worktrees/vox-tput
HEAD 472dc14ca2ad87b9965bff50498745b48f21dd7f
detached

worktree /opt/vox/.claude/worktrees/vox-trust-bound
HEAD a60e1862d81f5ced0b68c854f663643d113e1a34
branch refs/heads/fix/rekey-does-not-dial-on-the-actor

worktree /opt/vox/.claude/worktrees/vox-v2919
HEAD 30e53e96f46f03c3e3d911a5d68d9df20923d3e5
branch refs/heads/fix/consent-fetches-the-bundle

worktree /opt/vox/.claude/worktrees/vox-wan
HEAD b28eccfadbc2c05a564619521afea75802629217
detached

worktree /opt/vox/.claude/worktrees/vox-want
HEAD 61f790ed8b026321867bdff91d072e791616b282
branch refs/heads/test/want-proof-counts-distinct

worktree /opt/vox/.claude/worktrees/vret2
HEAD bab1a22c0aa3394f47dff6f5c55735c78328ab54
detached

worktree /opt/vox/.claude/worktrees/vshipped
HEAD d9b136cb0b33a3c63d7e78e9d4a2d14359742761
detached

worktree /opt/vox/.claude/worktrees/vshipped-mut
HEAD d9b136cb0b33a3c63d7e78e9d4a2d14359742761
detached

worktree /opt/vox/.claude/worktrees/vshipped-mut2
HEAD d9b136cb0b33a3c63d7e78e9d4a2d14359742761
detached

worktree /opt/vox/.claude/worktrees/w180
HEAD 58fde3650bf17cef8ad212b175116a0dcdc2cce8
branch refs/heads/fix/180-no-defer

worktree /opt/vox/.claude/worktrees/w197-base
HEAD 0583154fa1b498aba8ea1115f5247ed193b5be39
detached

worktree /opt/vox/.claude/worktrees/w198
HEAD 885d2f57f5debf0adf41d025fd70c936d56ce472
branch refs/heads/fix/198-author-names

worktree /opt/vox/.claude/worktrees/w41
HEAD b6545e5e2af9fb885ee7c6c9185b5f8fe6dd709b
branch refs/heads/test/41-collision-gate

worktree /opt/vox/.claude/worktrees/w41-base
HEAD 91da36eced54f0b47235ca85aeb85d730372f17d
detached

worktree /opt/vox/.claude/worktrees/wedge-gate
HEAD 6472291e167fc22afa75976ec203135a9eb26809
branch refs/heads/sec/wedge-gate

worktree /opt/vox/.claude/worktrees/wtm
HEAD 3bb6ca11617d2c8de0bb36d4d5b7cabaa49c09fa
branch refs/heads/test/two-member-collisions

worktree /private/tmp/claude-502/-opt-vox/00beb60a-7ba2-4515-a4d8-89e528d87598/scratchpad/wt/int28
HEAD b1818e84c712bcc33261bf5d04d8b5f72187e276
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/AB
HEAD 0acd1239b2a2915c06456fcf2b13637477f741e7
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/BASE
HEAD 0590cdcfe85b2e64acaa261b474583b7d70c3d48
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/BD
HEAD 17ea6ba31b782ed9cb09ebcb7df1088c901c2e12
branch refs/heads/fix/publish-bounded

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/BISECT
HEAD f3f8a94e516cf77f2f96be382748c126460e441e
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/HD-hold
HEAD c2c7e503c26df033f3c1386e7cdac175cdbb1cef
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/HD-nohold
HEAD 225dc63c4076169caf4d8df2987d34a6e6385a4c
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I28
HEAD f5c22f968d16a3b06b6b5204b4b9f8fe26081dd9
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I28B
HEAD 90e550cc658b0aa9ea40dfcc16621728eab60aa4
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I28C
HEAD 2a94681d9d825f4120effdacac338dc8d3af5916
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I28D
HEAD b4b5e27c24ddadff84ad1394827c8029c57eeaa6
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I29
HEAD 4917a2b0b2d30a6efa9ce577a9c5a1ea21fc81c0
branch refs/heads/fix/room-create-and-join-off-actor

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I29B
HEAD 113317c3491ec347dd127b6f6e050f1a8d8c59dd
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/I29D
HEAD 4ccc0f177c506265b71703eb5822f4547ad8d896
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/INT
HEAD dce2ea2aebf90b88cce2f0e3ebf20d126cb47e0a
branch refs/heads/fix/flaky-watch-cannot-kill-a-release

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/LKA
HEAD 96a37d770bc9dbae034be3da9e7f031c0049e4cd
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/LKA2
HEAD 73ed51d21aa8d20f60a1a0e25b001cae134deb10
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/LKB
HEAD e26ee1b5f38846dc951bd2f5b00d32cf4e5804e6
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/LKB2
HEAD 1c8fd030e7dc33cec37a23da4e1ac9189196ba74
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/M14D
HEAD 0844943036bc474fcf8fc56aae12dd3de1a1d1dc
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/MS
HEAD 2d8f7d08bb2660c46c10a2aa04d08c12a694c78f
branch refs/heads/m19.9/millisecond-claim-ordering

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/MUT
HEAD 2d8f7d08bb2660c46c10a2aa04d08c12a694c78f
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/NOW
HEAD 3f1cb7dbb47a71090e18fdae1acc1cfb714d9601
branch refs/heads/fix/join-slots-and-board-growth

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/OB
HEAD 0bd7a152a2582a684e68d4ca740fbde44fa3d204
branch refs/heads/fix/sync-push-only-to-members

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/OBB
HEAD 3d4de162053986122b9184020c8ed3cd731ff480
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/PA
HEAD dc64e306072c1e0dbcccf0263cc8f9ce317f17cc
branch refs/heads/fix/push-on-append-v2

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/PB
HEAD 95bd300c29c93dc5eb8f0e64cec0d3be29fb9856
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/PW
HEAD c1fc7d63ba90461f8b2e0e8c4ff9a686159b0cd7
branch refs/heads/fix/publish-waits-for-no-session

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/R26
HEAD 55272b0ec4089ef867fbe1e18b4b4dcaf562fd62
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/R6
HEAD f711e0ef3e47e868dfd65c1a1c71fc87558ee19b
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/REL
HEAD eee200d1be67c75812f4c541b1fed5271c2dfced
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/RF
HEAD 1002a3f0d3315dcc130f7e5572b7301d2ea10755
branch refs/heads/fix/sync-refuses-a-room-it-does-not-hold

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/SC
HEAD 9f0b73dc805d177a15d884f3b27216a6d3525b6a
branch refs/heads/fix/serve-streams-concurrently

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/SD
HEAD 2afa020b8d16877abfb5770b628509ac8d233d48
branch refs/heads/fix/stream-open-deadline

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/SG
HEAD 9e4ebd43c9444f10de9b6377fde5358a44418adc
branch refs/heads/fix/shutdown-done-means-gone

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/SGB
HEAD 3cac220a1d7d1230fe1b6fa730ae5bc73fc177a6
detached

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/SP
HEAD 0844943036bc474fcf8fc56aae12dd3de1a1d1dc
branch refs/heads/fix/sync-mark-per-peer

worktree /private/tmp/claude-502/-opt-vox/ba4ae1d2-949e-4d74-8814-230a10d77b29/scratchpad/wt/V29
HEAD 1c8fd030e7dc33cec37a23da4e1ac9189196ba74
branch refs/heads/integrate/v0.2.9

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/baseline
HEAD 0844943036bc474fcf8fc56aae12dd3de1a1d1dc
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/d2
HEAD 5eab862e4e23e016377cb422db3da12e4ba1762a
branch refs/heads/prd1/d2-want-bounds

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/d2before
HEAD 3cac220a1d7d1230fe1b6fa730ae5bc73fc177a6
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/d5
HEAD 3d4de162053986122b9184020c8ed3cd731ff480
branch refs/heads/prd1/d5-sync-membership

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/hg
HEAD 1491a29ea883c56c2029d3b25bd8f75efd433fc6
branch refs/heads/prd1/history-grants

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/hgbase
HEAD 7296b6bb4fcf452a72e19364b205ca18783bb5fc
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/irf
HEAD e2a74b923dbf4582446570346746ead9ca75cb02
branch refs/heads/prd1/integrate-retention-fix

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/kd
HEAD d9b136cb0b33a3c63d7e78e9d4a2d14359742761
branch refs/heads/fix/key-delivery

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/pa
HEAD 8ba8dd00961fa004e3a4837a39c920eef741a31f
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/pam
HEAD 49cd999f17f320bc203a5ba7f3872cceedd4086c
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/perf
HEAD 733b34631faf25387b3c200a9f190138c73903ba
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/r3
HEAD 85fb55e82e645f25343f85c80f1574d396a8641c
branch refs/heads/prd1/retention

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/rg
HEAD bab1a22c0aa3394f47dff6f5c55735c78328ab54
branch refs/heads/prd1/retention-gates

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/prd1/v028
HEAD 3cac220a1d7d1230fe1b6fa730ae5bc73fc177a6
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/rbase
HEAD 9ff315d0a413d2049087bca7a44d28fd5ef3341a
detached

worktree /private/tmp/claude-502/-opt-vox/f394c7ba-70fe-42a4-9310-ea620e498c37/scratchpad/wt/RES
HEAD 96c47edebea342da18a76875290067f1180b17e4
detached
[0m
[0m$ [0mgh issue list --repo robertelee78/vox --state all --search '"V210-31"' --json number,title,body --limit 10
[]
[0m
[0m✱ [0mGrep "impl.*Transport for QuicStreamTransport|SYNC_FRAME_TIMEOUT|fn finish\(&mut self\)"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport · 7 matches[0m
[0m✱ [0mGrep "room_in_session|in_session_with|NetEvent::SyncDone|answer_pending_consents|Not deferred|Not.*deferred|sync_slots"[90m in /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node · 24 matches[0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/w180 diff -- crates/vox-core/src/node/actor.rs
(no output)
[0m
[0m✱ [0mGrep "restart|held|probe|existing.*close|\.close\("[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node · 0 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=202, limit=35][0m
[0m✱ [0mGrep "SILENCE_IS_DEATH|held.connection|held connection|restart.probe"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src · 21 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs
[0m→ [0mRead /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node/actor.rs[90m [offset=3360, limit=32][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node/actor.rs[90m [offset=4328, limit=105][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node/actor.rs[90m [offset=5145, limit=60][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node/actor.rs[90m [offset=2937, limit=25][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs[90m [offset=727, limit=145][0m
[0m→ [0mRead /Users/robert.lee/.claude/skills/github-work-accountability/references/adr-sources.md[90m [limit=160][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node/actor.rs[90m [offset=4900, limit=135][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/w180/crates/vox-core/src/node/actor.rs[90m [offset=4683, limit=48][0m
[0m
[0m$ [0mgit show 8c4e347:docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
(no output)
[0m
**BLOCK.** D3 assumes a delivery acknowledgement the protocol does not provide; D4’s state machine cannot represent its own overlapping sessions safely.

Reviewed the specified commits and both #180 changes. No files changed; no builds or tests run. Below, code paths are relative to `crates/vox-core/src/` at `8436100`; **`180:`** denotes `58fde36`. **ADR** denotes `docs/adr/ADR-025-sync-scheduling-switch-not-hub.md`.

## BLOCKER

### 1. D3 cannot establish “delivered through `gen_at_have`”

There are three separate problems:

- **Truncation looks successful.** `entries_for_wants` returns a bounded vector without indicating whether entries remain. The session also breaks on `SERVE_BUDGET`, sends FIN, and can return `Ok(applied)`. The limits are 1,024 entries, 64 MiB, and 30 seconds. Neither `SessionRoom::entries` nor `SyncOutcome` exposes completeness.  
  (`log/sync.rs:82–95,491–513,835,886–916`; `node/channel.rs:212–219`.)
- **Local completion does not establish remote application.** Each endpoint finishes sending **before** draining and applying incoming entries. Alice can receive Bob’s FIN and finish successfully while Bob has not yet applied Alice’s entries. Bob can subsequently reject them or fail persistence. There is no post-apply acknowledgement for Alice to await; QUIC `finish()` merely finishes the send stream.  
  (`log/sync.rs:886–916`; `node/channel.rs:2694–2720`; `transport/stream_transport.rs:128–136`.)
- **Failure does not mean nothing arrived.** Applying a batch can store and persist a prefix before returning an error. The returned error loses the successful outcome information, and actor-side forwarding currently runs only for `Ok(o)` with `o.applied > 0`. D2 must therefore wake other ports for successful stores even when their containing session fails.  
  (`node/channel.rs:2701–2715,2117–2127`; `node/actor.rs:3471–3495`.)

Thus the answers are **yes**: one endpoint can report completion while the other truncated its serving, or before the other rejects received entries. This applies equally to either initiator direction.

**HAVE/WANT snapshot question:** the current code uses the actual received HAVE to calculate WANT; it does not accidentally substitute another HAVE. WANT uses a *later local DAG snapshot*, which is normally safe for monotonic append-only feeds: entries acquired meanwhile need not be requested again. (`log/sync.rs:880–887`; `node/channel.rs:2671–2691`.) However, the proposed generation must be captured **atomically with the advertised frontiers**, under the same lock and epoch. Reading the generation afterward can credit an append absent from the transmitted HAVE.

**Required change:** define acknowledged, persisted coverage and explicit partial-progress outcomes. A local `SyncOutcome` extension alone cannot prove remote acceptance. The “no wire change” constraint conflicts with D3’s present delivery guarantee (ADR:173–174,201–212). Also qualify “everything held”: frontier reconciliation implements tail extension and limited fork-head exchange, not arbitrary set equality (`log/sync.rs:438–475`).

### 2. D4 lacks session identity and has destructive completion races

`Running { dir, gen_at_have } | Awaiting` cannot represent “accepted keeper still running, refused outbound completion still pending.”

The relevant existing mechanics are concrete:

- #180 inserts one `(room, peer)` marker when accepting a session and removes that marker on **any** matching `SyncDone`. There is no attempt identifier.  
  (`180:node/actor.rs:5165–5195,3373–3380`.)
- Outbound and inbound tasks independently emit `SyncDone`.  
  (`node/actor.rs:5100–5106,5156–5162`.)
- `owed_a_reason` depends on the running-partner bookkeeping; #202’s current map has only one peer per room. This also needs reconciliation with #180 and D4.  
  (`node/actor.rs:1732–1738,5306–5312`.)

The missing interleavings are:

| Interleaving | Consequence for the proposal |
|---|---|
| Bob receives refusal **before** Alice’s keeper arrives | `Awaiting` is appropriate; keeper arrival must replace it and invalidate its timer. |
| Keeper arrives **before** Bob receives refusal | Bob must remain `Running{In}`. Applying D4’s stated “refusal → Awaiting” overwrites live ownership. |
| Keeper completes **before** the refused outbound’s `SyncDone` arrives | The stale refusal must not resurrect `Awaiting`, clear a newer attempt, or regress delivery coverage. |
| Keeper fails midway | Its failure must control retry; the losing outbound’s later result must not override it. |
| Bob’s old outbound arrives after Alice locally completed | Alice accepts it under the table’s final row—even if Bob never posted after HAVE. It was already in flight, not opened by D3’s follow-up decision. |
| Peer restarts under the same identity | “A second inbound is impossible” is false: the new process has no old port state. Old-session completion can race with replacement admission. |

The late-arrival case also invalidates the assertion that both sessions cannot complete: Alice’s local completion can precede Bob’s application/completion of the keeper, permitting overlap with the delayed second session. The protocol’s asymmetric completion ordering permits this (`log/sync.rs:893–916`).

For **one fresh outbound at each endpoint**, the identity rule prevents mutual glare refusal, and only Bob should enter `Awaiting`; I found no basis to claim both must await in that restricted case. That is substantially weaker than the ADR’s universal claims.

**Required change:** specify connection incarnation and session/attempt tokens, keeper and loser ownership, stale-event rejection, timer cancellation, and all state transitions. An expected loser completion must not alter the keeper’s state or consume unrelated consent retries; current `SyncDone` also retries pending consents by room (`180:node/actor.rs:3378–3380,4362–4393`).

### 3. Content generation alone cannot encode every trigger

D1 defines dirty as `room.gen > done_gen`, but D2/D7 say connect, manual sync, and periodic anti-entropy can make an unchanged room dirty merely by reading its generation (ADR:190–198,276–280). They cannot.

A clean port still needs reconciliation when the peer has news, loses state, reconnects, or when a previous delivery assumption was wrong. Membership/board changes also need work without necessarily adding a log entry: #180’s `note_new_members` explicitly triggers a push after learning new board authors (`180:node/actor.rs:4691–4719`).

Keep an independent **reconciliation-request generation or pending flag**, alongside content coverage. Define initialization and reset on restart/epoch change. Otherwise even the claimed periodic safety net can be a no-op. The current schedule treats connect and periodic reconciliation independently of append state (`node/syncstream.rs:79–112`).

## MAJOR

### 4. `AWAIT_KEEPER` needs a narrower meaning; two seconds is unsupported

A watchdog is needed when Bob receives `SessionBusy` but no keeper ever arrives. Without one, no keeper task exists locally to produce a completion event.

But the proposed deadline waits for **completion**, not arrival. A healthy keeper may already be running after two seconds. Existing transport waits allow 20 seconds per frame, and serving/draining have 30-second budgets; these establish no justification for a two-second completion deadline (`transport/stream_transport.rs:20–29,88–115`; `log/sync.rs:73,95,886–901`).

Specify:

- An **arrival deadline**, measured from processing the matching refusal, only while no keeper has been accepted.
- Separate active-session progress/absolute deadlines once accepted.
- No retry concurrent with a still-owned keeper.
- No indefinite deadline extension from duplicate refusals.
- Timeout means **eligible for scheduling**, not guaranteed delivery within two seconds.

Restart recovery already probes and closes dead held connections, but that does not eliminate stale actor-event races (`node/net.rs:756–795,810–828`).

Anchors need the same rules. They execute the same reconciliation and application machinery (`node/anchor.rs:328–359,426–465`). Use the authenticated network identity for ordering, not a mechanical copy of the pairwise caller’s profile lookup (`node/actor.rs:5379–5382`; compare the network identity comparison at `3447`). “Delivered” for an anchor must mean persisted ciphertext, not rendered text (`node/channel.rs:213–218,223–231`).

### 5. The proof plan does not establish its advertised properties

These are design assessments, not executed mutation results.

| Proof | Review |
|---|---|
| **P1** | The **accept-both mutant can pass every stated assertion**: timely delivery, no failure reports, no random retries. Printing session counts does not assert one session. Conversely, suppressing `SyncFailed` can satisfy the report assertion while collisions remain. Require an observed glare episode and asserted, correlated session outcomes. |
| **P2** | Three-way delivery can bypass a broken pair through another member or the anchor. Also, recording the generation at start rather than HAVE ordinarily records an **older** generation: that causes redundant work, not necessarily missed delivery. The named mutant is insufficiently defined. |
| **P3** | Potentially useful, but “24 simultaneous posts” does not prove 16 slots were occupied when another eligible pair was skipped. Require observable saturation and queued work, and prevent alternate replication paths from masking the skipped pair. |
| **P4** | **Unsound.** Delivery to a third member/anchor can proceed independently of the blocked Alice–Bob port. It can pass with no `Awaiting` deadline. Stopping Alice “right after” a post also does not establish that Bob observed the losing refusal. Test that exact port, establish the refused/no-keeper condition, restore reachability, and observe timer-caused recovery. |
| **P5** | Needs an observable HAVE boundary and a deliberately ordered later store; aggregate counters cannot establish that ordering. The base already retains append work while a session runs, so base-red is not established merely by describing this scenario (`node/actor.rs:4717–4727,4850–4852,4940–4943,3463–3465`). |
| **P6** | Contradicts D4: D4 explicitly sends one `SessionBusy` for ordinary glare; P6 demands **zero refusals** (ADR:222–228,315). |

The existing #202 harness synchronizes CLI invocation, not HAVE or stream admission; it ignores round-post results and checks reports rather than delivery (`crates/vox-tui/tests/a_sync_failure_names_its_reason_proof.rs:192–247`). Its counts therefore do not establish that every collision resolved, as ADR:42–43 claims.

The 250 ms p100 bounds need an explicit environment and timing origin. A shared timing lock does not enforce phase ordering or bound external CPU/network delays. These bounds are not intrinsically invalid, but the proposed harness does not make them reliable causal proofs.

**Missing decisive binary proofs:** asymmetric truncation beyond each serve limit; rejection/persistence failure after peer FIN; partial application followed by forwarding; all keeper/loser completion orders; same-identity restart; delayed keeper arrival; reconciliation with unchanged local generation; and FIFO progress under sustained load. Retain a real-failure reporting proof after removing #202’s collision assertion.

### 6. D6 leaves admission capacity and fairness ambiguous

Today, the semaphore is acquired by outbound `sync_one`; inbound `start_session` does not acquire it (`node/actor.rs:5010–5020,5113–5163`). Therefore “16 session slots” is not currently a global inbound-plus-outbound limit.

If D6 makes it global, two endpoints can fill all slots with outbound sessions and leave no capacity for the inbound sessions needed to finish them. D4’s temporary overlap makes this especially relevant. Specify outbound-only capacity, reserved responder capacity, or explicit slot transfer/cancellation.

“FIFO by time it became dirty” also needs a requeue rule. A perpetually dirty port retaining its original timestamp must not repeatedly outrank later arrivals. Put continuing work at the tail after each bounded turn. Clarify that appends and periodic triggers do not bypass real-failure backoff.

## MINOR

### 7. Context claims: verdicts against the actual trees

| Claim | Verdict |
|---|---|
| **1. Glare and randomized retry** | **CONFIRMED**, when both outbound sessions remain marked running as the inbound requests arrive. Busy refusal and retry windows are implemented (`node/actor.rs:5226–5240,3430–3455`). Posting within one RTT alone does not guarantee that ordering. The measured totals were not independently reproduced. |
| **2. Skipped, not queued** | **CONFIRMED—and a real delivery-scheduling defect.** Slot failure returns `false`, but does not add that pair to `owed`; the peer schedule is nevertheless marked synced (`node/actor.rs:5010–5012,4910–4944`). |
| **3. Pushed means started** | **CONFIRMED**, but not sufficient evidence of the claimed lost-update defect: failures are re-owed, and appends during running sessions have a pending-work path (`node/actor.rs:4911–4917,3365–3375,4717–4727,4850–4852,4940–4943`). |
| **4. Six maps** | **CONFIRMED** as a description of distributed bookkeeping, not an exhaustive state inventory: #202 also introduces `syncing_with` (`node/actor.rs:1732–1738`; updates at `3365–3457,4785–4806,4910–4972`). |
| **5. #180 fixes room-wide guarding** | **CONFIRMED for #180; WRONG if read as the state of `8436100`.** The supplied base remains room-keyed; #180 changes the predicate to `(room, peer)` (`node/actor.rs:1732,5226`; `180:node/actor.rs:4724–4725`). ADR:7–8 does disclose the integration assumption. |

For claim 2, there is **no guaranteed prompt recovery**: retained `pending_push` can make `SyncDone` request another pass, but that pass finds no due peer after `note_synced`. A new append, inbound session, or another peer’s forwarding may rescue it; none is guaranteed. The next periodic eligibility is 30 seconds (`node/actor.rs:3463–3465,4785–4798,4920–4944`; `node/syncstream.rs:93–110`). #180 retains this hole (`180:node/actor.rs:4923–4957,5023–5024`).

### 8. D6 contains a false baseline claim; the release rationale overstates D3’s evidence

ADR:274 says anchor publishing, new-member handling, and consent retries retain `room_in_session` from #180. **The second #180 commit removes that mechanism.** Publishing and member discovery are no longer deferred; consent scheduling checks the target pair (`180:node/actor.rs:2944–2957,4691–4719,4341–4349`). Restore neither the removed helper nor its starvation behavior.

The blanket claim that per-event sessions avoid persistent-stream stale-state/dead-session defect classes is also overstated (ADR:152–153). The current source explicitly documents a prior permanent running-marker wedge, and its connection layer handles dead connections blocking replacements (`node/actor.rs:5060–5063`; `node/net.rs:727–744`).

**Release scope:**

- D6’s lost scheduling obligation is defensible as a v0.2.10 defect.
- D3 needs an actual failing delivery case; the stale “started, not delivered” comment alone does not establish one after the retry/pending fixes.
- D1/D2 are supporting refactoring only to the extent needed by demonstrated defects.
- D4/D5 are the performance/behavior change the ADR itself acknowledges, not automatically mandated by “fix every known defect.”
- D7 preserves existing anti-entropy intent, provided clean ports can actually be scheduled.

The document labels the design proposed; I found no wholesale claim that D1–D7 are already implemented. The baseline assertion above is nevertheless false.

## NIT

### 9. The alternatives discussion does not justify the chosen complexity

- **Accept-both:** the smallest candidate for removing collision-induced waits. It still needs attempt-aware bookkeeping and bounded duplicate admission; removing the refusal alone is insufficient. Per-step locking supports considering it (`node/channel.rs:2671–2720`), but does not prove the entire actor remains correct. Measure its extra work against D4’s overlap, timeout, and stale-event complexity.
- **Designated initiator plus “news” notification:** missing entirely. It removes symmetric session initiation, at the cost of reliable/coalesced notification, reconnect replay, and potentially an extra round trip. With no compatibility requirement, it deserves explicit comparison rather than exclusion by “no wire change.”
- **Persistent per-peer replication:** deferring multiplexing, flow control, and reconnect-state work is defensible for a defect release. Citing other projects’ bugs is not evidence that short-lived sessions avoid those failure classes.

D3 already anticipates extra empty follow-up sessions for entries received from the same peer (ADR:343–345). Consequently, “one session per collision” needs a precise accounting definition before it can justify rejecting accept-both.

*Accountability check: repository tracking is enabled; read-only searches found no matching ADR-025/V210-31 issue. The work-key mapping remains unresolved; tracker state was unchanged.*

## VERDICT

**BLOCK**

The three changes I would insist on:

1. **Replace D3’s assumed delivery with an explicit, persisted coverage acknowledgement**, including truncation, partial failure, and atomic HAVE/generation capture.
2. **Specify the complete port lifecycle**, including independent reconciliation requests, session/incarnation tokens, keeper/loser event ordering, deadlines, restart handling, and slot admission.
3. **Rewrite the binary proofs around observable causal events and isolated paths**, fixing P1’s surviving mutant, P4’s unrelated recipient, P6’s contradictory refusal assertion, and the unestablished base-red claims.
