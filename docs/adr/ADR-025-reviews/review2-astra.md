[0m
> build · gpt-6-astra
[0m
[0m⚙ [0mak_skill_search {"query":"github-work-accountability","limit":1}
[0m→ [0mSkill "github-work-accountability"
[0m✱ [0mGlob "**/AGENTS.md"[90m 0 matches[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m→ [0mRead docs/adr/ADR-025-reviews/review-glm-5.3.md
[0m→ [0mRead docs/adr/ADR-025-reviews/review-astra.md
[0m→ [0mRead docs/adr/ADR-025-reviews/review-kimi-k3.md
[0m
[0m$ [0mawa status --json
{"host": "github.com", "managed": true, "managed_issue_count": 201, "repository": "robertelee78/vox", "schema": "agent-work-accountability/status-v1", "transport": "github-rest-search"}
[0m
[0m✱ [0mGrep "## BLOCKER|## MAJOR|## MINOR|## NIT|## VERDICT"[90m in docs/adr/ADR-025-reviews/review-astra.md · 15 matches[0m
[0m
[0m$ [0mgit rev-parse HEAD && git -C /opt/vox/.claude/worktrees/ac-fix202 rev-parse HEAD && git -C /opt/vox/.claude/worktrees/ac-fix202 diff --stat && git -C /opt/vox/.claude/worktrees/ac-fix202 diff 58fde36 8436100 -- crates/vox-core/src/log/sync.rs crates/vox-core/src/node/channel.rs crates/vox-core/src/node/net.rs crates/vox-core/src/node/anchor.rs crates/vox-core/src/node/syncstream.rs
16951fec193c6d2d2abd1b997e2c5a7f24358f07
843610005df17ecac6d3d803adeed12491f21654
diff --git a/crates/vox-core/src/log/sync.rs b/crates/vox-core/src/log/sync.rs
index 336dd0e..c251d8f 100644
--- a/crates/vox-core/src/log/sync.rs
+++ b/crates/vox-core/src/log/sync.rs
@@ -677,8 +677,8 @@ where
     R: AuthorResolver,
     P: FnMut(&mut TA, &mut TB) -> usize,
 {
-    let send_a = |t: &mut TA, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
-    let send_b = |t: &mut TB, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
+    let send_a = |t: &mut TA, f: Vec<u8>| t.send(&f).map_err(|e| wire_of(&e));
+    let send_b = |t: &mut TB, f: Vec<u8>| t.send(&f).map_err(|e| wire_of(&e));
 
     // 1. HELLO exchange + mode negotiation.
     send_a(ta, encode_hello(SYNC_MODE_FRONTIER))?;
@@ -769,7 +769,7 @@ where
     T: Transport,
     R: AuthorResolver,
 {
-    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
+    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|e| wire_of(&e));
 
     // 1. HELLO exchange + mode negotiation.
     send(t, encode_hello(SYNC_MODE_FRONTIER))?;
@@ -871,7 +871,7 @@ where
     T: Transport,
     S: SessionRoom + ?Sized,
 {
-    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
+    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|e| wire_of(&e));
 
     send(t, encode_hello(SYNC_MODE_FRONTIER))?;
     let remote_hello = expect_hello(t.recv())?;
@@ -896,7 +896,7 @@ where
     let deadline = std::time::Instant::now() + DRAIN_BUDGET;
     let mut staged: Vec<Vec<u8>> = Vec::new();
     let mut applied = 0;
-    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
+    while let Some(frame) = t.recv().map_err(|e| wire_of(&e))? {
         if std::time::Instant::now() >= deadline {
             return Err(WireError::SyncModeUnsupported);
         }
@@ -964,7 +964,7 @@ fn drain_entries<T: Transport, R: AuthorResolver>(
     // circuit on total idle. A per-frame bound alone only defends against a peer that stops, never
     // against one that drips.
     let deadline = std::time::Instant::now() + DRAIN_BUDGET;
-    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
+    while let Some(frame) = t.recv().map_err(|e| wire_of(&e))? {
         if std::time::Instant::now() >= deadline {
             return Err(WireError::SyncModeUnsupported);
         }
@@ -988,8 +988,17 @@ fn drain_entries<T: Transport, R: AuthorResolver>(
     Ok(applied)
 }
 
+/// The coded reason a transport error carries: the peer's own reason when it refused the stream
+/// with one ([`Error::PeerRefused`]), and [`WireError::TransportFailed`] for everything else
+/// (#202). Reporting every refusal as `TransportFailed` hid a collision behind a dead path.
+fn wire_of(e: &Error) -> WireError {
+    match e {
+        Error::PeerRefused(code) => *code,
+        _ => WireError::TransportFailed,
+    }
+}
 fn expect_hello(r: Result<Option<Vec<u8>>>) -> std::result::Result<u8, WireError> {
-    match r.map_err(|_| WireError::TransportFailed)? {
+    match r.map_err(|e| wire_of(&e))? {
         Some(frame) => match decode_frame(&frame) {
             Ok(SyncFrame::Hello(bitmap)) => Ok(bitmap),
             _ => Err(WireError::SyncModeUnsupported),
@@ -1000,7 +1009,7 @@ fn expect_hello(r: Result<Option<Vec<u8>>>) -> std::result::Result<u8, WireError
 }
 
 fn expect_have(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<FeedFrontier>, WireError> {
-    match r.map_err(|_| WireError::TransportFailed)? {
+    match r.map_err(|e| wire_of(&e))? {
         Some(frame) => match decode_frame(&frame) {
             Ok(SyncFrame::Have(v)) => Ok(v),
             _ => Err(WireError::SyncModeUnsupported),
@@ -1010,7 +1019,7 @@ fn expect_have(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<FeedFronti
 }
 
 fn expect_want(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<WantRange>, WireError> {
-    match r.map_err(|_| WireError::TransportFailed)? {
+    match r.map_err(|e| wire_of(&e))? {
         Some(frame) => match decode_frame(&frame) {
             Ok(SyncFrame::Want(v)) => Ok(v),
             _ => Err(WireError::SyncModeUnsupported),
diff --git a/crates/vox-core/src/node/channel.rs b/crates/vox-core/src/node/channel.rs
index 1bac9c6..7ae5cbe 100644
--- a/crates/vox-core/src/node/channel.rs
+++ b/crates/vox-core/src/node/channel.rs
@@ -168,16 +168,8 @@ pub fn join_context_from_genesis(
 /// Map an ADR-008 coded sync failure onto the error taxonomy, keeping the reason
 /// (the ADR's rule is that a failure is never silently downgraded).
 pub(crate) fn sync_failure(code: crate::wire::WireError) -> Error {
-    Error::MalformedGovernance(match code {
-        crate::wire::WireError::ProtocolVersionUnsupported => "sync failed: protocol version",
-        crate::wire::WireError::SuiteBelowFloor => "sync failed: suite below floor",
-        crate::wire::WireError::UnknownStructTag => "sync failed: unknown struct tag",
-        crate::wire::WireError::UnknownAlgoId => "sync failed: unknown algo id",
-        crate::wire::WireError::AuthenticatorInvalid => "sync failed: authenticator invalid",
-        crate::wire::WireError::SyncModeUnsupported => "sync failed: sync mode unsupported",
-        crate::wire::WireError::EpochMismatch => "sync failed: epoch mismatch",
-        crate::wire::WireError::TransportFailed => "sync failed: transport",
-    })
+    // Its own variant, carrying the coded reason, never `MalformedGovernance` (#202).
+    Error::SyncFailed(code)
 }
 
 /// The channel's [`AuthorResolver`] for ADR-008 sync: the admitted authors' keys,
diff --git a/crates/vox-core/src/node/net.rs b/crates/vox-core/src/node/net.rs
index c06c931..75760d6 100644
--- a/crates/vox-core/src/node/net.rs
+++ b/crates/vox-core/src/node/net.rs
@@ -237,6 +237,12 @@ fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
 /// How a connection reaches its peer, in preference order (ADR-012: prefer direct).
 #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
 pub enum PathClass {
+    /// Set up over a relay circuit that this node **no longer has**: the mux detached it (a
+    /// second circuit to the same peer replaces the first) or its driver ended. Nothing this
+    /// node sends on it leaves the socket, so it is dead whatever it last heard, and it is never
+    /// kept over anything — least of all read as direct, which is what asking the mux's table
+    /// alone made of it (V29-15).
+    Severed,
     /// Through a relay circuit (rung 4): works anywhere, costs a third party.
     Relayed,
     /// Straight to the peer — dialled, or punched (rungs 1–3).
@@ -245,16 +251,24 @@ pub enum PathClass {
 
 /// The path a connection is on.
 ///
-/// Asked of the endpoint whose socket carries it, because a circuit's address is random:
-/// only the mux's table knows which addresses are circuits, and a guess from the address
-/// would be wrong in both directions — a real address can fall inside the subnet, and a
-/// circuit's address looks like nothing in particular.
+/// **Relayed or direct is the connection's own, fixed fact** ([`VoxConnection::via_circuit`]),
+/// recorded when it was made and identical at both ends. Only whether a relayed connection's
+/// circuit is *still attached* is asked of the endpoint's mux table — the only authority on
+/// which addresses are circuits, since a circuit's address is random and a guess from its shape
+/// would be wrong in both directions.
+///
+/// Asking the table for the whole answer was the defect (V29-15): a circuit detached by a second
+/// circuit to the same peer left its connection's address in nobody's table, so a relayed
+/// connection that could no longer send read as **direct**, beat the live circuit on "better
+/// path", and was kept by both ends.
 #[must_use]
 pub fn path_class(endpoint: &VoxEndpoint, conn: &VoxConnection) -> PathClass {
-    if endpoint.is_circuit(conn.quinn().remote_address()) {
+    if !conn.via_circuit() {
+        PathClass::Direct
+    } else if endpoint.is_circuit(conn.quinn().remote_address()) {
         PathClass::Relayed
     } else {
-        PathClass::Direct
+        PathClass::Severed
     }
 }
 
@@ -321,6 +335,54 @@ pub const RETIRE_GRACE_SECS: u64 = 60;
 /// before this rule; it cannot make a live connection look dead.
 pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);
 
+/// The one byte a liveness probe carries. Too short to be a framed datagram (which starts with an
+/// 8-byte sequence number), so the far end drops it unread; what matters is that the frame is
+/// ack-eliciting.
+const PROBE_BYTE: u8 = 0;
+
+/// How often a probe checks whether anything came back.
+const PROBE_POLL: Duration = Duration::from_millis(10);
+
+/// How long a probe waits for an answer: three round trips of the held connection's own RTT
+/// estimate — one for the probe and its ACK, the rest for an ACK delay and a loss — but never
+/// less than 250ms, where a loopback RTT of microseconds would make scheduling noise look like
+/// death, and never more than 2s, past which a newcomer is kept waiting for a path that is too
+/// slow to be the one worth keeping.
+fn probe_patience(rtt: Duration) -> Duration {
+    (rtt * 3).clamp(Duration::from_millis(250), Duration::from_secs(2))
+}
+
+/// Send one probe on `conn` and wait [`probe_patience`] for anything at all to arrive on it.
+///
+/// `None` is an answer, or a connection that cannot be probed (no datagram support) or that
+/// closed on its own meanwhile — none of which is evidence that a live peer is absent.
+/// `Some(before)` is no answer, with the received-datagram count the probe started from, so the
+/// verdict can be re-checked at the moment it is acted on (see [`ConnectionManager::file_inner`]).
+async fn probe_unanswered(conn: &VoxConnection) -> Option<u64> {
+    let quic = conn.quinn();
+    let before = quic.stats().udp_rx.datagrams;
+    if quic
+        .send_datagram(bytes::Bytes::from_static(&[PROBE_BYTE]))
+        .is_err()
+    {
+        return None;
+    }
+    let deadline = tokio::time::Instant::now() + probe_patience(quic.rtt());
+    loop {
+        if quic.stats().udp_rx.datagrams != before || !is_live(conn) {
+            return None;
+        }
+        if tokio::time::Instant::now() >= deadline {
+            return Some(before);
+        }
+        tokio::time::sleep(PROBE_POLL).await;
+    }
+}
+
+/// Connections a probe found unanswered, each with the received-datagram count its probe started
+/// from. Closed only inside [`ConnectionManager::file_inner`], under the connection lock.
+type Unanswered = Vec<(Arc<VoxConnection>, u64)>;
+
 /// One QUIC connection per peer fingerprint (see the module docs).
 pub struct ConnectionManager {
     endpoint: Arc<VoxEndpoint>,
@@ -392,7 +454,7 @@ impl ConnectionManager {
             lock(&self.conns).remove(peer);
             return self.promote_heard(peer);
         }
-        if self.is_silent(&conn) {
+        if self.is_dead(&conn) {
             return self.promote_heard(peer);
         }
         Some(conn)
@@ -418,6 +480,13 @@ impl ConnectionManager {
         self.silent_for(conn) > SILENCE_IS_DEATH
     }
 
+    /// Whether `conn` can no longer be used, though it may not be closed: silent past
+    /// [`SILENCE_IS_DEATH`], or relayed over a circuit this node no longer has
+    /// ([`PathClass::Severed`]), which can send nothing however recently it heard something.
+    fn is_dead(&self, conn: &VoxConnection) -> bool {
+        path_class(&self.endpoint, conn) == PathClass::Severed || self.is_silent(conn)
+    }
+
     /// Replace `peer`'s silent (or closed) primary with a retired connection to the same peer
     /// that is still being heard from, if there is one. The dead primary is closed: if anything
     /// is still behind it the close tells it which connection this end chose, and if nothing is
@@ -432,7 +501,7 @@ impl ConnectionManager {
     fn promote_heard(&self, peer: &Digest32) -> Option<Arc<VoxConnection>> {
         let mut map = lock(&self.conns);
         if let Some(held) = map.get(peer) {
-            if is_live(held) && !self.is_silent(held) {
+            if is_live(held) && !self.is_dead(held) {
                 return Some(Arc::clone(held)); // somebody else promoted it first
             }
         }
@@ -440,13 +509,13 @@ impl ConnectionManager {
         let best = retiring
             .iter()
             .enumerate()
-            .filter(|(_, (c, _))| c.peer_id() == *peer && is_live(c) && !self.is_silent(c))
+            .filter(|(_, (c, _))| c.peer_id() == *peer && is_live(c) && !self.is_dead(c))
             .min_by_key(|(_, (c, _))| tie_key(c))
             .map(|(i, _)| i)?;
         let (conn, _) = retiring.swap_remove(best);
         drop(retiring);
         if let Some(dead) = map.insert(*peer, Arc::clone(&conn)) {
-            dead.close(WireError::AuthenticatorInvalid);
+            dead.close(WireError::Unresponsive);
         }
         Some(conn)
     }
@@ -479,7 +548,7 @@ impl ConnectionManager {
             .collect();
         let mut changed = 0;
         for (peer, conn) in &peers {
-            if is_live(conn) && !self.is_silent(conn) {
+            if is_live(conn) && !self.is_dead(conn) {
                 continue;
             }
             match self.promote_heard(peer) {
@@ -500,7 +569,7 @@ impl ConnectionManager {
                     if map.get(peer).is_some_and(|held| Arc::ptr_eq(held, conn)) {
                         map.remove(peer);
                         drop(map);
-                        conn.close(WireError::AuthenticatorInvalid);
+                        conn.close(WireError::Unresponsive);
                         changed += 1;
                     }
                 }
@@ -509,8 +578,8 @@ impl ConnectionManager {
         // A retired connection that has gone silent is as dead as a primary one, and anything
         // still carried on it is waiting on nothing.
         for c in &retired {
-            if is_live(c) && self.is_silent(c) {
-                c.close(WireError::AuthenticatorInvalid);
+            if is_live(c) && self.is_dead(c) {
+                c.close(WireError::Unresponsive);
             }
         }
         // Forget connections that are gone, so the table is bounded by what is held.
@@ -542,7 +611,7 @@ impl ConnectionManager {
             (self.clock)(),
         )
         .await?;
-        Ok(self.file(conn))
+        Ok(self.file(conn).await)
     }
 
     /// Accept the next inbound connection under `admission` and file it under the
@@ -560,7 +629,7 @@ impl ConnectionManager {
         else {
             return Ok(None);
         };
-        Ok(Some(self.file(conn)))
+        Ok(Some(self.file(conn).await))
     }
 
     /// Phase one for an accept loop: the next inbound attempt, with no handshake.
@@ -579,13 +648,13 @@ impl ConnectionManager {
             .endpoint
             .finish_incoming(incoming, (self.clock)(), admission)
             .await?;
-        Ok(self.file_reporting(conn))
+        Ok(self.file_reporting(conn).await)
     }
 
     /// Take ownership of a connection this manager did not dial — one a hole punch
     /// produced (ADR-012 rung 3) — under the same one-per-peer rule.
-    pub fn adopt(&self, conn: VoxConnection) -> Arc<VoxConnection> {
-        self.file(conn)
+    pub async fn adopt(&self, conn: VoxConnection) -> Arc<VoxConnection> {
+        self.file(conn).await
     }
 
     /// File a connection under its peer id. One connection per peer is a
@@ -620,13 +689,14 @@ impl ConnectionManager {
     /// node then failed ("relay cannot reach the peer") until the grace ran out. This is
     /// the "cross-connection interaction in circuit establishment" ADR-017 recorded as
     /// unidentified: the serial loop was hiding an order-dependent tie-break.
-    fn file(&self, conn: VoxConnection) -> Arc<VoxConnection> {
+    async fn file(&self, conn: VoxConnection) -> Arc<VoxConnection> {
         // **Closes the loser, because this caller will not serve it.** Retiring a duplicate is only
         // safe where somebody keeps reading it; retiring it here and dropping the handle would
         // leave it transport-alive and application-deaf, which is strictly worse than the close it
         // replaced. `connect`, the one-shot `accept` and `adopt` all arrive through here and none of
         // them serves a second connection, so for them the old behaviour is the correct one.
-        let filed = self.file_inner(conn, false);
+        let unanswered = self.probe_held(&conn).await;
+        let filed = self.file_inner(conn, false, unanswered);
         debug_assert!(filed.also_serve.is_none());
         filed.kept
     }
@@ -646,23 +716,116 @@ impl ConnectionManager {
     /// Retiring without serving it would be worse than the close it replaces: the connection
     /// would be transport-alive and application-deaf, and the peer's request would never be
     /// answered at all.
-    fn file_reporting(&self, conn: VoxConnection) -> Filed {
-        self.file_inner(conn, true)
+    async fn file_reporting(&self, conn: VoxConnection) -> Filed {
+        let unanswered = self.probe_held(&conn).await;
+        self.file_inner(conn, true, unanswered)
+    }
+
+    /// **Ask the connections held for a peer whether anyone is there**, before a newcomer for
+    /// the same peer is filed against them — and close each one nobody answers on.
+    ///
+    /// Silence ([`SILENCE_IS_DEATH`]) tells a dead connection from a live one, but only after
+    /// 30s, and a restarted peer's new connection usually arrives within a second or two of the
+    /// crash. In that window the tie-break keeps the dead one half the time, and the restarted
+    /// peer is unreachable through this node until the silence rule catches up: measured with
+    /// `vox`'s two-daemon harness as 23–27s before anything crossed.
+    ///
+    /// So the question is asked instead of waited for. One datagram goes out on each held
+    /// connection — one byte, deliberately unframed, which the far end's
+    /// [`VoxConnection::recv_datagram`] discards before any application sees it — and a
+    /// datagram frame is ack-eliciting, so a live peer ACKs it within its ACK delay (25ms)
+    /// whether or not anything reads datagrams. Anything at all arriving on a held connection
+    /// within [`probe_patience`] of its probe is an answer. Nothing is a connection whose far
+    /// end is gone: it is closed, and [`Self::file_inner`] then files the newcomer against no
+    /// rival.
+    ///
+    /// Measured against `a_restarted_host_is_reached_through_its_anchor` (real nodes, a relayed
+    /// client, the host crashed and restarted): reachable again within 0.1s of being back, where
+    /// without the probe 5 of 12 restarts waited 28.0–28.6s for the silence rule.
+    ///
+    /// **Both ends still decide alike.** A restarted peer holds nothing to probe, and the dead
+    /// side cannot vote, so only this end decides. Two *live* connections — a member whose NAT
+    /// rebound dialling again — are both probed, one from each end, and each end's probe is
+    /// traffic the other end hears: the member's probe even migrates the old connection onto
+    /// its new port at the anchor, where the anchor's own probe could not reach. Both ends see
+    /// an answer and both go to [`tie_key`], as before. `a_live_duplicate_is_decided_alike`
+    /// is the gate for that.
+    ///
+    /// A held connection that cannot carry a datagram (the peer disabled them) is assumed live:
+    /// that is the old behaviour, and silence still catches it.
+    async fn probe_held(&self, newcomer: &VoxConnection) -> Unanswered {
+        let peer = newcomer.peer_id();
+        // **Every** connection held for the peer, not only the primary. A retired one — the
+        // loser of an earlier tie-break, still served for its grace — is as dead as the primary
+        // when the peer's process is, and it is exactly what [`Self::promote_heard`] reaches for
+        // when a primary closes: measured, an anchor promoted the connection to a process two
+        // restarts old, because it had been silent for only 3s of the 30s silence needs, and
+        // relayed a client onto it for 28s. Probing them here closes them while the evidence is
+        // fresh.
+        let mut held: Vec<Arc<VoxConnection>> = Vec::new();
+        if let Some(primary) = lock(&self.conns).get(&peer) {
+            held.push(Arc::clone(primary));
+        }
+        held.extend(
+            lock(&self.retiring)
+                .iter()
+                .filter(|(c, _)| c.peer_id() == peer)
+                .map(|(c, _)| Arc::clone(c)),
+        );
+        // A closed or already-dead (silent, or severed) connection is no rival to `file_inner` or
+        // to a promotion.
+        held.retain(|c| is_live(c) && !self.is_dead(c));
+        // Probed at once, so a peer with a dead primary and a dead retired connection costs one
+        // patience, not two.
+        //
+        // **Nothing is closed here.** The probes are awaited, and while they are another newcomer
+        // for the same peer can be filed and a retired connection promoted; closing on the spot
+        // would act on a verdict about a table that has since changed. The verdicts go to
+        // `file_inner`, which acts on them under the lock, re-checked (see there).
+        let mut probes = tokio::task::JoinSet::new();
+        for c in held {
+            probes.spawn(async move { probe_unanswered(&c).await.map(|before| (c, before)) });
+        }
+        let mut unanswered = Vec::new();
+        while let Some(done) = probes.join_next().await {
+            if let Ok(Some(dead)) = done {
+                unanswered.push(dead);
+            }
+        }
+        unanswered
     }
 
     /// [`Self::file_reporting`]'s body. `serve_loser` says whether the caller will read a duplicate
     /// this keeps alive: with it the loser is retired and handed back, without it the loser is
     /// closed. There is no third option — a retired connection nobody reads is the worst of both.
-    fn file_inner(&self, conn: VoxConnection, serve_loser: bool) -> Filed {
+    ///
+    /// `unanswered` is what [`Self::probe_held`] found, and it is acted on **here, under the
+    /// lock**, not where it was found: the probes were awaited, and during that await another
+    /// newcomer can have been filed or a retired connection promoted. A connection is closed only
+    /// if it is still live and has received **nothing since its probe was sent** — so one that
+    /// answered late, or that became the peer's connection because it is live, is spared.
+    /// Newcomers filed during the await were never probed, so they cannot be closed by it.
+    /// `a_live_duplicate_is_decided_alike` covers the case this protects: two live newcomers
+    /// for one peer, filed concurrently at both ends, each probing the other's.
+    fn file_inner(&self, conn: VoxConnection, serve_loser: bool, unanswered: Unanswered) -> Filed {
         let peer = conn.peer_id();
         let mut map = lock(&self.conns);
+        for (dead, before) in unanswered {
+            if is_live(&dead) && dead.quinn().stats().udp_rx.datagrams == before {
+                dead.close(WireError::Unresponsive);
+            }
+        }
         if let Some(existing) = map.get(&peer) {
-            // **A held connection that has gone silent is not a rival.** The process behind it
-            // is gone (see [`SILENCE_IS_DEATH`]), so the newcomer is filed and the dead one
-            // closed, whatever the tie-break would have said. Everything else is decided by
-            // path class and then by `tie_key`, which both ends compute identically.
-            if is_live(existing) && self.is_silent(existing) {
-                existing.close(WireError::AuthenticatorInvalid);
+            // **A held connection that is dead is not a rival.** Silent: the process behind it
+            // is gone (see [`SILENCE_IS_DEATH`]). Severed: its circuit is gone, so it can send
+            // nothing — and a second circuit to this peer is exactly what severs it, so it is
+            // severed at both ends by the time either files the newcomer that replaced it. The
+            // newcomer is filed and the dead one closed, whatever the tie-break would have said.
+            // Everything else is decided by path class and then by `tie_key`, which both ends
+            // compute identically; the class is the connection's own recorded fact (see
+            // [`path_class`]), not a reading of a table that changes underneath it.
+            if is_live(existing) && self.is_dead(existing) {
+                existing.close(WireError::Unresponsive);
             } else if is_live(existing) {
                 let existing = Arc::clone(existing);
                 let (new_class, held_class) = (
@@ -771,7 +934,7 @@ impl ConnectionManager {
             .map(|(p, c)| (*p, Arc::clone(c)))
             .collect();
         held.into_iter()
-            .filter(|(_, c)| is_live(c) && !self.is_silent(c))
+            .filter(|(_, c)| is_live(c) && !self.is_dead(c))
             .map(|(p, _)| p)
             .collect()
     }
@@ -787,29 +950,6 @@ impl ConnectionManager {
         }
     }
 
-    /// Close every connection that runs **over a relay circuit**, and hand back how many.
-    ///
-    /// Done before the others at shutdown: a relayed connection's CONNECTION_CLOSE travels inside
-    /// a circuit on another connection (the one to the relay), so closing that carrier at the same
-    /// moment loses the frame, and the far peer learns only from `SILENCE_IS_DEATH`.
-    pub fn close_relayed(&self) -> usize {
-        let relayed = |c: &VoxConnection| path_class(&self.endpoint, c) == PathClass::Relayed;
-        let mut n = 0;
-        for (conn, _) in lock(&self.retiring).iter() {
-            if relayed(conn) {
-                conn.close(WireError::AuthenticatorInvalid);
-                n += 1;
-            }
-        }
-        for conn in lock(&self.conns).values() {
-            if relayed(conn) {
-                conn.close(WireError::AuthenticatorInvalid);
-                n += 1;
-            }
-        }
-        n
-    }
-
     /// Close every connection (node shutdown).
     pub fn close_all(&self) {
         for (conn, _) in lock(&self.retiring).drain(..) {
@@ -858,3 +998,11 @@ pub fn refuse_stream(send: &mut SendStream, recv: &mut RecvStream) {
     let _ = send.reset(code);
     let _ = recv.stop(code);
 }
+
+/// Reset both halves of a stream with a **specific** coded reason, for a peer that is owed one
+/// (#202). Use [`refuse_stream`] for anyone who must learn nothing from the refusal.
+pub fn refuse_stream_because(send: &mut SendStream, recv: &mut RecvStream, why: WireError) {
+    let code = close_code(why);
+    let _ = send.reset(code);
+    let _ = recv.stop(code);
+}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs
//! Anti-entropy sync (ADR-008 §"Sync = anti-entropy") — the protocol *logic* over
//! an abstract byte-stream transport.
//!
//! Two peers reconcile their per-author logs to identical state. M5 implements the
//! protocol logic; the real QUIC transport is M9 (ADR-011), so sync runs over an
//! abstract [`Transport`] — an in-memory [`DuplexTransport`] drives the tests.
//!
//! ## Frames (ADR-008, M0 [`crate::wire::FrameId`])
//! Each frame is `1-byte FrameId ‖ canonical-CBOR body`:
//! - `HELLO {mode_bitmap}` — opening frame; the mode is negotiated as the highest
//!   bit both peers set (frontier is mandatory; range-reconciliation optional).
//! - `HAVE {[(author_id, max_seq, head_hash)]}` — the feeds a peer holds.
//! - `WANT {[(author_id, from_seq, to_seq)]}` — the ranges a peer is missing.
//! - `ENTRY {entry_wire, has_payload}` — a log entry (skeleton + optional payload).
//! - `NEG {negentropy_msg}` — a Negentropy range-reconciliation message.
//!
//! ## Modes
//! - **Frontier (default, required of every peer).** `HAVE` lists each held feed's
//!   `(author, max_seq, head_hash)`; the receiver replies `WANT` for the missing
//!   `(author, from..=to)` ranges; the holder streams `ENTRY` frames. Used below
//!   ~100 authors where `HAVE` is small.
//! - **Range-reconciliation (when both peers set bit 1).** `NEG` frames carry the
//!   [`crate::log::negentropy`] v1 protocol keyed by the full 32-byte entry hash;
//!   the resolved have/need ids drive `ENTRY` exchange. Used at scale.
//!
//! ## Hard-fail signalling
//! On a hard fail a peer **closes the stream with a Vox application error code**
//! (M0 [`crate::wire::WireError`]) — never a silent downgrade. The abstract
//! transport carries a [`Transport::close`] that records the code; the QUIC
//! mapping is M9.
//!
//! ## Acceptance
//! Received entries pass through the same DAG acceptance predicate as local ones
//! ([`crate::log::dag::Dag::accept`]): admission, authenticator, feed link, and
//! fork handling. A peer never trusts an entry merely because it arrived over
//! sync.
//!
//! ## Serving is bounded by what is held, never by what is asked
//! A `WANT` is the peer's to write, so nothing in it is trusted for size: each
//! range is clamped to the entries this node actually holds, overlapping and
//! duplicate ranges are merged so no entry is sent twice, and one session serves
//! at most [`MAX_SERVE_ENTRIES`] entries / [`MAX_SERVE_BYTES`] bytes within
//! [`SERVE_BUDGET`]. That is correctness, not a quota (PRD-001 R4): a session that
//! stops at the bound still sends what it served, the requester applies it, and
//! because it applied something it syncs again at once and asks for the rest. A
//! history of any size therefore still catches up — in as many sessions as it
//! takes — while no single request can hold the room's lock for longer than the
//! bound.

use std::collections::VecDeque;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, DIGEST_LEN};
use crate::identity::composite::CompositePublicKey;
use crate::log::dag::{AdmissionPolicy, Dag, Rejected};
use crate::log::entry::{Entry, EntryKind, MAX_AUTHENTICATOR_LEN, MAX_PAYLOAD_LEN};
use crate::log::negentropy::{self, Role, MAX_MESSAGE_LEN as MAX_NEG_MESSAGE_LEN};
use crate::wire::{FrameId, WireError, SYNC_MODE_FRONTIER, SYNC_MODE_RANGE_RECONCILIATION};

/// The whole drain phase's budget, however many frames arrive.
///
/// Chosen absolutely, not derived from the per-frame timeout. A room's lock is held for the entire
/// session, so this is how long one member may stop every other operation on that room — a bound on
/// what the rest of the node will tolerate, which is a different question from how patient any one
/// frame should be. The two must not be tied: a per-frame bound tightened to abandon a dead peer
/// sooner would otherwise also abandon an honest sync that is merely slow.
///
/// The references bound the total as well as the gap, for this reason: go-libp2p's relay sets a
/// per-stream timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor
/// reclaims a circuit on total idle. A per-frame bound alone defends only against a peer that
/// stops, never against one that drips.
const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The most entries one session serves to a peer's `WANT`.
///
/// The session holds the room's lock throughout, so what one peer may ask for is
/// what every other operation on the room waits behind. This bounds one session,
/// not a catch-up: the requester applies what it got and, because it applied
/// something, syncs again at once for the rest (see the module docs). A thousand
/// entries verify and file in well under the requester's `DRAIN_BUDGET`.
pub const MAX_SERVE_ENTRIES: usize = 1024;

/// The most entry bytes one session serves, for the same reason as
/// [`MAX_SERVE_ENTRIES`]: a single entry may be up to [`MAX_PAYLOAD_LEN`], so a
/// count alone would still let one `WANT` pull gigabytes into memory. At least one
/// entry is always served, so an entry larger than this still gets through.
pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;

/// The serve phase's wall-clock budget. Each frame is bounded by the transport,
/// but a peer that *reads* one frame every nineteen seconds would otherwise keep
/// the room's lock for as long as there are entries to send — the drip that
/// `DRAIN_BUDGET` closes on the other direction. Stopping here is not a failure:
/// what was served is kept, and the requester comes back for the rest.
pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Hard upper bound on an `ENTRY` frame's carried wire bytes, checked **before**
/// `to_vec` so a hostile frame cannot force a large allocation ahead of
/// [`Entry::from_wire`]'s own per-field caps (ADR-008 anti-abuse). It is the sum
/// of the entry's structural maxima — the payload, the authenticator, and a
/// generous fixed overhead for the skeleton/CBOR framing.
pub const MAX_ENTRY_WIRE: usize = MAX_PAYLOAD_LEN + MAX_AUTHENTICATOR_LEN + 4096;

/// An abstract bidirectional, reliable, ordered byte-frame transport.
///
/// M5 defines this trait so the sync logic is transport-agnostic; the real QUIC
/// stream is M9 (ADR-011). A frame is an opaque byte vector (the caller frames
/// with [`FrameId`] + CBOR). `close` carries the M0 wire error code on a hard
/// fail (the QUIC application-close mapping is M9).
pub trait Transport {
    /// Send one framed message. Errors are surfaced; the sync engine treats a
    /// send error as a transport failure and aborts.
    fn send(&mut self, frame: &[u8]) -> Result<()>;

    /// Receive the next framed message, or `Ok(None)` if the peer half-closed
    /// (no more frames).
    fn recv(&mut self) -> Result<Option<Vec<u8>>>;

    /// Close the stream with a Vox application error code (ADR-008). After a
    /// close the peer must not send/receive further frames.
    fn close(&mut self, code: WireError);

    /// Cleanly finish the **send** direction: no more frames will be sent, and the
    /// peer's [`Transport::recv`] should observe end-of-stream (`Ok(None)`) once it
    /// has drained the frames already sent. This is the *success* terminator,
    /// distinct from the hard-fail [`Transport::close`].
    ///
    /// The default is a no-op: the in-memory [`DuplexTransport`] signals
    /// end-of-stream implicitly (an empty inbox reads as `Ok(None)`), so it needs
    /// nothing here. A real ordered byte transport (the QUIC mapping, M9) overrides
    /// this to FIN its send stream so the peer's blocking read terminates.
    fn finish(&mut self) {}
}

/// An in-memory duplex transport pairing two endpoints by shared queues, for
/// tests and local reconciliation. Not used in production (QUIC is M9).
#[derive(Debug, Default)]
pub struct DuplexTransport {
    /// Frames this endpoint will read (pushed by the peer).
    inbox: VecDeque<Vec<u8>>,
    /// Frames this endpoint writes (the peer reads from here).
    outbox: VecDeque<Vec<u8>>,
    /// The last close code observed on this endpoint, if any.
    closed: Option<WireError>,
}

impl DuplexTransport {
    /// Create a connected pair `(a, b)`: `a`'s outbox feeds `b`'s inbox via
    /// [`DuplexTransport::pump`].
    #[must_use]
    pub fn pair() -> (Self, Self) {
        (Self::default(), Self::default())
    }

    /// Move all of `a`'s outbox into `b`'s inbox and vice-versa (one exchange
    /// step). Returns the number of frames moved in total.
    pub fn pump(a: &mut Self, b: &mut Self) -> usize {
        let mut moved = 0;
        while let Some(f) = a.outbox.pop_front() {
            b.inbox.push_back(f);
            moved += 1;
        }
        while let Some(f) = b.outbox.pop_front() {
            a.inbox.push_back(f);
            moved += 1;
        }
        moved
    }

    /// Whether this endpoint was closed, and with what code.
    #[must_use]
    pub fn close_code(&self) -> Option<WireError> {
        self.closed
    }
}

impl Transport for DuplexTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed.is_some() {
            return Err(Error::MalformedBundle("sync: send on closed transport"));
        }
        self.outbox.push_back(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.inbox.pop_front())
    }

    fn close(&mut self, code: WireError) {
        self.closed = Some(code);
    }
}

/// One feed's frontier summary: `(author_id, max_seq, head_hash)` (ADR-008 HAVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedFrontier {
    /// The feed's author fingerprint.
    pub author_id: Digest32,
    /// The highest seq the peer holds.
    pub max_seq: u64,
    /// The hash of the head entry (for fork-head comparison).
    pub head_hash: Digest32,
}

/// A requested range `(author_id, from_seq, to_seq)` inclusive (ADR-008 WANT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WantRange {
    /// The feed's author fingerprint.
    pub author_id: Digest32,
    /// The first missing seq (inclusive).
    pub from_seq: u64,
    /// The last missing seq (inclusive).
    pub to_seq: u64,
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

/// Encode a `HELLO {mode_bitmap}` frame.
#[must_use]
pub fn encode_hello(mode_bitmap: u8) -> Vec<u8> {
    let mut e = Encoder::new();
    e.uint(u64::from(mode_bitmap));
    framed(FrameId::Hello, e.finish())
}

/// Encode a `HAVE` frame from a peer's feed frontiers.
#[must_use]
pub fn encode_have(frontiers: &[FeedFrontier]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(frontiers.len());
    for f in frontiers {
        e.array(3)
            .bytes(&f.author_id)
            .uint(f.max_seq)
            .bytes(&f.head_hash);
    }
    framed(FrameId::Have, e.finish())
}

/// Encode a `WANT` frame.
#[must_use]
pub fn encode_want(ranges: &[WantRange]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(ranges.len());
    for r in ranges {
        e.array(3)
            .bytes(&r.author_id)
            .uint(r.from_seq)
            .uint(r.to_seq);
    }
    framed(FrameId::Want, e.finish())
}

/// Encode an `ENTRY` frame carrying a framed entry's wire bytes.
#[must_use]
pub fn encode_entry(entry_wire: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(entry_wire);
    framed(FrameId::Entry, e.finish())
}

/// Encode a `NEG` frame carrying a Negentropy message's wire bytes.
#[must_use]
pub fn encode_neg(neg_msg: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(neg_msg);
    framed(FrameId::Neg, e.finish())
}

/// Prefix a CBOR body with its 1-byte frame id.
fn framed(id: FrameId, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(id.as_u8());
    out.extend_from_slice(&body);
    out
}

/// A decoded sync frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFrame {
    /// `HELLO {mode_bitmap}`.
    Hello(u8),
    /// `HAVE {frontiers}`.
    Have(Vec<FeedFrontier>),
    /// `WANT {ranges}`.
    Want(Vec<WantRange>),
    /// `ENTRY {entry_wire}` — the raw framed entry bytes (parsed by the caller).
    Entry(Vec<u8>),
    /// `NEG {negentropy_msg}` — the raw Negentropy wire bytes.
    Neg(Vec<u8>),
}

/// Decode a sync frame. Rejects an unknown frame id (→ a
/// [`WireError::SyncModeUnsupported`] close at the caller) or a malformed body.
pub fn decode_frame(bytes: &[u8]) -> Result<SyncFrame> {
    let id_byte = *bytes
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
                let from_seq = d.uint()?;
                let to_seq = d.uint()?;
                v.push(WantRange {
                    author_id,
                    from_seq,
                    to_seq,
                });
            }
            d.finish()?;
            Ok(SyncFrame::Want(v))
        }
        FrameId::Entry => {
            let mut d = Decoder::new(body);
            // `d.bytes()` borrows (length bounded by remaining input, no alloc);
            // check the borrowed length against the cap BEFORE `to_vec`.
            let slice = d.bytes()?;
            if slice.len() > MAX_ENTRY_WIRE {
                return Err(Error::SizeLimitExceeded("sync ENTRY frame"));
            }
            let wire = slice.to_vec();
            d.finish()?;
            Ok(SyncFrame::Entry(wire))
        }
        FrameId::Neg => {
            let mut d = Decoder::new(body);
            let slice = d.bytes()?;
            if slice.len() > MAX_NEG_MESSAGE_LEN {
                return Err(Error::SizeLimitExceeded("sync NEG frame"));
            }
            let msg = slice.to_vec();
            d.finish()?;
            Ok(SyncFrame::Neg(msg))
        }
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("sync digest length"))
}

/// Negotiate the sync mode from two mode bitmaps: the highest bit both set
/// (range-reconciliation preferred over frontier). Frontier is mandatory, so if
/// both at least set frontier the result is always at least frontier; if a peer
/// sets *no* common bit, [`WireError::SyncModeUnsupported`] is returned.
pub fn negotiate_mode(local: u8, remote: u8) -> std::result::Result<u8, WireError> {
    let common = local & remote;
    if common & SYNC_MODE_RANGE_RECONCILIATION != 0 {
        Ok(SYNC_MODE_RANGE_RECONCILIATION)
    } else if common & SYNC_MODE_FRONTIER != 0 {
        Ok(SYNC_MODE_FRONTIER)
    } else {
        Err(WireError::SyncModeUnsupported)
    }
}

// ---------------------------------------------------------------------------
// Resolver — maps an author fingerprint to its composite root key.
// ---------------------------------------------------------------------------

/// Resolves an author fingerprint to that author's composite root public key and
/// entry kind, so received entries can be verified + classified. The population
/// of this mapping is the identity/consent layers' job (M1/M6); sync only
/// consumes it.
pub trait AuthorResolver {
    /// The composite root key for `author`, or `None` if unknown (an entry from an
    /// unknown author is refused — it cannot be verified).
    fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey>;

    /// The entry kind for an entry, used to choose the fork remedy. M5 has no way
    /// to read encrypted payloads, so the default is [`EntryKind::Content`]; M6/M7
    /// override for governance entries.
    fn kind_for(&self, _entry: &Entry) -> EntryKind {
        EntryKind::Content
    }
}

// ---------------------------------------------------------------------------
// Frontier-mode sync.
// ---------------------------------------------------------------------------

/// Build the local `HAVE` frontiers from a [`Dag`] (one per author feed).
#[must_use]
pub fn frontiers_of(dag: &Dag) -> Vec<FeedFrontier> {
    dag.authors()
        .into_iter()
        .filter_map(|author| {
            dag.feed(&author).map(|feed| FeedFrontier {
                author_id: author,
                max_seq: feed.max_seq(),
                head_hash: feed.head_hash(),
            })
        })
        .collect()
}

/// Given the *remote* peer's `HAVE` frontiers and the local [`Dag`], compute the
/// `WANT` ranges the local peer needs:
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
    //
    // The references bound the total as well as the gap: go-libp2p's relay sets a per-stream
    // timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor reclaims a
    // circuit on total idle. A per-frame bound alone only defends against a peer that stops, never
    // against one that drips.
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
        if std::time::Instant::now() >= deadline {
            return Err(WireError::SyncModeUnsupported);
        }
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                if matches!(
                    apply_entry(dag, resolver, admission, &wire)?,
                    ApplyOutcome::Stored
                ) {
                    applied += 1;
                }
            }
            // **A protocol violation, not something to ignore.** This phase is defined as entries
            // only, and silently accepting anything else is what made the hold above free: a
            // non-entry frame costs the sender nothing and never reaches `apply_entry`, so it
            // would buy the whole budget for free.
            Ok(_) => return Err(WireError::SyncModeUnsupported),
            Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    Ok(applied)
}

fn expect_hello(r: Result<Option<Vec<u8>>>) -> std::result::Result<u8, WireError> {
    match r.map_err(|_| WireError::TransportFailed)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Hello(bitmap)) => Ok(bitmap),
            _ => Err(WireError::SyncModeUnsupported),
        },
        // A clean end-of-stream where a frame was due: the peer hung up mid-session.
        None => Err(WireError::TransportFailed),
    }
}

fn expect_have(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<FeedFrontier>, WireError> {
    match r.map_err(|_| WireError::TransportFailed)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Have(v)) => Ok(v),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::TransportFailed),
    }
}

fn expect_want(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<WantRange>, WireError> {
    match r.map_err(|_| WireError::TransportFailed)? {
        Some(frame) => match decode_frame(&frame) {
            Ok(SyncFrame::Want(v)) => Ok(v),
            _ => Err(WireError::SyncModeUnsupported),
        },
        None => Err(WireError::TransportFailed),
    }
}

// ---------------------------------------------------------------------------
// Range-reconciliation (Negentropy) mode.
// ---------------------------------------------------------------------------

/// Drive a complete **Negentropy range-reconciliation** session between two
/// in-memory DAGs to convergence, applying the entries each side learns it needs.
/// `a` is the Negentropy initiator. Returns `(applied_into_a, applied_into_b)`.
///
/// The Negentropy engine resolves which entry *hashes* differ; the hashes drive
/// `ENTRY` exchange via the content-addressed DAG index. Acceptance is the same
/// predicate as frontier mode.
pub fn range_reconcile_exchange<R: AuthorResolver>(
    a: &mut Dag,
    b: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<(usize, usize), WireError> {
    let _mode = negotiate_mode(
        SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION,
        SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION,
    )?;

    let a_items = negentropy::items_from_ids(&hashes_of(a));
    let b_items = negentropy::items_from_ids(&hashes_of(b));

    // a initiates; messages bounce until a's response is empty. a collects the
    // have/need diff (have = a-only hashes, need = b-only hashes).
    let mut msg = negentropy::reconcile_initiate(&a_items);
    let mut a_need = Vec::new();
    let mut a_have = Vec::new();
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > 64 {
            return Err(WireError::SyncModeUnsupported);
        }
        // Carry NEG over the wire frame to exercise the codec.
        let neg_wire = encode_neg(&negentropy::encode_message(&msg));
        let b_msg = decode_neg_frame(&neg_wire)?;
        let b_res = negentropy::reconcile(Role::Responder, &b_items, &b_msg);
        if b_res.response.is_empty() {
            break;
        }
        let resp_wire = encode_neg(&negentropy::encode_message(&b_res.response));
        let a_msg = decode_neg_frame(&resp_wire)?;
        let a_res = negentropy::reconcile(Role::Initiator, &a_items, &a_msg);
        a_have.extend(a_res.have);
        a_need.extend(a_res.need);
        if a_res.response.is_empty() {
            break;
        }
        msg = a_res.response;
    }

    // Apply: a pulls its `need` from b; b pulls its `need` (= a's `have`) from a.
    let applied_into_a = apply_hashes(a, b, resolver, admission, &a_need)?;
    let applied_into_b = apply_hashes(b, a, resolver, admission, &a_have)?;
    Ok((applied_into_a, applied_into_b))
}

/// All entry hashes in a DAG, in causal order (deterministic).
fn hashes_of(dag: &Dag) -> Vec<Digest32> {
    dag.causal_order()
}

/// Decode a `NEG` frame into a Negentropy message.
fn decode_neg_frame(frame: &[u8]) -> std::result::Result<negentropy::Message, WireError> {
    match decode_frame(frame) {
        Ok(SyncFrame::Neg(bytes)) => {
            negentropy::decode_message(&bytes).map_err(|_| WireError::SyncModeUnsupported)
        }
        _ => Err(WireError::SyncModeUnsupported),
    }
}

/// Apply, into `dst`, the entries at `hashes` fetched from `src` (content-address
/// lookup), under the full acceptance predicate. Entries `src` does not hold are
/// skipped. Entries are applied in seq order per author so feed links resolve.
fn apply_hashes<R: AuthorResolver>(
    dst: &mut Dag,
    src: &Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    hashes: &[Digest32],
) -> std::result::Result<usize, WireError> {
    // Gather the source entries, then order by (author, seq) so prev/lipmaa links
    // are satisfiable as they are appended.
    let mut wires: Vec<(Digest32, u64, Vec<u8>)> = hashes
        .iter()
        .filter_map(|h| {
            src.get_by_hash(h)
                .map(|e| (e.skeleton.author_id, e.skeleton.seq, e.to_wire()))
        })
        .collect();
    wires.sort_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(&y.1)));
    let mut applied = 0;
    for (_, _, wire) in wires {
        if matches!(
            apply_entry(dst, resolver, admission, &wire)?,
            ApplyOutcome::Stored
        ) {
            applied += 1;
        }
    }
    Ok(applied)
}

const _: () = assert!(DIGEST_LEN == 32);
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(3300,3510),(4300,4370),(4680,5330)]; print("".join(f"{i}: {s}" for i,s in enumerate(lines,1) if any(a<=i<=b for a,b in spans)))'
...output truncated...

Full output saved to: /Users/robert.lee/.local/share/opencode/tool-output/tool_0dd38a54f001TLBMq09q04uoy1

3394:                 // every tick, sorted ahead of the member it shared the room with, took the room each
3395:                 // pass, and the member's owed push lost every round: the independent verdict
3396:                 // measured 2–3 relayed runs in 10 losing a message for 120s (vox-bc, #41). Now the
3397:                 // retry goes to the peer that failed, at most `MAX_PUSH_RETRIES` times running; past
3398:                 // that the pair waits for the periodic interval like any other.
3399:                 //
3400:                 // **After a short random wait, not the next tick.** The commonest failure is a
3401:                 // collision: both ends push on the same event, each refuses the other because its
3402:                 // own session for the room is running, and both fail. Retried on the tick, the two
3403:                 // retries landed together again and a message took up to a second (median 364–531ms
3404:                 // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
3405:                 if outcome.is_err() {
3406:                     let failures = self.push_failures.entry((channel_id, peer)).or_insert(0);
3407:                     *failures = failures.saturating_add(1);
3408:                     if *failures <= MAX_PUSH_RETRIES {
3409:                         let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
3410:                         let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
3411:                         let tx = self.net_tx.clone();
3412:                         tokio::spawn(async move {
3413:                             tokio::time::sleep(wait).await;
3414:                             let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
3415:                         });
3416:                     }
3417:                 } else {
3418:                     self.push_failures.remove(&(channel_id, peer));
3419:                 }
3420:                 // The room is free now **whatever the outcome**: a push that found it mid-session
3421:                 // is owed and goes at once. Gating this on success left an owed push waiting for the
3422:                 // tick whenever the session that held the room failed — which a log-less anchor's
3423:                 // always does — and put a 1.00s ceiling on exactly the messages it delayed.
3424:                 if !self.pending_push.is_empty() {
3425:                     // A push that found this room mid-session is owed; the room is free now.
3426:                     self.push_now = true;
3427:                 }
3428:                 self.refresh_network_view().await;
3429:                 if let Ok(o) = outcome {
3430:                     // **Event, not interval.** Propagation was event-driven in one direction only:
3431:                     // an append here pushed at once, but a sync that *brought entries in* marked
3432:                     // nothing, so this node sat on them until its own `SYNC_INTERVAL_SECS`. For an
3433:                     // anchor that is the entire job undone — it holds the log for whoever is away and
3434:                     // then forwards it a half-minute late. End to end the worst case was 30s to reach
3435:                     // the anchor plus 30s for the next member to pull.
3436:                     //
3437:                     // Self-limiting rather than a storm: reconciliation is idempotent, so the peer
3438:                     // this came from applies nothing on the way back and marks nothing onward.
3439:                     // The actor-side half of what the slot just did: a session may have admitted
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
3471:                     }
3472:                     if o.rendered > 0 || o.governance > 0 {
3473:                         let _ = self.event_tx.send(NodeEvent::Synced {
3474:                             channel_id,
3475:                             applied: o.applied as u64,
3476:                             rendered: o.rendered as u64,
3477:                         });
3478:                     }
3479:                 }
3480:             }
3481:             NetEvent::Stream { conn, inbound } => {
3482:                 // Held for the whole handler: the connection must outlive the streams
3483:                 // opened on it, or the peer sees it close mid-exchange.
3484:                 let connection = conn;
3485:                 match inbound {
3486:                     Inbound::Join { .. } => {
3487:                         // Unreachable: the stream loop turns these into
3488:                         // `NetEvent::JoinRequest` once the request is read.
3489:                     }
3490:                     Inbound::Pairwise { peer, send, recv } => {
3491:                         self.take_inbound_skdm(peer, send, recv).await;
3492:                     }
3493:                     Inbound::Sync { .. } => {
3494:                         // Unreachable: the stream loop converts these into
3495:                         // `NetEvent::SyncRequest` once the preamble is read.
3496:                     }
3497:                     Inbound::Punch {
3498:                         peer,
3499:                         coordinator,
3500:                         send,
3501:                         recv,
3502:                     } => {
3503:                         self.answer_punch(peer, coordinator, send, recv);
3504:                     }
3505:                     Inbound::Tunnel { peer, send, recv } => {
3506:                         // The snapshot is taken here (only the actor reads channel
3507:                         // state) and the tunnel runs on its own task: it lives as long
3508:                         // as the TCP connection it carries, which may be hours.
3509:                         let snapshot = self.host_snapshot().await;
3510:                         // The host is told who reached what, because the carried
4300:         let chain_id = {
4301:             let mut channel = shared.lock().await;
4302:             if let Err(e) = channel.issue_consent(profile, target, &skdm, now) {
4303:                 return Outcome::Failed(fault_of(&e));
4304:             }
4305:             channel.sender_generation()
4306:         };
4307:         // The consent is a fact once decided; whether the key landed is learnt off the actor.
4308:         self.watch_delivery(sent, *channel_id, target, chain_id);
4309:         Outcome::Done
4310:     }
4311: 
4312:     /// Decide what an explicit consent's `outcome` means for the person waiting on it.
4313:     ///
4314:     /// `Unreachable` has two causes. With no connection to the member, `reach_member` has started
4315:     /// a dial, so the consent waits for `Dialed` or `ReachFailed`. With a connection but no pairwise
4316:     /// session, the member's bundle record is not on this node's board yet: a node that has just
4317:     /// started holds only what its first sessions bring in. V29-19 measured this through the real
4318:     /// `vox tui`: a consent to a member who was online failed at once, in 0.75s, with
4319:     /// `no reachable peer`, at 0, 3, 6 and 10s after the room opened, and succeeded from 15s. So a
4320:     /// sync with that member is started, since that is what fetches its records, and the consent
4321:     /// is retried when the room's session is done.
4322:     async fn settle_consent(
4323:         &mut self,
4324:         channel_id: Digest32,
4325:         target: Digest32,
4326:         reply: oneshot::Sender<Outcome>,
4327:         outcome: Outcome,
4328:         attempts: u8,
4329:     ) {
4330:         const MAX_CONSENT_ATTEMPTS: u8 = 3;
4331:         if !matches!(outcome, Outcome::Failed(Fault::Unreachable))
4332:             || attempts >= MAX_CONSENT_ATTEMPTS
4333:         {
4334:             let _ = reply.send(outcome);
4335:             return;
4336:         }
4337:         let connected = self
4338:             .net
4339:             .as_ref()
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
4680:     /// third member saw a new one 24–28 s after the join returned; with the interval forced to
4681:     /// 5 s, 1.9–2.6 s. So when this node's board gains a bundle record from an author it has
4682:     /// not seen, it admits what the evidence allows and pushes the room to its connected members.
4683:     /// That push offers their boards the records they lack (`sync_one`), and each receiving
4684:     /// member does the same once, when the newcomer is new to it.
4685:     ///
4686:     /// **Bounded, not a storm.** Only a *new author* triggers this: a member's periodic refresh of
4687:     /// its own records does not. Each node therefore pushes at most once per newcomer, which is
4688:     /// the same fan-out one chat message already has, and in a 500-member room it is one pass per
4689:     /// member per join, over the connections it already holds, with nothing forwarded twice
4690:     /// because a board that already holds the record does not grow.
4691:     async fn note_new_members(&mut self, channel_id: &Digest32) {
4692:         // Not deferred while a session runs; see `publish_channel_to_anchors`.
4693:         let (Some(net), Some(shared)) = (
4694:             self.net.as_ref().map(Arc::clone),
4695:             self.channels.get(channel_id).map(Arc::clone),
4696:         ) else {
4697:             return;
4698:         };
4699:         let epoch = shared.lock().await.epoch();
4700:         let bundles = net.board_bundles(channel_id, epoch);
4701:         let known = self.board_authors.entry(*channel_id).or_default();
4702:         let fresh = bundles.iter().filter(|b| known.insert(b.author_id)).count();
4703:         if fresh == 0 {
4704:             return;
4705:         }
4706:         if let Some(store) = self.profile.as_ref().map(Profile::store_handle) {
4707:             let now = self.now();
4708:             let mut channel = shared.lock().await;
4709:             let _ = admit_board_records(
4710:                 &mut channel,
4711:                 &store,
4712:                 &bundles,
4713:                 ChannelState::MAX_ADMISSIONS_PER_SWEEP,
4714:                 now,
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
4746:     /// A peer with no live connection is skipped, not retried in place: it gets a
4747:     /// fresh schedule when it reconnects.
4748:     /// Re-run the ladder's publish side when the granted mappings are halfway through
4749:     /// their lifetime, so a node that outlives a two-hour mapping stays dialable.
4750:     ///
4751:     /// Nothing happens while the network is down: the renewal instant is left in place
4752:     /// so the next unlock's discovery supersedes it.
4753:     ///
4754:     /// The re-request runs on its own task (it talks to a gateway) and lands back as
4755:     /// [`NetEvent::AddressesDiscovered`], which republishes the address records too —
4756:     /// a renewal that came back with a *different* external port must be advertised.
4757:     fn renew_mappings_if_due(&mut self) {
4758:         let Some(due) = self.renew_mappings_at else {
4759:             return;
4760:         };
4761:         if self.now() < due {
4762:             return;
4763:         }
4764:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
4765:             return;
4766:         };
4767:         // Cleared now, not when the refresh returns: one renewal in flight at a time.
4768:         self.renew_mappings_at = None;
4769:         let tx = self.net_tx.clone();
4770:         tokio::spawn(async move {
4771:             let mappings = net.refresh_advertised().await;
4772:             let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
4773:         });
4774:     }
4775: 
4776:     /// Push what a local append made due **now**, rather than at the next tick.
4777:     ///
4778:     /// A message was marked due by `note_local_append` and then waited for `TICK` — up to a full
4779:     /// second — before anything sent it: PRD-001 R40 asks for chat under a second, and measured
4780:     /// through the real binary the median was 322–894ms with a maximum of 1.021s, the tick's own
4781:     /// shape. Run after the command or event that made the push due, and after its reply, so the
4782:     /// command's own latency is unchanged.
4783:     ///
4784:     /// A burst coalesces for free: a room mid-session is owed rather than re-sent (see
4785:     /// `run_due_syncs`), and the session's `SyncDone` re-arms this while pushes are still owed, so
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
4831:             // A member reconciles a channel with its co-authors — and with that channel's
4832:             // anchors, which keep the log for whoever is away (M15.2b). Both are decided per room
4833:             // by `may_sync` below.
4834: 
4835:             // **Learn who this peer is before deciding we share nothing with it.**
4836:             //
4837:             // The filter below asks `is_author(&peer)`, and the thing that admits a newly joined
4838:             // peer as an author — `learn_members`, reading the bundle records off this node's own
4839:             // board — lives inside `sync_one`, which only runs for channels that already passed the
4840:             // filter. So a peer that has just joined is skipped for having no entries, by the node
4841:             // holding the evidence that it belongs, and the only code that would fix that sits
4842:             // behind the check it is meant to satisfy. `learn_members`' own comment says reading
4843:             // membership from the board "is a precondition for reconciling at all"; it was not one.
4844:             //
4845:             // The consequence, measured as a user: a message posted seconds after somebody joins is
4846:             // **lost, not delayed** — the sender skips them, the connect trigger is consumed, and
4847:             // the next chance is a full `SYNC_INTERVAL_SECS`. With the daemons settled, twelve posts
4848:             // crossed twelve times in 0-1s; posting immediately after a join lost one in six even
4849:             // after the owed-push fix below.
4850:             //
4851:             // Done only on a connect, not every tick: this reads the board and admits authors, which
4852:             // is exactly the work a new connection warrants and would be waste on the interval.
4853:             // Candidates first, decided after: the membership test below needs `&mut self` (it may
4854:             // admit a member from this node's own board), which the maps cannot be borrowed across.
4855:             let mut member_rooms: Vec<Digest32> = Vec::new();
4856:             for cid in self.channels.keys() {
4857:                 if trigger == SyncTrigger::LocalAppend
4858:                     && (!self.pending_push.contains(cid)
4859:                         || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
4860:                 {
4861:                     continue;
4862:                 }
4863:                 if self.in_session_with(cid, &peer) || self.publishing.contains(&(*cid, peer)) {
4864:                     owed.push(*cid);
4865:                     continue;
4866:                 }
4867:                 member_rooms.push(*cid);
4868:             }
4869:             // **A room goes only to a peer that belongs to it.** On a fresh connection this pushed
4870:             // *every* open room to the peer — the inbound half of D5 refuses a non-member's request,
4871:             // and this was the outbound half handing the same log over unasked. The bypass existed
4872:             // because a peer that has just joined is not yet an author in this node's view;
4873:             // `may_sync` covers that case properly, by admitting the peer from this node's own board
4874:             // before deciding, which is the evidence the bypass was standing in for.
4875:             //
4876:             // **An anchor gets the rooms that name it, not every room** (V29-04, #39). An anchor was
4877:             // pushed every room this node held because `anchor_ids` held it, and `anchor_ids` holds
4878:             // the anchors named by ANY room's invite link: an anchor named only by room A's link was
4879:             // handed room B's log unasked, while that anchor's own `may_sync` would have refused B
4880:             // inbound. vox-bc's verifier reproduced it with real nodes: the other room's anchor was
4881:             // pushed room B, one session and five entries. `may_sync` already accepts a room's own
4882:             // anchors, and the configured ones are in every room's anchor set, so it decides alone.
4883:             for cid in member_rooms {
4884:                 let belongs = {
4885:                     let Some(epoch) = (match self.channels.get(&cid) {
4886:                         Some(shared) => Some(shared.lock().await.epoch()),
4887:                         None => None,
4888:                     }) else {
4889:                         continue;
4890:                     };
4891:                     self.may_sync(&cid, &peer, epoch).await
4892:                 };
4893:                 if belongs {
4894:                     channels.push(cid);
4895:                 }
4896:             }
4897:             // An anchor forwards a room it keeps only to that room's authors — read fresh off its
4898:             // own board first, so a member that has just been vouched for is not skipped. It used to
4899:             // forward every kept room to any peer that connected or pushed.
4900:             let mut kept_rooms: Vec<Digest32> = Vec::new();
4901:             for cid in self.anchored.keys() {
4902:                 if trigger == SyncTrigger::LocalAppend
4903:                     && (!self.pending_push.contains(cid)
4904:                         || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
4905:                 {
4906:                     continue;
4907:                 }
4908:                 if self.in_session_with(cid, &peer) {
4909:                     owed.push(*cid);
4910:                     continue;
4911:                 }
4912:                 kept_rooms.push(*cid);
4913:             }
4914:             for cid in kept_rooms {
4915:                 self.refresh_anchored_authors(&cid).await;
4916:                 let Some(state) = self.anchored.get(&cid).map(Arc::clone) else {
4917:                     continue;
4918:                 };
4919:                 if state.lock().await.is_author(&peer) {
4920:                     channels.push(cid);
4921:                 }
4922:             }
4923:             for channel_id in channels {
4924:                 if self.sync_one(&channel_id, peer).await {
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
4941:                 // **aligned once, aligned forever.** A local append makes every peer due at once, so
4942:                 // the alignment was the default after the first post, and which peer starved came
4943:                 // down to how the fingerprints sorted.
4944:                 //
4945:                 // Measured in `node_m15_anchor_gate` (instrumented, by the other session): in every
4946:                 // red, each member skipped the *other member* nine rounds running while its only
4947:                 // session — with the anchor — failed each time, so the one leg that could carry the
4948:                 // room never ran. Red about half the time in CI since before v0.2.5.
4949:                 //
4950:                 // Owed is not the unconditional retry the note on `pending_push` below warns
4951:                 // against: nothing here takes a lock, and it is retried only while that room is
4952:                 // mid-session, which is milliseconds. The next tick finds the room free.
4953:                 if !owed.is_empty() {
4954:                     owed_rooms.extend(owed.iter().copied());
4955:                     schedule.note_local_append();
4956:                     self.owed_first.insert(peer);
4957:                 }
4958:             }
4959:         }
4960:         // **Keep what did not go out.** This cleared unconditionally, which discarded the intent to
4961:         // push an append whenever it had not actually been pushed — and the ordinary case is a peer
4962:         // that has just joined: `note_local_append` marks "every peer's schedule due", but a peer
4963:         // whose `NetEvent::Connected` the actor has not handled yet **has no schedule to mark**, so
4964:         // nothing was owed to it and the entry was dropped rather than delayed. It then waited for
4965:         // that peer's own `SYNC_INTERVAL_SECS`, and if that raced too, longer.
4966:         //
4967:         // Measured as a user: with the daemons settled, twelve posts crossed twelve times in 0-1s;
4968:         // the proof that posts seconds after joining lost one in three.
4969:         //
4970:         // Note what is deliberately NOT changed: `note_synced` above still runs whether or not
4971:         // anything went out. Making it conditional looks right and is wrong — it leaves the peer due
4972:         // every tick, so one that cannot sync is retried once a second, each attempt taking the
4973:         // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
4974:         // hold on failure; what must survive is the work owed, which is this line.
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
4996:     /// a concurrent session for the same channel.
4997:     async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
4998:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
4999:             return false;
5000:         };
5001:         let Some(conn) = net.manager().existing(&peer) else {
5002:             return false;
5003:         };
5004:         let Some(store) = self.log_store() else {
5005:             return false;
5006:         };
5007:         let target = match (
5008:             self.channels.get(channel_id).map(Arc::clone),
5009:             self.anchored.get(channel_id).map(Arc::clone),
5010:         ) {
5011:             (Some(shared), _) => SessionTarget::Channel(shared),
5012:             (None, Some(state)) => SessionTarget::Anchored(state),
5013:             (None, None) => return false,
5014:         };
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
5111:                         return;
5112:                     }
5113:                 };
5114:             // 3. Run the session. It takes the room's lock inside each protocol step and never across
5115:             //    a send or a receive (`sync_over_room`), so a peer slow to answer no longer holds the
5116:             //    room — or, through `publish()` and every other lock on it, the actor.
5117:             let joined = tokio::task::spawn_blocking(move || {
5118:                 let mut t = transport;
5119:                 match target {
5120:                     SessionTarget::Channel(shared) => {
5121:                         crate::node::channel::ChannelState::sync_over_room(
5122:                             &shared, &store, &mut t, now,
5123:                         )
5124:                     }
5125:                     SessionTarget::Anchored(state) => {
5126:                         crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
5127:                     }
5128:                 }
5129:             })
5130:             .await;
5131:             // A session that panicked still hands the room back: `Err` from the join is the panic.
5132:             let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
5133:                 "sync session panicked",
5134:             )));
5135:             let _ = tx
5136:                 .send(NetEvent::SyncDone {
5137:                     channel_id: cid,
5138:                     peer,
5139:                     outcome,
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
5231:     /// actor is the only writer of channel state and anything it awaits inline stops the whole
5232:     /// node, so it must never wait on an untrusted peer to speak. What it does here is local
5233:     /// and ordered, which is what the single-task design is for.
5234:     /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
5235:     /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
5236:     /// of any room this node holds may — and the preamble then names whichever channel the
5237:     /// peer likes. Nothing here checked the two against each other, so a member of room A who
5238:     /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
5239:     /// [`Self::may_sync`] for who counts.
5240:     async fn run_sync_session(
5241:         &mut self,
5242:         peer: Digest32,
5243:         channel_id: Digest32,
5244:         epoch: u64,
5245:         send: quinn::SendStream,
5246:         recv: quinn::RecvStream,
5247:     ) {
5248:         use crate::node::syncstream::accept_sync;
5249:         // Answering while our own session holds this room is the other half of the deadlock.
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
5321:                 if channel.is_author(peer)
5322:                     || channel.anchors().nodes().iter().any(|a| a.id == *peer)
5323:                 {
5324:                     return true;
5325:                 }
5326:             }
5327:             let (Some(net), Some(store)) = (
5328:                 self.net.as_ref().map(Arc::clone),
5329:                 self.profile.as_ref().map(Profile::store_handle),
5330:             ) else {
[0m
[0m$ [0mgh issue list --repo robertelee78/vox --state all --search '"ADR-025"' --json number,title,body --limit 10
[]
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-astra.md[90m [offset=1600, limit=180][0m
[0m✱ [0mGrep "open_uni|accept_uni|dispatch_uni|StreamKind|Sync \{|sync_channel\("[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src · 63 matches[0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs
//! ADR-008 anti-entropy sync on a typed `sync` stream, and the schedule ADR-016
//! specifies for it (§"Sync scheduling").
//!
//! The reconciliation engine is ADR-008's and is used unchanged; this module only
//! opens/accepts the stream and states the policy:
//!
//! - **When.** A session per shared channel on every new connection
//!   ([`SyncTrigger::Connected`]), every [`SYNC_INTERVAL_SECS`] while connected
//!   ([`SyncTrigger::Periodic`]), and a push immediately after a local append
//!   ([`SyncTrigger::LocalAppend`]). [`SyncSchedule`] is the pure clock-driven
//!   decision, so the node's timer logic is testable without a network.
//! - **Which mode.** Frontier mode until a channel exceeds
//!   [`RANGE_MODE_AUTHOR_THRESHOLD`] authors, then range reconciliation
//!   ([`should_use_range_mode`]) — the scale rule ADR-008 requires.
//!
//! ## The stream names its channel first
//! A frontier session reconciles **one channel's** log, but a connection is per
//! *peer* (ADR-016 §"Connections") and a peer may share several channels with us —
//! so the ADR-008 frames alone are not enough to know which log to open. The
//! initiator therefore sends a one-field preamble naming the `(channelID, epoch)`
//! before handing the stream to the engine, exactly as the join stream does. The
//! ADR-008 frame sequence itself is untouched; the channelID is not a secret (it is
//! on the board and in the invite link) and the preamble is inside the authenticated
//! stream regardless.
//!
//! ## Blocking, deliberately
//! ADR-008's engine is synchronous, and [`QuicStreamTransport`] bridges it onto
//! async quinn with [`tokio::runtime::Handle::block_on`]. A session therefore runs
//! on a thread that may block — `tokio::task::spawn_blocking` in the node, a plain
//! thread in tests — never inside an async task on a runtime worker.

use quinn::{RecvStream, SendStream};
use tokio::runtime::Handle;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{QuicStreamTransport, VoxConnection};
use crate::transport::streams::{open_typed, StreamKind};

/// Seconds between periodic sync sessions with a connected peer (ADR-016).
pub const SYNC_INTERVAL_SECS: u64 = 30;

/// Author count above which a channel reconciles in **range** mode instead of
/// frontier mode (ADR-008 at scale).
pub const RANGE_MODE_AUTHOR_THRESHOLD: usize = 100;

/// Whether a channel with `authors` admitted authors should use range
/// reconciliation rather than frontier mode.
#[must_use]
pub fn should_use_range_mode(authors: usize) -> bool {
    authors > RANGE_MODE_AUTHOR_THRESHOLD
}

/// Why a sync session is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTrigger {
    /// A connection to this peer was just established.
    Connected,
    /// The periodic interval elapsed.
    Periodic,
    /// This node appended locally and is pushing it out.
    LocalAppend,
}

/// The per-peer sync clock (ADR-016 §"Sync scheduling"), as a pure function of
/// time and local appends so it can be tested without a network.
#[derive(Debug, Clone, Copy)]
pub struct SyncSchedule {
    last_sync: u64,
    pending_append: bool,
}

impl SyncSchedule {
    /// A schedule for a peer that has just connected: the first session is due
    /// immediately.
    #[must_use]
    pub fn connected() -> Self {
        Self {
            last_sync: 0,
            pending_append: false,
        }
    }

    /// Record a local append: the next check pushes it out without waiting for the
    /// interval.
    pub fn note_local_append(&mut self) {
        self.pending_append = true;
    }

    /// Record that a session ran at `now_secs`.
    pub fn note_synced(&mut self, now_secs: u64) {
        self.last_sync = now_secs;
        self.pending_append = false;
    }

    /// The trigger due at `now_secs`, if any. A local append wins over the
    /// interval, and the first call after [`SyncSchedule::connected`] is
    /// `Connected`.
    #[must_use]
    pub fn due(&self, now_secs: u64) -> Option<SyncTrigger> {
        if self.last_sync == 0 {
            return Some(SyncTrigger::Connected);
        }
        if self.pending_append {
            return Some(SyncTrigger::LocalAppend);
        }
        if now_secs.saturating_sub(self.last_sync) >= SYNC_INTERVAL_SECS {
            return Some(SyncTrigger::Periodic);
        }
        None
    }
}

impl Default for SyncSchedule {
    fn default() -> Self {
        Self::connected()
    }
}

/// The largest sync preamble either side will read (`[channel_id, epoch]`).
const MAX_SYNC_PREAMBLE: usize = 64;

/// Open a `sync`-typed bi-stream on `conn` for one channel and wrap it as the
/// ADR-008 transport. The kind frame is written first so the peer dispatches it,
/// then the preamble naming the channel (see the module docs).
pub async fn open_sync(
    conn: &VoxConnection,
    handle: Handle,
    channel_id: &Digest32,
    epoch: u64,
) -> Result<QuicStreamTransport> {
    let (mut send, recv) = open_typed(conn, StreamKind::Sync).await?;
    let mut e = Encoder::new();
    e.array(2).bytes(channel_id).uint(epoch);
    write_frame(&mut send, &e.finish()).await?;
    Ok(QuicStreamTransport::new(handle, send, recv))
}

/// Read the preamble from an accepted `sync` stream: which `(channelID, epoch)` the
/// peer wants to reconcile.
pub async fn read_sync_request(recv: &mut quinn::RecvStream) -> Result<(Digest32, u64)> {
    let bytes = read_frame(recv, MAX_SYNC_PREAMBLE)
        .await?
        .ok_or(Error::MalformedGovernance(
            "sync stream closed before preamble",
        ))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedGovernance("sync preamble arity"));
    }
    let channel_id: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("sync preamble channel_id"))?;
    let epoch = d.uint()?;
    d.finish()?;
    Ok((channel_id, epoch))
}

/// Wrap an already-accepted, already-authorized `sync` stream as the ADR-008
/// transport (the manager accepted and classified it).
#[must_use]
pub fn accept_sync(handle: Handle, send: SendStream, recv: RecvStream) -> QuicStreamTransport {
    QuicStreamTransport::new(handle, send, recv)
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | python3 -c 'import sys; spans=[(5304,5370),(160,245),(550,605),(3310,3390)]; print("".join(f"{i}: {s}" for i,s in enumerate(sys.stdin,1) if any(a<=i<=b for a,b in spans)))'
160: 
161: /// A room's lock if it can be had by `deadline`. A free lock is taken even once the deadline has
162: /// passed: only a held one is given up.
163: async fn by<T>(
164:     deadline: tokio::time::Instant,
165:     m: &tokio::sync::Mutex<T>,
166: ) -> Option<tokio::sync::MutexGuard<'_, T>> {
167:     tokio::time::timeout_at(deadline, m.lock()).await.ok()
168: }
169: /// How long one publish round to one board may take before it is given up until the next round: a
170: /// live board answers each put in milliseconds. See `publish_channel_to_anchor`.
171: const ANCHOR_PUBLISH_PATIENCE: Duration = Duration::from_secs(5);
172: /// How long a delivered sender key may go unanswered before it is counted as not taken and sent
173: /// again. See `pairwise_stream::refused`.
174: const KEY_DELIVERY_PATIENCE: Duration = Duration::from_secs(30);
175: /// How many failed sessions in a row a `(room, peer)` push is retried on the next tick before it is
176: /// left to the periodic interval. Enough to ride out a collision (both sides pushing at once); few
177: /// enough that a peer whose sessions always fail cannot hold the room.
178: const MAX_PUSH_RETRIES: u32 = 3;
179: 
180: /// How often a peer reached over a relay is retried for a direct path.
181: ///
182: /// A relayed path works, so nothing forces a retry — but it costs a third party's bandwidth
183: /// and a round trip, and the conditions that prevented a direct path are usually temporary:
184: /// a NAT mapping expires, a firewall state clears, a laptop leaves a captive network. One
185: /// attempt at dial time is a snapshot of the worst moment, when neither side has learned the
186: /// other's addresses yet.
187: ///
188: /// A minute, which is `upgradeUDPDirectInterval` in tailscale's magicsock — the same
189: /// reasoning and the same figure, chosen there because NAT conditions change on that order.
190: const UPGRADE_RETRY: Duration = Duration::from_secs(60);
191: 
192: /// How long the actor may be busy before it says so.
193: ///
194: /// **Derived from the tick, not chosen.** The actor is the only writer of channel state, so while
195: /// it is busy the node answers nobody; anything beyond a few ticks means some peer's request is
196: /// queued behind it, and a peer's patience is measured in seconds. Five ticks is long enough that
197: /// ordinary work never reports, and short enough that a stall a person would notice always does.
198: const STALL_BUDGET: Duration = Duration::from_secs(5);
199: 
200: /// How long the actor will spend *setting up* one sync before abandoning it.
201: ///
202: /// **The actor may not block on the wire, and this is the interim bound while the setup moves into
203: /// its own slot.** Deciding to reconcile a room with a peer is cheap; the two steps before the
204: /// session are not — reading that peer's board (`fetch_channel`) and opening the sync stream
205: /// (`open_sync`) are both round trips, and both were bounded only by `SYNC_FRAME_TIMEOUT`. So one
206: /// peer that went quiet mid-setup stopped the one task allowed to write channel state, for twenty
207: /// seconds, and the node answered nobody — including the pushes it had just marked owed.
208: ///
209: /// Measured on an anchor, which is the node it hurts most:
210: ///
211: /// ```text
212: /// vox node: took 1 entry for room 4yxukqstptuq
213: /// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
214: /// ```
215: ///
216: /// Safe to bound, unlike a publish: both steps are best-effort and their failure already means
217: /// "skip this one, the schedule will come round again". Nothing downstream needs them to have
218: /// completed, so a cut-short setup costs a tick where a cut-short publish lost a record.
219: ///
220: /// This is a bound, not the fix. The fix is for the whole setup to run in a slot and report back
221: /// through `NetEvent::SyncDone`, which is the seam that already exists for it.
222: /// How many sync setups and sessions may be in flight at once.
223: ///
224: /// **The actor decides; slots do the waiting.** Everything about reconciling a room with a peer that
225: /// touches the wire — reading that peer's board, opening the stream, the session itself — runs in one
226: /// of these, so the one task allowed to write channel state never waits on a network round trip. It
227: /// used to: `fetch_channel` and `open_sync` were awaited inline, bounded only by
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
550:         send: quinn::SendStream,
551:         /// The stream's receive half.
552:         recv: quinn::RecvStream,
553:     },
554:     /// A peer asked to reconcile a channel, and its request has **already been read** on
555:     /// the stream's own task. The actor does the reconciliation; it never waits for the
556:     /// peer to speak, because anything the actor awaits inline stops the whole node.
557:     SyncRequest {
558:         /// The connection the stream came in on.
559:         conn: Arc<VoxConnection>,
560:         /// The authenticated peer.
561:         peer: Digest32,
562:         /// The channel it asked to reconcile.
563:         channel_id: Digest32,
564:         /// The epoch it named.
565:         epoch: u64,
566:         /// The stream's send half.
567:         send: quinn::SendStream,
568:         /// The stream's receive half.
569:         recv: quinn::RecvStream,
570:     },
571:     /// A peer connected inbound: it gets a sync schedule, due immediately.
572:     Connected {
573:         /// The authenticated peer.
574:         peer: Digest32,
575:     },
576:     /// A sync session finished and is handing the channel back.
577:     ///
578:     /// A session **cannot** be awaited inside the actor loop: two nodes that each
579:     /// start one at the same moment would each be waiting for the other to serve the
580:     /// responder side, and neither could — a deadlock the M14 gate reproduced the
581:     /// moment sync became automatic. So a session owns the channel on its own task
582:     /// and returns it here, leaving the actor free to serve the peer meanwhile.
583:     SyncDone {
584:         /// The channel that was reconciled.
585:         channel_id: Digest32,
586:         /// The peer it was reconciled with.
587:         peer: Digest32,
588:         /// What the session did, or why it failed.
589:         outcome: crate::error::Result<crate::node::channel::SyncOutcome>,
590:     },
591:     /// A sender key written to `peer` was taken: any backoff on re-sending to it ends.
592:     SkdmTaken {
593:         /// The room.
594:         channel_id: Digest32,
595:         /// The member that took it.
596:         peer: Digest32,
597:     },
598:     /// A sender key written to `peer` was not taken (see `pairwise_stream::refused`): it is owed
599:     /// again, and the tick re-sends it.
600:     SkdmRefused {
601:         /// The room.
602:         channel_id: Digest32,
603:         /// The member it was for.
604:         peer: Digest32,
605:         /// The generation that did not land.
3310:                     return;
3311:                 };
3312:                 let _ = shared
3313:                     .lock()
3314:                     .await
3315:                     .note_undelivered(profile.store(), peer, chain_id);
3316:                 // 2, 4, 8 … 64s: a refusal that cures (a session that converges, a member learnt
3317:                 // from the board) is retried promptly, and one that does not stops costing a
3318:                 // stream every second.
3319:                 let now = self.now();
3320:                 let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
3321:                 entry.0 = entry.0.saturating_add(1);
3322:                 entry.1 = now.saturating_add(1u64 << entry.0.min(6));
3323:                 let _ = self.event_tx.send(NodeEvent::KeyNotTaken {
3324:                     channel_id,
3325:                     peer,
3326:                     why,
3327:                 });
3328:             }
3329:             NetEvent::PublishDone {
3330:                 channel_id,
3331:                 board,
3332:                 outcomes,
3333:             } => {
3334:                 self.publishing.remove(&(channel_id, board));
3335:                 self.report_publish(&channel_id, board, outcomes);
3336:                 if !self.publishing.iter().any(|(room, _)| *room == channel_id) {
3337:                     let (ready, waiting): (Vec<_>, Vec<_>) =
3338:                         std::mem::take(&mut self.publish_waiters)
3339:                             .into_iter()
3340:                             .partition(|(room, _, _)| *room == channel_id);
3341:                     self.publish_waiters = waiting;
3342:                     if !ready.is_empty() {
3343:                         self.publish().await;
3344:                         for (_, reply, outcome) in ready {
3345:                             let _ = reply.send(outcome);
3346:                         }
3347:                     }
3348:                 }
3349:                 if self.publish_again.remove(&(channel_id, board)) {
3350:                     let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
3351:                     if let Some(conn) = conn {
3352:                         self.publish_channel_to_anchor(&channel_id, &conn).await;
3353:                     }
3354:                 }
3355:                 // A session with that board for this room was held back while the round ran.
3356:                 self.push_now = true;
3357:             }
3358:             NetEvent::SkdmTaken { channel_id, peer } => {
3359:                 self.key_backoff.remove(&(channel_id, peer));
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
5321:                 if channel.is_author(peer)
5322:                     || channel.anchors().nodes().iter().any(|a| a.id == *peer)
5323:                 {
5324:                     return true;
5325:                 }
5326:             }
5327:             let (Some(net), Some(store)) = (
5328:                 self.net.as_ref().map(Arc::clone),
5329:                 self.profile.as_ref().map(Profile::store_handle),
5330:             ) else {
5331:                 return false;
5332:             };
5333:             let bundles = net.board_bundles(channel_id, epoch);
5334:             if !bundles.iter().any(|b| b.author_id == *peer) {
5335:                 return false;
5336:             }
5337:             let now = self.now();
5338:             let mut channel = shared.lock().await;
5339:             let _ = admit_board_records(
5340:                 &mut channel,
5341:                 &store,
5342:                 &bundles,
5343:                 ChannelState::MAX_ADMISSIONS_PER_SWEEP,
5344:                 now,
5345:             )
5346:             .await;
5347:             return channel.is_author(peer);
5348:         }
5349:         if let Some(state) = self.anchored.get(channel_id) {
5350:             return state.lock().await.is_author(peer);
5351:         }
5352:         false
5353:     }
5354: 
5355:     /// Accept an inbound [`PairwiseFrame::Hello`], establishing the responder half of
5356:     /// a session a peer opened from our bundle record. `true` if a session now exists.
5357:     ///
5358:     /// This is the join responder's PQXDH path minus the join: the message names a
5359:     /// signed prekey and optionally a one-time prekey **from our own ring**, so a party
5360:     /// holding no prekey of ours cannot open a session at all. The one-time prekey is
5361:     /// consumed and the consume persisted before the handshake completes, so a crash
5362:     /// here cannot leave it re-offerable; a replay is graded last-resort rather than
5363:     /// silently accepted, the same reconciliation `joinstream` performs.
5364:     ///
5365:     /// An existing session is never replaced: a peer cannot reset our ratchet by
5366:     /// sending a fresh `Hello`.
5367:     async fn accept_hello(&mut self, channel_id: Digest32, peer: Digest32, initial: &[u8]) -> bool {
5368:         let key = (channel_id, peer);
5369:         let hello_hash = crate::hash::sha256(initial);
5370:         let mut replaces = false;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | python3 -c 'import sys; spans=[(195,225),(2080,2140),(2650,2750)]; print("".join(f"{i}: {s}" for i,s in enumerate(sys.stdin,1) if any(a<=i<=b for a,b in spans)))'
195:         Self { authors }
196:     }
197: }
198: 
199: impl AuthorResolver for ChannelAuthors {
200:     fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey> {
201:         self.authors.get(author).cloned()
202:     }
203: 
204:     fn kind_for(&self, entry: &Entry) -> EntryKind {
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
2080:                         &self.gov_entries,
2081:                         now_secs,
2082:                     )?);
2083:                     out.governance += 1;
2084:                 }
2085:                 EntryKind::Content => {
2086:                     if self.render_content(store, author, entry_hash, &payload, now_secs)? {
2087:                         out.rendered += 1;
2088:                     }
2089:                 }
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
2136:         }
2137:     }
2138: 
2139:     /// Accept a **sender-key distribution message** from `author` (ADR-006/ADR-007
2140:     /// step 2/3): the sender key that member released to this identity, delivered
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
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | python3 -c 'import sys; print("".join(f"{i}: {s}" for i,s in enumerate(sys.stdin,1) if 300<=i<=470))'
300:                 .get_by_hash(&entry_hash)
301:                 .ok_or(Error::MalformedGovernance("synced entry vanished"))?;
302:             let wire = entry.to_wire();
303:             let is_governance = entry
304:                 .payload
305:                 .as_deref()
306:                 .map(classify_payload)
307:                 .transpose()?
308:                 .is_some_and(|k| k == EntryKind::Governance);
309:             let id = self.next_log_id;
310:             let seg = seal_segment(&self.sek, SegmentKind::AnchorLog, id, &wire)?;
311:             if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::AnchorLog, id, &seg) {
312:                 self.poisoned = true;
313:                 return Err(e);
314:             }
315:             self.next_log_id = id.saturating_add(1);
316:             if is_governance {
317:                 out.governance += 1;
318:             }
319:         }
320:         Ok(out)
321:     }
322: 
323:     /// Reconcile with a peer over `transport`, holding `shared`'s lock only inside each protocol
324:     /// step. See [`crate::log::sync::SessionRoom`] and `ChannelState::sync_over_room`.
325:     ///
326:     /// # Errors
327:     /// The copy is poisoned, a persist fails, or the session hard-fails.
328:     pub fn sync_over_room<T: Transport>(
329:         shared: &tokio::sync::Mutex<Self>,
330:         store: &Store,
331:         transport: &mut T,
332:     ) -> Result<SyncOutcome> {
333:         let epoch = {
334:             let st = shared.blocking_lock();
335:             if st.poisoned {
336:                 return Err(Error::Profile(
337:                     "anchored channel is poisoned after a failed persist; reopen it",
338:                 ));
339:             }
340:             st.epoch
341:         };
342:         let room = AnchorSessionRoom {
343:             shared,
344:             store,
345:             epoch,
346:             out: std::cell::RefCell::new(SyncOutcome::default()),
347:             fatal: std::cell::RefCell::new(None),
348:         };
349:         let session = crate::log::sync::frontier_session_room(transport, &room);
350:         if let Some(e) = room.fatal.take() {
351:             return Err(e);
352:         }
353:         let mut out = room.out.into_inner();
354:         match session {
355:             Ok(n) => {
356:                 out.applied = n;
357:                 Ok(out)
358:             }
359:             Err(code) => Err(sync_failure(code)),
360:         }
361:     }
362: 
363:     fn rebuild_admission(&mut self) {
364:         let mut admission = AdmissionPolicy::new();
365:         for author in self.authors.keys() {
366:             admission.admit(self.channel_id, self.epoch, *author);
367:         }
368:         self.admission = admission;
369:     }
370: 
371:     fn persist_meta(&mut self, store: &Store) -> Result<()> {
372:         let mut e = Encoder::new();
373:         e.array(3)
374:             .uint(META_VERSION)
375:             .bytes(&self.genesis.to_wire())
376:             .bytes(&authors_bytes(&self.authors));
377:         let seg = seal_segment(&self.sek, SegmentKind::AnchorMeta, SEG_META, &e.finish())?;
378:         if let Err(err) =
379:             store.put_segment(&self.channel_id, SegmentKind::AnchorMeta, SEG_META, &seg)
380:         {
381:             self.poisoned = true;
382:             return Err(err);
383:         }
384:         Ok(())
385:     }
386: }
387: 
388: fn parse_meta(bytes: &[u8]) -> Result<(Genesis, BTreeMap<Digest32, CompositePublicKey>)> {
389:     let mut d = Decoder::new(bytes);
390:     if d.array()? != 3 {
391:         return Err(Error::MalformedAtRest("anchor meta arity"));
392:     }
393:     if d.uint()? != META_VERSION {
394:         return Err(Error::MalformedAtRest("anchor meta version"));
395:     }
396:     let genesis = Genesis::from_wire(d.bytes()?)?;
397:     let authors = parse_authors(d.bytes()?)?;
398:     d.finish()?;
399:     Ok((genesis, authors))
400: }
401: 
402: /// An anchored copy as a [`crate::log::sync::SessionRoom`]; see `AnchorState::sync_over_room`.
403: struct AnchorSessionRoom<'a> {
404:     shared: &'a tokio::sync::Mutex<AnchorState>,
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
426: impl crate::log::sync::SessionRoom for AnchorSessionRoom<'_> {
427:     fn frontiers(
428:         &self,
429:     ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
430:         Ok(crate::log::sync::frontiers_of(&self.copy()?.dag))
431:     }
432: 
433:     fn wants(
434:         &self,
435:         remote: &[crate::log::sync::FeedFrontier],
436:     ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
437:         Ok(crate::log::sync::wants_for(&self.copy()?.dag, remote))
438:     }
439: 
440:     fn entries(
441:         &self,
442:         wants: &[crate::log::sync::WantRange],
443:     ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
444:         Ok(crate::log::sync::entries_for_wants(
445:             &self.copy()?.dag,
446:             wants,
447:         ))
448:     }
449: 
450:     fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
451:         let mut guard = self.copy()?;
452:         let st = &mut *guard;
453:         let before = st.heads();
454:         let resolver = ChannelAuthors::new(st.authors.clone());
455:         // Absorb what was stored, then report the failure: see `ChannelSessionRoom::apply`.
456:         let stored = crate::log::sync::apply_staged(&mut st.dag, &resolver, &st.admission, &staged);
457:         match st.absorb_arrived(self.store, &before) {
458:             Ok(got) => {
459:                 self.out.borrow_mut().governance += got.governance;
460:                 stored
461:             }
462:             Err(e) => {
463:                 *self.fatal.borrow_mut() = Some(e);
464:                 Err(crate::wire::WireError::TransportFailed)
465:             }
466:         }
467:     }
468: }
[0m
Two central gaps remain: the lower end can finish and open a follow-up while the higher end is still applying the previous session, and QUIC delivery of a notify does not ensure the application retains it until a session starts. I’m checking those cases against the membership, anchor, and frontier code, along with whether the proposed proofs force the claimed event orderings.
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/streams.rs
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs[90m [offset=150, limit=80][0m
[0m✱ [0mGrep "max_concurrent_uni|open_uni|accept_uni|max_concurrent_bidi|pub fn quinn"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport · 1 match[0m
[0m✱ [0mGrep "max_concurrent_uni|open_uni|accept_uni|max_concurrent_bidi|fn range|head_hash|pub fn accept|fork|prun"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log · 23 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=3360, limit=155][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=5165, limit=155][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | python3 -c 'import sys; spans=[(430,541),(575,625),(869,940)]; print("".join(f"{i}: {s}" for i,s in enumerate(sys.stdin,1) if any(a<=i<=b for a,b in spans)))'
430:                 author_id: author,
431:                 max_seq: feed.max_seq(),
432:                 head_hash: feed.head_hash(),
433:             })
434:         })
435:         .collect()
436: }
437: 
438: /// Given the *remote* peer's `HAVE` frontiers and the local [`Dag`], compute the
439: /// `WANT` ranges the local peer needs:
440: /// - for every remote feed whose `max_seq` **exceeds** what we hold, request
441: ///   `(local_max + 1 ..= remote_max)` (the ordinary tail-extension case);
442: /// - **and** — the equal-length fork case — when the remote's `max_seq` **equals**
443: ///   our `max_seq` but its `head_hash` **differs** from ours, request the head
444: ///   `(max_seq ..= max_seq)`. Two partitions each holding `(author, seq = N)` with
445: ///   different valid hashes would otherwise never exchange the conflicting entry
446: ///   and no fork proof would form (ADR-008 §"Fork / equivocation handling"). The
447: ///   pulled conflicting entry is fed into DAG fork handling, which freezes the
448: ///   author on an attributable proof and raises an alarm on a deniable one.
449: #[must_use]
450: pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
451:     let mut wants = Vec::new();
452:     for rf in remote {
453:         let local = dag.feed(&rf.author_id);
454:         let local_max = local.map_or(0, |f| f.max_seq());
455:         if rf.max_seq > local_max {
456:             wants.push(WantRange {
457:                 author_id: rf.author_id,
458:                 from_seq: local_max + 1,
459:                 to_seq: rf.max_seq,
460:             });
461:         } else if rf.max_seq == local_max && local_max > 0 {
462:             // Equal head seq: compare the gossiped head hashes. A mismatch is a
463:             // divergence (equal-length fork) — pull the remote head entry so the
464:             // conflict reaches DAG fork handling.
465:             let local_head = local.map_or(crate::log::entry::ZERO_HASH, |f| f.head_hash());
466:             if local_head != rf.head_hash {
467:                 wants.push(WantRange {
468:                     author_id: rf.author_id,
469:                     from_seq: local_max,
470:                     to_seq: local_max,
471:                 });
472:             }
473:         }
474:     }
475:     wants
476: }
477: 
478: /// Collect the `ENTRY` wire frames satisfying a peer's `WANT` ranges from the
479: /// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
480: /// [`MAX_SERVE_BYTES`].
481: ///
482: /// **The work is bounded by what this node holds, never by the ranges' numbers.**
483: /// This used to loop `from_seq..=to_seq` doing one lookup per number, collecting
484: /// into memory with the room's lock held, so a single `WANT (author, 1,
485: /// u64::MAX)` — any member may send one — pinned a core on a loop that would not
486: /// finish in the life of the machine, and nothing else could touch that room
487: /// again (PRD-001 D2). Now each author's ranges are merged, so duplicates and
488: /// overlaps cost nothing and serve nothing twice, and each merged range walks
489: /// only the entries the feed actually has. Entries not held are simply omitted.
490: #[must_use]
491: pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
492:     let mut out = Vec::new();
493:     let mut bytes = 0usize;
494:     for (author, ranges) in merged_wants(wants) {
495:         let Some(feed) = dag.feed(&author) else {
496:             continue;
497:         };
498:         for (from, to) in ranges {
499:             for entry in feed.range(from, to) {
500:                 let wire = entry.to_wire();
501:                 if !out.is_empty()
502:                     && (out.len() >= MAX_SERVE_ENTRIES
503:                         || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
504:                 {
505:                     return out;
506:                 }
507:                 bytes = bytes.saturating_add(wire.len());
508:                 out.push(wire);
509:             }
510:         }
511:     }
512:     out
513: }
514: 
515: /// A `WANT`'s ranges grouped by author (in author order) with each author's
516: /// ranges sorted and merged, so the ranges are disjoint and ascending. Inverted
517: /// ranges are dropped. The cost is `O(n log n)` in the number of ranges, which
518: /// the frame size already bounds.
519: fn merged_wants(wants: &[WantRange]) -> std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> {
520:     let mut by_author: std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> =
521:         std::collections::BTreeMap::new();
522:     for w in wants.iter().filter(|w| w.from_seq <= w.to_seq) {
523:         by_author
524:             .entry(w.author_id)
525:             .or_default()
526:             .push((w.from_seq, w.to_seq));
527:     }
528:     for ranges in by_author.values_mut() {
529:         ranges.sort_unstable();
530:         let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
531:         for &(from, to) in ranges.iter() {
532:             match merged.last_mut() {
533:                 Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
534:                 _ => merged.push((from, to)),
535:             }
536:         }
537:         *ranges = merged;
538:     }
539:     by_author
540: }
541: 
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
921: ///
922: /// # Errors
923: /// The first hard sync failure.
924: pub fn apply_staged<R: AuthorResolver>(
925:     dag: &mut Dag,
926:     resolver: &R,
927:     admission: &AdmissionPolicy,
928:     staged: &[Vec<u8>],
929: ) -> std::result::Result<usize, WireError> {
930:     let mut stored = 0;
931:     for wire in staged {
932:         if matches!(
933:             apply_entry(dag, resolver, admission, wire)?,
934:             ApplyOutcome::Stored
935:         ) {
936:             stored += 1;
937:         }
938:     }
939:     Ok(stored)
940: }
[0m
[0m✱ [0mGrep "SYNC_NOTIFY|WrongOpener|timers|notify"[90m in docs/adr/ADR-025-sync-scheduling-switch-not-hub.md · 26 matches[0m
[0m✱ [0mGrep "fn learn_members|learn_members\(|async fn adopt_anchored|refresh_anchored_authors|join.*sync|sync.*join"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node · 24 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/feed.rs[90m [offset=30, limit=220][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs[90m [offset=275, limit=115][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=815, limit=130][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/net.rs | python3 -c 'import sys; spans=[(160,215),(710,753),(825,861)]; print("".join(f"{i}: {s}" for i,s in enumerate(sys.stdin,1) if any(a<=i<=b for a,b in spans)))'
160:     }
161: 
162:     /// Whether a peer of `class` may open a `kind` stream.
163:     ///
164:     /// - **Member**: everything. It is in the channel; the log, consent and
165:     ///   render gates (ADR-007/008) govern what it can actually *read*.
166:     /// - **Anchor**: `rendezvous` (the board), `sync` (it replicates ciphertext it
167:     ///   can never read) and `coord` (it relays hole-punch signalling). Never
168:     ///   `join` or `pairwise`: it has no channel authority.
169:     /// - **PendingJoiner**: `join`, `rendezvous` and `pairwise`. ADR-016's Decision
170:     ///   says "for the join stream only", which is one stream too few: the moment a
171:     ///   join completes, the newcomer must deliver its **own** sender key (ADR-007
172:     ///   step 2), and it cannot wait to be reclassified — the responder only admits
173:     ///   it as a member *after* the join's final frame, and the ADR-004 responder
174:     ///   cannot speak first on the new session anyway. Allowing `pairwise` costs
175:     ///   nothing: a sealed message from a peer we hold no session with cannot be
176:     ///   opened and is dropped. Never `sync` (no log authority) and never `tunnel`.
177:     /// - **Unknown**: `rendezvous` only, gated further by the service's own policy
178:     ///   (ADR-012: reads open, member-only writes refused there).
179:     #[must_use]
180:     pub fn allows(class: PeerClass, kind: StreamKind) -> bool {
181:         match class {
182:             PeerClass::Member => true,
183:             PeerClass::Anchor => matches!(
184:                 kind,
185:                 StreamKind::Rendezvous | StreamKind::Sync | StreamKind::Coord | StreamKind::Circuit
186:             ),
187:             PeerClass::PendingJoiner => matches!(
188:                 kind,
189:                 StreamKind::Join
190:                     | StreamKind::Rendezvous
191:                     | StreamKind::Pairwise
192:                     | StreamKind::Coord
193:                     | StreamKind::Circuit
194:             ),
195:             // **Its sender key, and nothing an unknown peer could not already open.** The responder
196:             // releases its key the moment it admits us, which is before this node holds the room
197:             // or knows the responder as a member. Judged as `Unknown`, that pairwise stream was
198:             // refused at accept — `stream refused: peer may not open this stream kind` — while
199:             // the responder counted the write as delivered and never sent it again. So a trusted
200:             // member could never read the first room it joined: measured through the real
201:             // binaries, both members had nothing in the first of two rooms after 90s, 3 runs of 3,
202:             // while the second room — joined when the responder was already a member — worked.
203:             PeerClass::JoinResponder => matches!(
204:                 kind,
205:                 StreamKind::Pairwise | StreamKind::Rendezvous | StreamKind::Coord
206:             ),
207:             // An unknown peer reaches the board — and the coord stream, where the only
208:             // verb open to it is `WHOAMI`, whose answer is its own address (enforced in
209:             // `node::coordstream`). A NATed client cannot learn its reflexive address
210:             // any other way, and this ADR exists for that client.
211:             PeerClass::Unknown => matches!(kind, StreamKind::Rendezvous | StreamKind::Coord),
212:         }
213:     }
214: 
215:     /// The transport admission for a node that does **not** serve rendezvous: only
710: 
711:     /// Close every retired connection whose grace has elapsed (or that the peer
712:     /// already closed). Returns how many were closed. The node's tick calls this.
713:     pub fn retire_expired(&self) -> usize {
714:         let now = (self.clock)();
715:         let mut retiring = lock(&self.retiring);
716:         let before = retiring.len();
717:         retiring.retain(|(conn, at)| {
718:             // **Still carried** means somebody other than this list holds the connection:
719:             // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
720:             // long as they run, so the strong count is the liveness signal, and it needs no
721:             // bookkeeping that could disagree with reality.
722:             //
723:             // The grace alone is not enough to close on. It is sized for a request finishing
724:             // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
725:             // file transfer is in flight for hours. Closing on the timer killed live sessions
726:             // mid-stream whenever a better path displaced the one they were on, which reached
727:             // the person as `Connection reset by peer` in the middle of their work.
728:             let still_carried = Arc::strong_count(conn) > 1;
729:             if (now >= *at && !still_carried) || !is_live(conn) {
730:                 conn.close(WireError::AuthenticatorInvalid);
731:                 false
732:             } else {
733:                 true
734:             }
735:         });
736:         before - retiring.len()
737:     }
738: 
739:     /// Retire `conn` as [`Self::file`] would when a better path displaces it. For proofs of
740:     /// the retirement rule, which otherwise needs two real paths to the same peer.
741:     #[doc(hidden)]
742:     pub fn retire_for_test(&self, conn: &Arc<VoxConnection>) {
743:         // Exactly what `file` does: the displaced connection leaves the per-peer map and
744:         // moves to the retiring list. Leaving it in the map would keep a reference of the
745:         // manager's own, which is not what "still carried" means.
746:         lock(&self.conns).retain(|_, c| !Arc::ptr_eq(c, conn));
747:         let at = (self.clock)().saturating_add(self.retire_grace_secs);
748:         lock(&self.retiring).push((Arc::clone(conn), at));
749:     }
750: 
751:     /// How many displaced connections are still within their grace.
752:     #[must_use]
753:     pub fn retiring_count(&self) -> usize {
825: fn is_live(conn: &VoxConnection) -> bool {
826:     conn.quinn().close_reason().is_none()
827: }
828: 
829: /// What filing one connection decided: which one is the peer's primary, and whether a duplicate was
830: /// retired rather than closed and so still needs reading.
831: pub struct Filed {
832:     /// The connection that is now this peer's primary.
833:     pub kept: Arc<VoxConnection>,
834:     /// A duplicate that was retired rather than closed, and still needs reading for its grace.
835:     pub also_serve: Option<Arc<VoxConnection>>,
836: }
837: 
838: /// Accept the next stream on `conn` and authorize it against `policy`: the peer's
839: /// class must be allowed to open that kind, or the stream is reset with the coded
840: /// rejection and [`Error::StreamRefused`] is returned (see the module docs).
841: pub async fn accept_authorized(
842:     conn: &VoxConnection,
843:     policy: &PeerPolicy,
844: ) -> Result<(StreamKind, SendStream, RecvStream)> {
845:     let (kind, mut send, mut recv) = accept_typed(conn).await?;
846:     let class = policy.classify(&conn.peer_id());
847:     if !PeerPolicy::allows(class, kind) {
848:         refuse_stream(&mut send, &mut recv);
849:         return Err(Error::StreamRefused("peer may not open this stream kind"));
850:     }
851:     Ok((kind, send, recv))
852: }
853: 
854: /// Reset both halves of a stream with the coded rejection — the same code an
855: /// unauthenticated peer gets, so probing stream kinds reveals nothing.
856: pub fn refuse_stream(send: &mut SendStream, recv: &mut RecvStream) {
857:     let code = close_code(WireError::AuthenticatorInvalid);
858:     let _ = send.reset(code);
859:     let _ = recv.stop(code);
860: }
[0m
[0m$ [0mgh issue list --repo robertelee78/vox --state all --search '"V210-34"' --json number,title,body --limit 10
[]
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs[90m [offset=20, limit=145][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/circuitstream.rs[90m [offset=1, limit=60][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=728, limit=70][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=770, limit=160][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 diff 58fde36 8436100 -- crates/vox-core/src/log/feed.rs crates/vox-core/src/log/dag.rs crates/vox-core/src/transport/streams.rs
(no output)
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | python3 -c 'import sys; spans=[(2720,2855),(3090,3185),(4120,4235),(4360,4405)]; print("".join(f"{i}: {s}" for i,s in enumerate(sys.stdin,1) if any(a<=i<=b for a,b in spans)))'
2720:     /// The next board-record sequence number for `channel_id`: strictly above the last one this
2721:     /// process used, and never below the clock in milliseconds.
2722:     ///
2723:     /// **It must keep rising across a restart**, because a board accepts only a higher `seq` from
2724:     /// the same author (`non-increasing seq (replay)`). The counter started again at 1 in every
2725:     /// process, so after a restart every record this node published was older than the one the
2726:     /// board already held, and was refused. A member that restarted could not be reached at its
2727:     /// new address. vox-bc's causal-order proof measured it: the second joiner, restarted, logged
2728:     /// `a board would not take our address … the board holds a newer record from that author`,
2729:     /// and failed 5 of 9. The clock is what survives a restart without a store write per publish.
2730:     fn next_record_seq(&mut self, channel_id: &Digest32) -> u64 {
2731:         let floor = (self.millis_clock)();
2732:         let entry = self.record_seq.entry(*channel_id).or_insert(0);
2733:         *entry = entry.saturating_add(1).max(floor);
2734:         *entry
2735:     }
2736: 
2737:     /// The store anchored logs and channels live in: the profile's, or the headless
2738:     /// node's own.
2739:     fn log_store(&self) -> Option<Arc<crate::node::store::Store>> {
2740:         self.profile
2741:             .as_ref()
2742:             .map(Profile::store_handle)
2743:             .or_else(|| self.anchor_store.as_ref().map(Arc::clone))
2744:     }
2745: 
2746:     /// The sealing key for the anchor's copy of `channel_id`: derived from whichever
2747:     /// identity this node networks as.
2748:     fn anchor_sek(&self, channel_id: &Digest32) -> Option<crate::atrest::sek::Sek> {
2749:         if let Some(signer) = self.headless.as_ref() {
2750:             return crate::node::anchor::anchor_sek(&**signer, channel_id).ok();
2751:         }
2752:         let profile = self.profile.as_ref()?;
2753:         let signer = profile.signer().ok()?;
2754:         crate::node::anchor::anchor_sek(signer, channel_id).ok()
2755:     }
2756: 
2757:     /// Start keeping a log for `channel_id` if this node anchors logs, its board holds
2758:     /// the genesis, and it is neither a member of the channel nor already keeping it.
2759:     /// Reopens a copy the store already has (a restart), else creates one.
2760:     async fn adopt_anchored(&mut self, channel_id: &Digest32) {
2761:         if !self.anchor_logs
2762:             || self.channels.contains_key(channel_id)
2763:             || self.anchored.contains_key(channel_id)
2764:         {
2765:             return;
2766:         }
2767:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
2768:             return;
2769:         };
2770:         let Some(genesis) = net.board_genesis(channel_id) else {
2771:             return;
2772:         };
2773:         let (Some(store), Some(sek)) = (self.log_store(), self.anchor_sek(channel_id)) else {
2774:             return;
2775:         };
2776:         let now = self.now();
2777:         let opened =
2778:             crate::node::anchor::AnchorState::open(&store, sek, channel_id).or_else(|_| {
2779:                 let sek = self
2780:                     .anchor_sek(channel_id)
2781:                     .ok_or(Error::Profile("no anchor key"))?;
2782:                 crate::node::anchor::AnchorState::create(&store, sek, &genesis, now)
2783:             });
2784:         if let Ok(state) = opened {
2785:             self.anchored
2786:                 .insert(*channel_id, Arc::new(tokio::sync::Mutex::new(state)));
2787:             self.refresh_anchored_authors(channel_id).await;
2788:             self.refresh_network_view().await;
2789:         }
2790:     }
2791: 
2792:     /// Adopt every channel the board holds a genesis for (the tick's pass).
2793:     async fn adopt_anchored_from_board(&mut self) {
2794:         if !self.anchor_logs {
2795:             return;
2796:         }
2797:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
2798:             return;
2799:         };
2800:         let ids: Vec<Digest32> = net
2801:             .anchored_channels()
2802:             .into_iter()
2803:             .map(|a| a.channel_id)
2804:             .filter(|cid| !self.channels.contains_key(cid) && !self.anchored.contains_key(cid))
2805:             .collect();
2806:         for cid in ids {
2807:             self.adopt_anchored(&cid).await;
2808:         }
2809:     }
2810: 
2811:     /// Admit into an anchored channel every author its board knows (the creator, and
2812:     /// everyone a member vouched for), so their entries verify.
2813:     async fn refresh_anchored_authors(&mut self, channel_id: &Digest32) {
2814:         let (Some(net), Some(state), Some(store)) = (
2815:             self.net.as_ref().map(Arc::clone),
2816:             self.anchored.get(channel_id).map(Arc::clone),
2817:             self.log_store(),
2818:         ) else {
2819:             return;
2820:         };
2821:         let keys = net.board_member_keys(channel_id, 0);
2822:         let added = state.lock().await.admit_authors(&store, keys).unwrap_or(0);
2823:         if added > 0 {
2824:             self.refresh_network_view().await;
2825:         }
2826:     }
2827: 
2828:     /// After a restart, reopen every anchored channel the store holds and put its
2829:     /// genesis back on the board, so members find the room where they left it.
2830:     fn reopen_anchored(&mut self) -> crate::error::Result<()> {
2831:         if !self.anchor_logs {
2832:             return Ok(());
2833:         }
2834:         let (Some(store), Some(net)) = (self.log_store(), self.net.as_ref().map(Arc::clone)) else {
2835:             return Ok(());
2836:         };
2837:         for cid in store.anchored_channels()? {
2838:             let Some(sek) = self.anchor_sek(&cid) else {
2839:                 continue;
2840:             };
2841:             if let Ok(state) = crate::node::anchor::AnchorState::open(&store, sek, &cid) {
2842:                 let _ = net.publish_local(&state.genesis().to_wire());
2843:                 self.anchored
2844:                     .insert(cid, Arc::new(tokio::sync::Mutex::new(state)));
2845:             }
2846:         }
2847:         Ok(())
2848:     }
2849: 
2850:     /// Dial any configured or learned anchor this node is not connected to. Runs on
2851:     /// the tick, throttled: an anchor that restarted, or a link that dropped, is
2852:     /// re-established without anyone noticing.
2853:     fn redial_anchors_if_due(&mut self) {
2854:         let now = self.now();
2855:         if now < self.redial_anchors_at {
3090:                 identity,
3091:                 ack,
3092:             } => {
3093:                 // The join proved this identity; admit it as an author so its entries — and its
3094:                 // records on this node's board — are accepted. Reading still needs consent.
3095:                 let now = self.now();
3096:                 if let (Some(profile), Some(shared)) = (
3097:                     self.profile.as_ref(),
3098:                     self.channels.get(&channel_id).map(Arc::clone),
3099:                 ) {
3100:                     let _ = shared
3101:                         .lock()
3102:                         .await
3103:                         .admit_author(profile.store(), &identity, now);
3104:                 }
3105:                 // Answered whatever happened: a joiner waiting on this must not be left holding a
3106:                 // stream because the room closed or this node has no profile. It will find out from
3107:                 // the join's own outcome, which is the right place for it to learn.
3108:                 let _ = ack.send(());
3109:             }
3110:             NetEvent::Dialed {
3111:                 conn,
3112:                 endpoints,
3113:                 board,
3114:             } => {
3115:                 let peer = conn.peer_id();
3116:                 self.adopt_connection(Arc::clone(&conn));
3117:                 if let Some(net) = self.net.as_ref().map(Arc::clone) {
3118:                     if crate::node::net::path_class(net.manager().endpoint(), &conn)
3119:                         == crate::node::net::PathClass::Relayed
3120:                     {
3121:                         let tx = self.net_tx.clone();
3122:                         self.last_upgrade.insert(peer, self.now());
3123:                         tokio::spawn(async move {
3124:                             match net.upgrade(peer, &endpoints).await {
3125:                                 Ok(better) => {
3126:                                     let _ = tx.send(NetEvent::BetterPath { conn: better }).await;
3127:                                 }
3128:                                 Err(crate::error::Error::LadderExhausted(reason)) => {
3129:                                     let _ = tx.send(NetEvent::UpgradeFailed { peer, reason }).await;
3130:                                 }
3131:                                 Err(_) => {}
3132:                             }
3133:                         });
3134:                     }
3135:                 }
3136:                 if board {
3137:                     self.anchor_ids.insert(peer);
3138:                     self.refresh_network_view().await;
3139:                 }
3140:                 // Whatever this member is owed goes out now that it can be reached, rather than on
3141:                 // the next tick: a dial `reach_member` started was started for exactly this.
3142:                 self.answer_pending_consents(|_, target| *target == peer, None)
3143:                     .await;
3144:                 self.deliver_owed_rekeys().await;
3145:                 self.deliver_owed_consents(None).await;
3146:             }
3147:             NetEvent::JoinerDone {
3148:                 reply,
3149:                 parsed,
3150:                 local_name,
3151:                 passphrase,
3152:                 now,
3153:                 me,
3154:                 result,
3155:             } => {
3156:                 let room = parsed.channel_id;
3157:                 let outcome = match *result {
3158:                     Ok(won) => {
3159:                         let _ = self.event_tx.send(NodeEvent::JoinSteps {
3160:                             joined: true,
3161:                             steps: won.steps.render(),
3162:                         });
3163:                         self.finish_join_channel(*parsed, local_name, passphrase, now, me, won)
3164:                             .await
3165:                     }
3166:                     Err(lost) => {
3167:                         let _ = self.event_tx.send(NodeEvent::JoinSteps {
3168:                             joined: false,
3169:                             steps: lost.steps.render(),
3170:                         });
3171:                         if !lost.why.is_empty() {
3172:                             self.say_why_the_join_failed(&lost.why);
3173:                         }
3174:                         Outcome::Failed(lost.fault)
3175:                     }
3176:                 };
3177:                 // Whatever arrived for this room while it was being joined, in arrival order — into
3178:                 // the room if the join made one, or discarded as before if it did not.
3179:                 self.joining.remove(&room);
3180:                 if self.joining.is_empty() {
3181:                     if let Some(net) = self.net.as_ref() {
3182:                         net.policy().forget_join_responders();
3183:                     }
3184:                 }
3185:                 let (held, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held_pairwise)
4120:                 sealed,
4121:             ) {
4122:                 Ok(c) => c,
4123:                 Err(e) => return Outcome::Failed(fault_of(&e)),
4124:             }
4125:         };
4126:         self.channels.insert(
4127:             parsed.channel_id,
4128:             Arc::new(tokio::sync::Mutex::new(channel)),
4129:         );
4130:         // Keep the responder's witness to this join (M17.6). It is republished with
4131:         // every bundle record this node ever puts on a board for this room, so it is
4132:         // persisted rather than held: a node that lost it could publish nothing and
4133:         // would fall off every board. The joiner already verified it binds its own key,
4134:         // this room and this epoch, in `run_initiator`.
4135:         if let (Some(profile), Some(shared)) = (
4136:             self.profile.as_ref(),
4137:             self.channels.get(&parsed.channel_id).map(Arc::clone),
4138:         ) {
4139:             let admission =
4140:                 crate::nat::record::Admission::Witnessed(Box::new(joined.witness.clone()));
4141:             if let Err(e) = shared
4142:                 .lock()
4143:                 .await
4144:                 .set_own_admission(profile.store(), admission)
4145:             {
4146:                 return Outcome::Failed(fault_of(&e));
4147:             }
4148:         }
4149:         // Every member whose bundle is on the board is an admitted author **on the
4150:         // M17.6 evidence its record carries** — a self-signed record proves possession
4151:         // of a key and nothing else. Sync hard-fails on an entry from an author we
4152:         // never admitted, so this is what makes the log reconcilable at all.
4153:         if let (Some(profile), Some(shared)) = (
4154:             self.profile.as_ref(),
4155:             self.channels.get(&parsed.channel_id).map(Arc::clone),
4156:         ) {
4157:             // Same rule as `learn_members`: evidence, not relay (M17.6). The
4158:             // responder's own board is no more trustworthy than any other — it is
4159:             // where a joiner first looks, which makes it the *first* place a
4160:             // compromised member would seed keys.
4161:             let mut channel = shared.lock().await;
4162:             let _ = admit_board_records(
4163:                 &mut channel,
4164:                 profile.store(),
4165:                 &set.bundles,
4166:                 ChannelState::MAX_ADMISSIONS_PER_SWEEP,
4167:                 now,
4168:             )
4169:             .await;
4170:         }
4171:         // An admission changes a room's author set, the other half of the reacher join.
4172:         self.refresh_reachers().await;
4173:         self.adopt_join_session(parsed.channel_id, responder, joined.session, true)
4174:             .await;
4175:         // The link's anchors are this channel's anchors from now on (persisted, so a
4176:         // restart still knows where the swarm's board is), together with our own.
4177:         let mut learned = BootstrapSet::new();
4178:         for a in parsed.anchors.iter().filter(|a| a.id != me) {
4179:             let _ = learned.add(a.clone());
4180:         }
4181:         // `merge_endpoints`, not `merge`: the link's anchors went in first, so with
4182:         // keep-first semantics a link minted before the anchor moved would win and this
4183:         // node's freshly resolved address for the same identity would be discarded —
4184:         // the joiner would adopt the stale address and keep it.
4185:         let _ = learned.merge_endpoints(&self.anchors);
4186:         self.adopt_channel_anchors(&parsed.channel_id, Some(&learned))
4187:             .await;
4188:         self.refresh_network_view().await;
4189:         self.publish_channel_locally(&parsed.channel_id).await;
4190:         // And on every anchor we hold, so every other member can find our key and
4191:         // admit us as a log author (without which their sync sessions fail).
4192:         self.publish_channel_to_anchors(&parsed.channel_id).await;
4193:         if !self.anchor_ids.contains(&conn.peer_id()) {
4194:             self.publish_channel_to_anchor(&parsed.channel_id, &conn)
4195:                 .await;
4196:         }
4197:         // **Joining releases no sender key** (M17.6). This is the correction to
4198:         // ADR-007 step 2, which read "the newcomer announces its own sender key … it
4199:         // has nothing to consent over". It does: it decides which members may read it,
4200:         // per member, exactly as they each decide about it. Releasing automatically
4201:         // made that decision for it, and made it in favour of whichever member happened
4202:         // to answer the join — a member chosen from the board, so influenceable by
4203:         // whoever supplied the link. Under ADR-017 decision 3 that consent also carries
4204:         // service reach, so an automatic grant here handed a service to a party no
4205:         // human approved.
4206:         //
4207:         // The stated reason for releasing here does not require it: the ADR-004
4208:         // responder needs the initiator's first message, which is the PQXDH
4209:         // `InitialMessage` the join already sent, not the SKDM. `ensure_session` builds
4210:         // a session from a board bundle record alone, and the SKDM rides over it.
4211:         //
4212:         // What *is* still required is one ratchet message, and it carries nothing. A
4213:         // PQXDH responder starts with no chains — `Ratchet::init_responder`: "with no
4214:         // chains yet — they are established when the first inbound message triggers a
4215:         // DH ratchet step" — and the join's `InitialMessage` creates the session
4216:         // without delivering a message, so until the joiner speaks over it the
4217:         // responder cannot send at all. That need is real and is what the old comment
4218:         // was pointing at; meeting it with a *sender key* is what made it a grant.
4219:         // `PairwiseFrame::Open` meets it with an empty plaintext.
4220:         // The ratchet message that opens the responder's sending direction rides the
4221:         // **join stream itself** (`JoinFrame::Open`), so the responder has processed it
4222:         // before the join returns. Sending it afterwards on a separate stream was a
4223:         // race: `Consent` immediately after a join would find no sending chain and fail,
4224:         // and only luck decided whether it did.
4225:         // Nothing else replaces the release. A joiner becomes readable when it trusts
4226:         // someone, which is a human act, and `deliver_owed_consents` issues the grant.
4227:         let _ = self.event_tx.send(NodeEvent::Joined {
4228:             channel_id: parsed.channel_id,
4229:             responder,
4230:         });
4231:         Outcome::Done
4232:     }
4233: 
4234:     /// Release this identity's sender key to `target` and record the grant: deliver
4235:     /// the SKDM over the pairwise session, then append the ADR-007 consent grant
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
4401:     /// Consent to `target` reading this identity's messages — ADR-007 step 3, the
4402:     /// human decision, taken per sender.
4403:     async fn consent(&mut self, channel_id: &Digest32, target: Digest32, asked: bool) -> Outcome {
4404:         let outcome = self.release_key_to(channel_id, target, asked).await;
4405:         if outcome.is_done() {
[0m
**BLOCK.** Revision 2 removes symmetric initiation, but does not establish collision-free session turnover or reliable consumption of reconciliation requests.

Reviewed ADR HEAD `16951fe`, the three round-1 reviews, `58fde36`, and the unchanged `8436100` working tree. No edits, builds, or tests performed.

**Citation key:** `ADR` means `docs/adr/ADR-025-sync-scheduling-switch-not-hub.md`; `180:` and `202:` mean commits `58fde36` and `8436100`. Code paths below are relative to `crates/vox-core/src/`.

## BLOCKER

### 1. One designated opener does not guarantee one unfinished session

D4 retains “serves the inbound session as today,” while D3 immediately schedules a follow-up when necessary (ADR:227,249–252). This permits:

1. L serves entries and sends FIN.
2. H sends its own FIN, then continues applying L’s entries.
3. L finishes its empty receive direction and processes `SyncDone`.
4. A post after L’s HAVE—or a pending notify—makes L open another session.
5. H is still running the previous session.

This ordering follows directly from FIN preceding application: `180:log/sync.rs:886–916`. H’s existing pair guard refuses the next session: `180:node/actor.rs:5260–5263`; #202 supplies the `SessionBusy` reason: `202:node/actor.rs:5226–5240`.

Thus, **correct nodes can still receive busy refusals**, without either violating the designated-opener rule. Removing H’s guard instead permits overlapping inbound sessions and restores the token/ownership problem. Tokens alone do not prevent that overlap.

**Required:** specify receiver-ready turnover: a post-apply/release acknowledgement, deferred admission of the next session, or another explicit protocol mechanism. Account for the actor processing completion later than the worker. Until then, “collisions impossible,” “exactly one,” and P1/P6’s zero-busy assertion are unsupported.

### 2. `owed` plus “one outstanding notify” is not a complete work lifecycle

ADR:169–175 contains no outstanding-notify state. ADR:205–210 and 223–230 never define precisely when `owed` is consumed, when notify suppression clears, or which requests a completion satisfies.

Critical cases:

- **Notify during Running:** consume only requests covered by that attempt; preserve notifications arriving afterward. Clearing `owed` unconditionally at completion loses work; never clearing it loops forever. The workqueue analogy does not specify the transition.
- **Notify during Backoff:** retain the request and arrange an independent wakeup at expiry. D5 gives an `until` but no expiry transition; the options table incorrectly says no timers except the periodic tick (ADR:147,288–298).
- **Rejected/reset notify on a live connection:** QUIC reliability does not imply application admission, nor that a stream cannot fail while its connection survives. D4 itself intentionally drops unauthorized notifications. An outstanding notification can consequently suppress every subsequent attempt without any session starting.
- **Manual sync on H cannot implement D5’s override:** `{room, epoch}` is indistinguishable from an ordinary notification. L must honor its active backoff, yet ADR:297–298 promises that a person’s sync bypasses it.
- **Epoch/reconnection:** setting `owed` is insufficient without invalidating old attempt results and outstanding-notify suppression. Define connection incarnation, epoch, request coverage, and token invalidation together.

The shipped outbound stream opener already bounds waiting for stream credit because an otherwise-live connection can grant no stream indefinitely (`202:transport/quic.rs:764–781`). The new unidirectional path needs equivalent bounded opening/writing and explicit failure handling.

**Required:** a transition table covering request arrival, admission, Running, Backoff expiry, notify failure, reconnect, epoch replacement, and completion. Requests need a captured generation—or equally precise consume-at-start semantics—independent of content generation.

## MAJOR

### 3. D3’s arithmetic is computable; its claimed completeness is too strong

**Ordinary frontier counting is feasible.** Retain the exact local WANT alongside `remote_have`; currently WANT is computed inline and discarded (`180:log/sync.rs:880–884`). Feeds contain one canonical entry per sequence and enforce contiguous appends (`202:log/feed.rs:102–113,195–202,226–229`). Therefore normalized, HAVE-clamped inclusive ranges provide an expected count.

**Equal-sequence forks do not inherently invalidate that count.** `wants_for` asks for exactly one conflicting head, `(N,N)` (`180:log/sync.rs:450–475`). Receiving it counts as one even though application returns `Fork`, not `Stored` (`180:log/sync.rs:577–620`). Counting `applied` instead of received entries would be wrong.

But two gaps remain:

- **Aggregate count is not coverage.** A faulty or malicious member can substitute a valid duplicate for a requested entry. Duplicate application is nonfatal (`202:log/dag.rs:317–320`), and the receive loop currently checks neither WANT membership nor unique requested positions (`180:log/sync.rs:899–914`). Expected count, received count, and successful applies can all agree while requested data is missing. Neither proposed completion check detects that omission. For equal-head exchange, also verify the requested advertised head, not merely its sequence.
- **“Permanent refusals count as received” does not ensure progress.** Consider a sorted serve whose first 1,024 entries belong to a permanently refused author, followed by needed acceptable entries. If refusals do not advance any satisfied-request state, the next WANT is identical; the same bounded prefix is served repeatedly. WANT derives from the DAG, and serving proceeds in merged author/range order (`180:log/sync.rs:450–475,491–539`). A counter alone cannot implement ADR:232–234’s promise against endless retry.

Specify distinct outcomes: stored, duplicate, fork handled, permanently excluded, temporarily unadmitted, and persistence failure. Preserve partial progress and define how terminal exclusions affect subsequent WANTs.

For **honest contiguous feeds, matched entries, unchanged epoch, and successful persistence**, I found no additional invisible truncation: receiving fewer requested entries exposes it. A remote-apply acknowledgement is not necessary solely for retry liveness if the receiver reliably retains and communicates its own failure. That condition is precisely what finding 2 leaves unspecified.

### 4. Anchors, membership preparation, commands, and capacity need explicit paths

**Anchors as L:** the current inbound path adopts a just-published anchored room and refreshes its authors **before** checking membership (`180:node/actor.rs:5265–5293`). `may_sync` alone does neither for an unknown anchored room; it returns false (`180:node/actor.rs:5349–5352`). D4’s notify handler therefore omits preparation required by its claimed “same membership rule.” Retain adoption and author refresh, and schedule newly materialized ports immediately.

**H’s failed apply:** today, outbound setup fetches the peer’s board and admits authors (`180:node/actor.rs:5033–5089`); inbound `start_session` directly runs reconciliation (`180:node/actor.rs:5148–5197`). Under A, H never takes the outbound preparation path. “`learn_members` runs first” must become specified inbound/retry work, including board retrieval and publication ordering—not merely another notify. Exercise both anchor roles and both joining-member orientations.

**Commands and consent retries:** existing `sync_channel` returns `Done` after starting at least one task; it does not await successful reconciliation (`180:node/actor.rs:5202–5223`; `202:node/actor.rs:5168–5189`). Session-correlated command waiters and their deadlines are new work. Existing `SyncDone` also retries consents by **room**, not exact target/token (`180:node/actor.rs:3373–3380,4362–4393`). Revision 2 has not fully answered round 1’s attribution concern.

**NAT/relay:** identity ordering does not require L to accept a fresh network connection. Once an end-to-end QUIC connection exists, stream initiation is independent of who dialed it; Vox’s relay carries the endpoints’ QUIC packets (`202:node/circuitstream.rs:4–11`). I found no NAT-specific prohibition. But “can always open” is too strong: credit and stream failure still apply. The current typed-stream implementation accepts only bidirectional streams; the uni accept/authorization path is new work (`202:transport/streams.rs:81–111`).

**Sixteen slots:** FIFO and tail requeue prevent overtaking; they do not guarantee prompt service. An L responsible for many peers can occupy all 16 outbound slots with stalled sessions while a live seventeenth peer’s notify waits. Outbound tasks retain the permit through preparation and reconciliation (`180:node/actor.rs:5023–5032,5117–5142`); frame waits allow 20 seconds (`202:transport/stream_transport.rs:20–29,88–115`). This is not necessarily tick dependence, but it defeats an unconditional short delivery bound. P2’s two-member/many-room case does not cover it.

### 5. Notify coalescing is not an amplification bound

“At most one session per port at a time” limits concurrency, not work rate (ADR:260–261). A member can continuously notify during Running, keeping one follow-up owed forever; many rooms can fill L’s queue.

Specify bounded parsing, authorization before port allocation, scheduling fairness across peers, and how redundant notifications are suppressed without discarding genuine requests. This is authenticated resource amplification, not unauthenticated reflection.

For **non-members**, exact per-room `may_sync` checking is the relevant protection; membership in another room must not suffice (`180:node/actor.rs:5304–5352`). Apply #202’s disclosure discipline to `WrongOpener` too (`202:node/actor.rs:5302–5312`). Silence alone is not a proof of “no oracle”: an authorized notify intentionally causes an observable reverse session. State the narrower unauthorized-prober guarantee.

### 6. The rebuilt proof table still does not establish mutant discrimination

These are design assessments, not executed results.

| Proof | Remaining problem; base-red assessment |
|---|---|
| **P1** | `opened ≤ rounds + 2` can reject A itself: barrier-synchronized CLI calls do not ensure both posts precede both HAVEs; legitimate post-HAVE work requires another session. Anchor propagation also changes generation. Distinguish unauthorized parallel initiation from justified follow-ups. Base busy refusals are plausible, but the proposed gate has not been measured. |
| **P2** | Single-direction posting removes one rescue, not all. Twenty-four CLI posts do not establish simultaneous occupation of 16 slots; later appends re-mark schedules, and received entries trigger reverse synchronization (`180:node/actor.rs:4730–4740,3450–3453`). Require observed saturation, an actually waiting port, and isolated replication paths. **“Yes: ~30 s” is not established for this harness.** |
| **P3** | “To be measured” is honest. The double mutant addresses the old `applied > 0` rescue, but independent connect/anchor sessions can still mask it. Cover both opener orientations, byte/time truncation, and zero-progress truncation—not only 3,000 small entries. |
| **P4** | “Immediately serves before Bob admits Carol” is an ordering assertion, not a reproducible setup. Require binary evidence of the actual refusal, followed by retry and acceptance; exclude another successful path. Otherwise removing the refuser’s `owed` can remain green. Base status is honestly unknown. |
| **P5** | Base-green labeling is correct. “Many posts during one session” still does not prove a store occurred **after HAVE** and was absent from that attempt’s transfer. Counts alone do not expose that boundary. |
| **P6** | Zero-busy is consistent with A’s intention, but not its specified turnover—finding 1. Historical collision counts support an expectation, not a measured result for this revised gate. |
| **P7** | Killing mid-session does not force the survivor to process an old completion **after installing a replacement token**. Aggregate counter consistency cannot establish stale-token rejection. Force and observe that ordering in the surviving binary. Base status is honestly unknown. |
| **#202 replacement** | Naming a real failure is insufficiently specified to preserve both old mutation checks. Name the new refusal-reason mutant and malformed-governance-wrapper mutant, and verify the affected pair and reason. |

Missing decisive binary scenarios: Running/Backoff notifications; failed uni open on a live connection; unchanged-generation requests; H-side manual sync/consent; epoch change; both anchor roles; partial apply followed by forwarding despite failure; sustained FIFO load; and slow-peer saturation at a designated opener.

ADR:356’s blanket “not provable” claim is also unjustified. A notify-dropping **mutant of the real binary** can exercise recovery. Whether production interfaces can establish the necessary preconditions must be investigated, not categorically dismissed.

### Round-1 disposition

“Resolved” here means resolved **in the proposed design**, not implemented.

| Astra finding | Revision-2 disposition |
|---|---|
| **1 — D3: truncation, remote apply, partial progress, atomic HAVE** | **PARTIAL.** Atomic capture and partial-progress requirements are stated; local versus remote knowledge is corrected. Coverage/exclusion semantics and reliable retry remain incomplete—findings 2–3. |
| **2 — session attribution and destructive completions** | **PARTIAL.** Tokens and removal of symmetric initiation address losing-outbound races; turnover, replacement, and consent attribution remain. |
| **3 — non-content triggers** | **PARTIAL.** `owed` represents them, but consumption/reset semantics are missing. |
| **4 — AWAIT_KEEPER meaning/deadline** | **RESOLVED.** That mechanism is removed. New notify/backoff lifecycle problems are separate. |
| **5 — proof validity and missing scenarios** | **PARTIAL.** See proof audit. |
| **6 — capacity semantics and FIFO** | **RESOLVED.** Outbound-only slots, tail requeue, and backoff precedence are explicit. Short-latency coverage remains missing. |
| **7 — context claims** | **PARTIAL.** Mechanism descriptions are corrected; several citations still reference the wrong tree’s lines. |
| **8 — baseline, persistent-stream comparison, release rationale** | **PARTIAL.** Removed helper and comparison are corrected; D3’s proposed defect fix still lacks decisive proof. |
| **9 — alternatives** | **RESOLVED.** A/B/C and persistent-stream deferral are explicitly compared. Session-count claims remain under finding 6. |

| GLM finding | Revision-2 disposition |
|---|---|
| **B1 — proof table** | **PARTIAL.** P5 labeling and intended P6 semantics are repaired; discrimination remains unestablished. |
| **M1 — completion observability** | **PARTIAL.** Receive-side observation replaces unsupported remote knowledge, but needs finding 3’s qualifications. |
| **M2 — overlapping session state** | **PARTIAL.** Old glare ordering is removed; session turnover/replacement remains incomplete. |
| **M3 — removed `room_in_session`** | **RESOLVED.** False retention claim removed. |
| **M4 — selective skip quotation** | **RESOLVED.** Full argument and queued-port recheck are present. GLM’s claim of guaranteed prompt baseline recovery was itself incorrect; `due()` still gates it (`180:node/actor.rs:4801,4933–4956`; `node/syncstream.rs:93–113`). |
| **M5 — alternatives** | **RESOLVED.** Duplicate work is now limited to glare; designated opener is considered. |
| **m1 — overstated lost-update claim; m2 — identifier-order wording; m3 — AWAIT timing** | **RESOLVED.** Recovery is acknowledged, ordering is explicit, and AWAIT is removed. |
| **m4 — missing backlog/restart/fairness proofs** | **PARTIAL.** Backlog/restart rows added; fairness and causal ordering still absent. |
| **m5 — remaining interleavings/restart caveat** | **PARTIAL.** Old glare cases are superseded; restart transitions still need specification. |
| **m6 — scope/redundant `dirty_gen`** | **RESOLVED.** Scope distinguishes defects from improvement; redundant field removed. |
| **Nits — citation, unconditional carriage, re-owing source peer** | **PARTIAL / RESOLVED / RESOLVED**, respectively. Citations remain inaccurate; carriage is qualified; D2’s conservative source-peer exception is sound under the condition below. |

| Kimi finding | Revision-2 disposition |
|---|---|
| **M1 — attribution/state representation** | **PARTIAL.** Same unresolved turnover/replacement boundary. |
| **M2 — failed inbound on clean port** | **PARTIAL.** Failure explicitly sets `owed`; notify and inbound membership-preparation paths are incomplete. |
| **M2b — truncation signal** | **PARTIAL.** S1 adds receive completeness, but coverage and permanent-exclusion progress need definition. |
| **M3 — proof table** | **PARTIAL.** See audit. |
| **m1 — removed helper; m2 — wrong baseline; m3 — AWAIT; m4/m5 — alternatives** | **RESOLVED.** The conceptual baseline is now explicitly #180; individual citation errors remain below. |
| **n1 — “pushed means started” line** | **NOT RESOLVED.** Revision 2 still gives #202’s line rather than #180’s. |
| **n2 — universal refusal claim; n3 — omitted maps** | **RESOLVED.** Policy refusals remain explicit; migration includes both fields. |
| **n4 — epoch semantics** | **PARTIAL.** “Reset owed” does not define generation reset or invalidate old completions/notifies. |
| **n5 — #202 mutation coverage** | **PARTIAL.** Replacement is promised without explicit replacement mutants. |
| **n6 — late second-session wording; n7 — measurement provenance** | **RESOLVED.** Old row removed; measurements identified as external harness results. |

## MINOR

### 7. D2 is conservative and sound only with an exact atomic condition

Do not invent a concurrent-generation loss here: D2 explicitly falls back to re-owing P if another source intervenes.

Make its condition precise:

- Let `gH` be the generation captured with HAVE.
- Let `nP` count this attempt’s newly stored entries from P.
- Credit through `gH + nP` only if the current generation equals that value, checked atomically in the same epoch.
- Otherwise retain the uncovered generation/request.
- Never use that optimization to erase failure, truncation, or later explicit requests.

The check must span **HAVE through completion**, not merely the apply batch. Existing protocol steps acquire separate locks, allowing other sessions to interleave (`180:node/channel.rs:2678–2705`). Equal-sequence forks and duplicates are not newly stored entries (`180:log/sync.rs:924–939`).

### 8. Several “58fde36” citations are actually from other trees

Examples:

- Skip: **`180:node/actor.rs:5023–5024`**, not 5010–5011.
- Unconditional `note_synced`: **4933–4934**, not 4920–4921.
- “Pushed means started”: **4983–4984**, not 4970–4971.
- Running-marker wedge: **5095–5098**, not 5060–5063.
- `SyncOutcome`: **`180:node/channel.rs:218–227`**, not 211–219.
- Network-identity comparison at actor:3447 is **`202:`**.
- The restart-probe discussion at net:727 onward is **`202:`**; `180:node/net.rs:727–744` concerns retirement, not that probe.

The ADR explicitly labels implementation as proposed. I found no wholesale claim that D1–D7 are built. The misleading current-tree claim is the inherited command-completion behavior discussed above.

## NIT

- Change “exactly one” to **“at most one”**, after fixing turnover.
- Define whether counters are endpoint-local or pair-aggregated. `opened = completed + failed` is ambiguous when inbound served sessions also complete.
- “All three reviewers confirmed” the skip diagnosis overstates agreement: GLM’s original analysis argued prompt recovery.

*Accountability: tracking is enabled; read-only searches found no matching ADR-025/V210-34 issue. Work-key mapping remains unresolved; no tracker mutation was attempted.*

## VERDICT

**BLOCK**

The three changes I would most insist on:

1. **Specify collision-free turnover and the complete request lifecycle:** remote readiness, request consumption, notify failures, backoff wakeups, manual overrides, epochs, and replacement tokens.
2. **Define verifiable receive coverage and forward progress:** matched unique WANT satisfaction, fork/duplicate handling, permanent exclusions, partial durable progress, and membership preparation on both roles.
3. **Rebuild the proofs around observed causal boundaries and isolated paths:** demonstrate saturation, post-HAVE stores, actual refusal/retry, and stale completion after replacement; measure base-red claims rather than asserting them.
