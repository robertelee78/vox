[0m
> build · kimi-k3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m$ [0mls /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/
review-astra.md
review-glm-5.3.md
review-kimi-k3.md
review2-astra.md
review2-glm-5.3.md
review2-kimi-k3.md
review3-astra.md
review3-glm-5.3.md
review3-kimi-k3.md
review4-astra.md
review4-glm-5.3.md
review4-kimi-k3.md
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-astra.md
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-glm-5.3.md
[0m
[0m$ [0mgrep -n "^## " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md | tail -30
2948:## BLOCKER
2982:## MAJOR
3051:## MINOR
3082:## NIT
3104:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-kimi-k3.md
[0m
[0m$ [0mwc -l /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/*.md && ls -la /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/
1761 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md
     307 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-glm-5.3.md
     412 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-kimi-k3.md
    4312 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-glm-5.3.md
       4 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-kimi-k3.md
    3112 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
    2954 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md
    2332 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md
    1643 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md
     391 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-glm-5.3.md
      30 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-kimi-k3.md
   17262 total
total 2248
drwxr-xr-x@ 14 robert.lee  staff     448 Sep 26 18:20 .
drwxr-xr-x@ 32 robert.lee  staff    1024 Sep 26 18:20 ..
-rw-r--r--@  1 robert.lee  staff   85501 Sep 26 11:55 review-astra.md
-rw-r--r--@  1 robert.lee  staff   32827 Sep 26 12:05 review-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff   39080 Sep 26 12:12 review-kimi-k3.md
-rw-r--r--@  1 robert.lee  staff  230018 Sep 26 12:21 review2-astra.md
-rw-r--r--@  1 robert.lee  staff     101 Sep 26 12:16 review2-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff     101 Sep 26 12:17 review2-kimi-k3.md
-rw-r--r--@  1 robert.lee  staff  181496 Sep 26 12:29 review3-astra.md
-rw-r--r--@  1 robert.lee  staff  169028 Sep 26 18:14 review3-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff  136135 Sep 26 18:17 review3-kimi-k3.md
-rw-r--r--@  1 robert.lee  staff   84794 Sep 26 18:21 review4-astra.md
-rw-r--r--@  1 robert.lee  staff   20086 Sep 26 18:21 review4-glm-5.3.md
-rw-r--r--@  1 robert.lee  staff     778 Sep 26 18:21 review4-kimi-k3.md
[0m
[0m$ [0mgrep -n "^## BLOCKER" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md:2873:## BLOCKER
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md:2284:## BLOCKER
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-astra.md[90m [offset=2940, limit=175][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-glm-5.3.md[90m [offset=2860, limit=95][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-kimi-k3.md[90m [offset=2270, limit=65][0m
Now I have all three round-3 reviews. Let me verify the code citations. I'll pull the relevant sections from both trees.
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/net.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-180.rs 2>/dev/null; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-180.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/anchor-180.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/sync-180.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/channel.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/log/dag.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/dag-202.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/actor.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/transport/quic.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs; wc -l /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/*.rs
6837 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
    6838 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs
     468 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/anchor-180.rs
    2731 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-180.rs
    2723 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs
     442 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/dag-202.rs
     860 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-180.rs
    1008 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs
     861 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs
    1129 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/sync-180.rs
     167 /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs
   24064 total
[0m
[0m$ [0mawk 'NR>=815 && NR<=905 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs
815:                 dead.close(WireError::Unresponsive);
816:             }
817:         }
818:         if let Some(existing) = map.get(&peer) {
819:             // **A held connection that is dead is not a rival.** Silent: the process behind it
820:             // is gone (see [`SILENCE_IS_DEATH`]). Severed: its circuit is gone, so it can send
821:             // nothing — and a second circuit to this peer is exactly what severs it, so it is
822:             // severed at both ends by the time either files the newcomer that replaced it. The
823:             // newcomer is filed and the dead one closed, whatever the tie-break would have said.
824:             // Everything else is decided by path class and then by `tie_key`, which both ends
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
901: 
902:     /// Retire `conn` as [`Self::file`] would when a better path displaces it. For proofs of
903:     /// the retirement rule, which otherwise needs two real paths to the same peer.
904:     #[doc(hidden)]
905:     pub fn retire_for_test(&self, conn: &Arc<VoxConnection>) {
[0m
[0m$ [0mawk 'NR>=2640 && NR<=2723 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs
2640: 
2641: /// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
2642: /// lets go. See [`ChannelState::sync_over_room`].
2643: struct ChannelSessionRoom<'a> {
2644:     shared: &'a tokio::sync::Mutex<ChannelState>,
2645:     store: &'a Store,
2646:     now_secs: u64,
2647:     /// The epoch the session began at; a room that has moved on refuses what was staged for it.
2648:     epoch: u64,
2649:     out: std::cell::RefCell<SyncOutcome>,
2650:     /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
2651:     fatal: std::cell::RefCell<Option<Error>>,
2652: }
2653: 
2654: impl ChannelSessionRoom<'_> {
2655:     fn room(
2656:         &self,
2657:     ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
2658:     {
2659:         let ch = self.shared.blocking_lock();
2660:         if ch.poisoned {
2661:             return Err(crate::wire::WireError::TransportFailed);
2662:         }
2663:         if ch.epoch != self.epoch {
2664:             return Err(crate::wire::WireError::EpochMismatch);
2665:         }
2666:         Ok(ch)
2667:     }
2668: }
2669: 
2670: impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
2671:     fn frontiers(
2672:         &self,
2673:     ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
2674:         Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
2675:     }
2676: 
2677:     fn wants(
2678:         &self,
2679:         remote: &[crate::log::sync::FeedFrontier],
2680:     ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
2681:         Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
2682:     }
2683: 
2684:     fn entries(
2685:         &self,
2686:         wants: &[crate::log::sync::WantRange],
2687:     ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
2688:         Ok(crate::log::sync::entries_for_wants(
2689:             &self.room()?.dag,
2690:             wants,
2691:         ))
2692:     }
2693: 
2694:     fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
2695:         let mut guard = self.room()?;
2696:         let ch = &mut *guard;
2697:         let before = ch.heads();
2698:         // The resolver as it is *now*: an author revoked while this batch was on the wire is not
2699:         // an author of this room any more, and its entries are refused.
2700:         let resolver = ch.resolver();
2701:         // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
2702:         // at a time and stops at the first it refuses; those before it are already in the log.
2703:         // Returning the refusal first skipped persisting and rendering them, yet the log now held
2704:         // them, so every later session saw nothing to send and they were never shown: one joiner
2705:         // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
2706:         // refusal was the other joiner's entry, from an author this node had not admitted yet.
2707:         // `sync_over` always did it in this order ("reconciliation done; only now surface a
2708:         // session failure"); the per-step path lost it.
2709:         let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
2710:         match ch.absorb_arrived(self.store, &before, self.now_secs) {
2711:             Ok(got) => {
2712:                 let mut out = self.out.borrow_mut();
2713:                 out.rendered += got.rendered;
2714:                 out.governance += got.governance;
2715:                 stored
2716:             }
2717:             Err(e) => {
2718:                 *self.fatal.borrow_mut() = Some(e);
2719:                 Err(crate::wire::WireError::TransportFailed)
2720:             }
2721:         }
2722:     }
2723: }
[0m
[0m$ [0mawk 'NR>=200 && NR<=340 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/dag-202.rs
200:     }
201: 
202:     /// The feed for `author`, if any.
203:     #[must_use]
204:     pub fn feed(&self, author: &Digest32) -> Option<&Feed> {
205:         self.feeds.get(author)
206:     }
207: 
208:     /// All authors with a feed, sorted (deterministic iteration).
209:     #[must_use]
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
231:         let (author, seq) = self.by_hash.get(hash)?;
232:         self.feeds.get(author).and_then(|f| f.get(*seq))
233:     }
234: 
235:     /// Whether an entry with this hash is stored.
236:     #[must_use]
237:     pub fn contains(&self, hash: &Digest32) -> bool {
238:         self.by_hash.contains_key(hash)
239:     }
240: 
241:     /// Accept an entry into the DAG, enforcing the full ADR-008 predicate.
242:     ///
243:     /// Steps, in order (any failure leaves the DAG unchanged):
244:     /// 0. Governance entries must carry an attributable (composite)
245:     ///    authenticator → otherwise [`Rejected::GovernanceNotAttributable`].
246:     /// 1. If the author is frozen, refuse ([`Rejected::Fork`] with the recorded
247:     ///    proof is *not* re-raised; later entries from a frozen author are simply
248:     ///    refused via [`Rejected::NotAdmitted`]).
249:     /// 2. Duplicate (same hash already stored) → [`Rejected::Duplicate`]
250:     ///    (idempotent replication).
251:     /// 3. Admission: author ∈ admitted set for `(channel, epoch)`.
252:     /// 4. Authenticator + structure verify under `author_root`.
253:     /// 5. Equivocation: a different entry already occupies `(author, seq)` →
254:     ///    [`Rejected::Fork`]; for an attributable entry the author is frozen.
255:     /// 6. Feed link: `seq`/`prev_hash`/`lipmaa_backlink`/end-of-feed.
256:     ///
257:     /// Equivocation is classified **only after** admission and verification
258:     /// (steps 3–4 precede 5). An ADR-008 fork proof must be *self-authenticating*
259:     /// and a deniable-content alarm must come from an entry the epoch verifier
260:     /// accepts; classifying first would let a peer holding *no* valid key surface
261:     /// fork proofs and alarms — a framing / attention-DoS primitive
262:     /// (2026-09-19 review, HIGH). A conflicting entry that is unadmitted or fails
263:     /// verification is therefore rejected as [`Rejected::NotAdmitted`] /
264:     /// [`Rejected::Verification`], never as a fork.
265:     ///
266:     /// `kind` selects the governance/content rule; fork attributability is then
267:     /// determined by the entry's authenticator type (governance is forced
268:     /// composite above).
269:     ///
270:     /// Equivalent to [`Dag::accept_with_deniable`] with no deniable verifier, so a
271:     /// **deniable** content entry fails verification with
272:     /// [`Error::DeniableVerificationUnavailable`] (the M7 verifier is supplied via
273:     /// [`Dag::accept_with_deniable`]) — including a conflicting one, which is
274:     /// consequently never classified as an alarm without a verifier.
275:     pub fn accept(
276:         &mut self,
277:         entry: Entry,
278:         kind: EntryKind,
279:         author_root: &CompositePublicKey,
280:         admission: &AdmissionPolicy,
281:     ) -> std::result::Result<Digest32, Rejected> {
282:         self.accept_with_deniable(entry, kind, author_root, admission, NO_DENIABLE)
283:     }
284: 
285:     /// Accept an entry, verifying a [`crate::log::entry::Authenticator::Deniable`] authenticator with
286:     /// the supplied M7 [`DeniableVerifier`] when one is given (ADR-009 crypto is
287:     /// M7). The composite path is unaffected. This is the seam M7 fills; M5 callers
288:     /// use [`Dag::accept`].
289:     pub fn accept_with_deniable<V: DeniableVerifier>(
290:         &mut self,
291:         entry: Entry,
292:         kind: EntryKind,
293:         author_root: &CompositePublicKey,
294:         admission: &AdmissionPolicy,
295:         deniable: Option<&V>,
296:     ) -> std::result::Result<Digest32, Rejected> {
297:         let author = entry.skeleton.author_id;
298:         let seq = entry.skeleton.seq;
299:         let channel = entry.skeleton.channel_id;
300:         let epoch = entry.skeleton.epoch;
301:         let hash = entry.entry_hash();
302: 
303:         // Governance/control entries MUST be composite (attributable) in EVERY
304:         // channel (ADR-008 §"Per-entry-type authentication"): a deniable
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
331:             .verify_with_deniable(author_root, deniable)
332:             .map_err(Rejected::Verification)?;
333: 
334:         // Equivocation: a *different* entry already occupies (author, seq)?
335:         if let Some(feed) = self.feeds.get(&author) {
336:             if let Some(existing) = feed.get(seq) {
337:                 // Same seq, different hash (duplicate handled above) ⇒ a fork.
338:                 let outcome = self.classify_fork(existing.clone(), entry);
339:                 if let ForkOutcome::Attributable(ref proof) = outcome {
340:                     // `conflicting` verified just above. `existing` was verified
[0m
[0m$ [0mawk 'NR>=2040 && NR<=2110 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs; echo ====; awk 'NR>=1800 && NR<=1845 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs; echo ====; awk 'NR>=1930 && NR<=1945 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs
2040:                     "synced entry from an unadmitted author",
2041:                 ))?
2042:                 .clone();
2043:             let wire = self
2044:                 .dag
2045:                 .get_by_hash(&entry_hash)
2046:                 .ok_or(Error::MalformedGovernance("synced entry vanished"))?
2047:                 .to_wire();
2048:             let id = self.next_log_id;
2049:             let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
2050:             if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg) {
2051:                 self.poisoned = true;
2052:                 return Err(e);
2053:             }
2054:             self.next_log_id = id.saturating_add(1);
2055:             match classify_payload(&payload)? {
2056:                 EntryKind::Governance => {
2057:                     let entry = self
2058:                         .dag
2059:                         .get_by_hash(&entry_hash)
2060:                         .ok_or(Error::MalformedGovernance("synced entry vanished"))?
2061:                         .clone();
2062:                     let gov = GovEntry::from_verified_log_entry(
2063:                         &entry,
2064:                         &key,
2065:                         &self.channel_id,
2066:                         self.gov_heads(),
2067:                     )?;
2068:                     self.gov_entries.push(gov);
2069:                     self.evaluator = Arc::new(Self::build_evaluator(
2070:                         &self.genesis,
2071:                         &self.authors,
2072:                         &self.gov_entries,
2073:                         now_secs,
2074:                     )?);
2075:                     out.governance += 1;
2076:                 }
2077:                 EntryKind::Content => {
2078:                     if self.render_content(store, author, entry_hash, &payload, now_secs)? {
2079:                         out.rendered += 1;
2080:                     }
2081:                 }
2082:             }
2083:         }
2084:         // Reconciliation done; only now surface a session failure, with its coded
2085:         // reason preserved (ADR-008 never downgrades a failure silently).
2086:         Ok(out)
2087:     }
2088: 
2089:     /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
2090:     /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
2091:     ///
2092:     /// # Errors
2093:     /// The room is poisoned, a persist fails, or the session hard-fails.
2094:     pub fn sync_over_room<T: Transport>(
2095:         shared: &tokio::sync::Mutex<Self>,
2096:         store: &Store,
2097:         transport: &mut T,
2098:         now_secs: u64,
2099:     ) -> Result<SyncOutcome> {
2100:         let epoch = {
2101:             let ch = shared.blocking_lock();
2102:             if ch.poisoned {
2103:                 return Err(Error::Profile(
2104:                     "channel is poisoned after a failed persist; reopen it",
2105:                 ));
2106:             }
2107:             ch.epoch
2108:         };
2109:         let room = ChannelSessionRoom {
2110:             shared,
zsh:1: === not found
[0m
[0m$ [0mawk 'NR>=340 && NR<=420 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/dag-202.rs
(no output)
[0m
[0m$ [0mawk 'NR>=1800 && NR<=1845 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs; echo XX; awk 'NR>=1930 && NR<=1950 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs
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
XX
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
[0m$ [0msed -n '336,442p' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/dag-202.rs | awk '{printf "%d: %s\n", NR+335, $0}'
336:             if let Some(existing) = feed.get(seq) {
337:                 // Same seq, different hash (duplicate handled above) ⇒ a fork.
338:                 let outcome = self.classify_fork(existing.clone(), entry);
339:                 if let ForkOutcome::Attributable(ref proof) = outcome {
340:                     // `conflicting` verified just above. `existing` was verified
341:                     // when it was accepted (only this path stores entries); the
342:                     // re-check is an invariant guard so the recorded proof is
343:                     // self-authenticating regardless of how `existing` arrived.
344:                     if existing.verify(author_root).is_ok() {
345:                         self.frozen.insert(author, (**proof).clone());
346:                     }
347:                 }
348:                 return Err(Rejected::Fork(outcome));
349:             }
350:         }
351: 
352:         // Feed link: `append` validates seq/prev_hash/lipmaa_backlink/end-of-feed
353:         // and leaves the feed untouched on a rejection. Then index by hash.
354:         self.feeds
355:             .entry(author)
356:             .or_default()
357:             .append(entry)
358:             .map_err(Rejected::Feed)?;
359:         self.by_hash.insert(hash, (author, seq));
360:         Ok(hash)
361:     }
362: 
363:     /// Classify a `(author, seq)` conflict by the **authenticator type** of the
364:     /// conflicting entries (ADR-008 §"Fork / equivocation handling"). A conflict
365:     /// is a self-authenticating fork proof only if *both* entries are attributable
366:     /// (composite-signed): governance entries are forced composite at acceptance,
367:     /// so this rule alone covers them — no caller hint is consulted. If either
368:     /// entry carries a forgeable (deniable) authenticator, the conflict is a
369:     /// non-attributable alarm (auto-freeze would be a framing/DoS primitive).
370:     fn classify_fork(&self, existing: Entry, conflicting: Entry) -> ForkOutcome {
371:         let author_id = conflicting.skeleton.author_id;
372:         let seq = conflicting.skeleton.seq;
373:         let attributable =
374:             conflicting.authenticator.is_attributable() && existing.authenticator.is_attributable();
375:         if attributable {
376:             ForkOutcome::Attributable(Box::new(ForkProof {
377:                 author_id,
378:                 seq,
379:                 existing,
380:                 conflicting,
381:             }))
382:         } else {
383:             ForkOutcome::DeniableAlarm { author_id, seq }
384:         }
385:     }
386: 
387:     /// A deterministic causal (topological) order of every stored entry: each
388:     /// entry appears after all of its causal predecessors (its own feed's earlier
389:     /// entries). Ties between concurrent entries are broken on `(author_id, seq)`,
390:     /// so two replicas holding the same entry set yield the **identical** order —
391:     /// the observable form of Strong Eventual Consistency.
392:     ///
393:     /// The visible causal edges in M5 are the per-author `seq` chains; cross-author
394:     /// causal references travel inside (opaque, encrypted) payloads and surface in
395:     /// later milestones, so the merge here is the union of per-author total orders,
396:     /// deterministically interleaved.
397:     #[must_use]
398:     pub fn causal_order(&self) -> Vec<Digest32> {
399:         // Within an author, seq order is the causal order. Across authors there is
400:         // no edge visible to M5, so we interleave deterministically by author id,
401:         // emitting all entries in (author_id, seq) lexicographic order. This is a
402:         // valid topological order (per-author predecessors precede successors) and
403:         // is identical on any replica with the same set.
404:         let mut keyed: BTreeMap<(Digest32, u64), Digest32> = BTreeMap::new();
405:         for (author, feed) in &self.feeds {
406:             for entry in feed.iter() {
407:                 keyed.insert((*author, entry.skeleton.seq), entry.entry_hash());
408:             }
409:         }
410:         keyed.into_values().collect()
411:     }
412: 
413:     /// Render-gating seam (ADR-008): attempt to decrypt+render the payload of the
414:     /// entry at `hash` with `decrypt`. The store holds ciphertext regardless of
415:     /// readability; this returns `Some(plaintext)` only if a payload is retained
416:     /// **and** `decrypt` succeeds (the holder has keys). A `None` means "store it,
417:     /// replicate it, but do not render" — exactly the data-side of per-sender
418:     /// consent. The real decryptor is M4/M6; M5 only owns this seam.
419:     pub fn render<F>(&self, hash: &Digest32, decrypt: F) -> Option<Vec<u8>>
420:     where
421:         F: FnOnce(&Entry, &[u8]) -> Option<Vec<u8>>,
422:     {
423:         let entry = self.get_by_hash(hash)?;
424:         let payload = entry.payload.as_deref()?;
425:         decrypt(entry, payload)
426:     }
427: 
428:     /// Verify the entire DAG: every feed's chain + signatures, given a resolver
429:     /// from author fingerprint to that author's composite root key. Used after a
430:     /// bulk import / sync to confirm convergence integrity.
431:     pub fn verify_all<F>(&self, mut author_key: F) -> Result<()>
432:     where
433:         F: FnMut(&Digest32) -> Option<CompositePublicKey>,
434:     {
435:         for (author, feed) in &self.feeds {
436:             let key = author_key(author).ok_or(Error::MalformedBundle("dag missing author key"))?;
437:             feed.verify()?;
438:             feed.verify_all_signatures(&key)?;
439:         }
440:         Ok(())
441:     }
442: }
[0m
[0m$ [0mawk 'NR>=170 && NR<=180 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=230 && NR<=258 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=1755 && NR<=1770 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
XX
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
XX
1755:     /// When a background dial to each member was last started: see `reach_member`.
1756:     member_dialed_at: BTreeMap<Digest32, u64>,
1757:     /// Explicit consents waiting on the network: for a member's dial (answered on `Dialed` by
1758:     /// delivering, or on `ReachFailed` as `Unreachable`), or for that member's bundle record to
1759:     /// reach this node's board (retried on the room's `SyncDone`). Each carries its attempts so
1760:     /// far, so one that cannot succeed is answered rather than kept. The person gets the real
1761:     /// outcome and the node keeps answering meanwhile.
1762:     pending_consents: Vec<(Digest32, Digest32, oneshot::Sender<Outcome>, u8)>,
1763:     /// Consecutive failed sessions per `(room, peer)`; see `MAX_PUSH_RETRIES`.
1764:     push_failures: BTreeMap<(Digest32, Digest32), u32>,
1765:     /// Each room's view summary and detail as this node's own latest write left them, taken under the room's lock
1766:     /// by the write itself. `view_of` uses it when a session holds the room, so a person always sees
1767:     /// their own post in what they read straight after, however long that session holds on. A room's
1768:     /// entry is removed once a view reads the room under its lock, since that read includes the
1769:     /// write: an entry here is therefore always newer than the published one.
1770:     fresh_details: BTreeMap<Digest32, (ChannelSummary, ChannelDetail)>,
[0m
[0m$ [0mawk 'NR>=3365 && NR<=3385 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=4350 && NR<=4395 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
XX
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
[0m
Now let me check the actor.rs sections cited by the ADR and reviews.
[0m$ [0mawk 'NR>=5195 && NR<=5230 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=3430 && NR<=3460 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
XX
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
[0m
[0m$ [0mawk 'NR>=4720 && NR<=4810 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
[0m
[0m$ [0mawk 'NR>=85 && NR<=120 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs; echo XX; awk 'NR>=210 && NR<=230 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-180.rs
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
XX
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
[0m
[0m$ [0mawk 'NR>=400 && NR<=430 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/anchor-180.rs; echo XX; awk 'NR>=5220 && NR<=5245 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; echo XX; grep -n "SILENCE_IS_DEATH\|OPEN_STREAM_PATIENCE\|MAX_IDLE_MS" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs | head
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
XX
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
XX
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:336:pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:394:    /// sampled, and when that count last moved. The evidence [`SILENCE_IS_DEATH`] reads.
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:445:    /// [`SILENCE_IS_DEATH`] is not handed out, because what is behind it is a process that has
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:478:    /// Whether `conn` has been silent past [`SILENCE_IS_DEATH`].
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:480:        self.silent_for(conn) > SILENCE_IS_DEATH
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:484:    /// [`SILENCE_IS_DEATH`], or relayed over a circuit this node no longer has
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:499:    /// holds nothing else — uses it. Once the old one passes [`SILENCE_IS_DEATH`] the two ends
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:538:    /// look freshly heard after any gap, and its death would be noticed one [`SILENCE_IS_DEATH`]
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:670:    /// - except that a held connection **silent past [`SILENCE_IS_DEATH`]** is no rival at
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:727:    /// Silence ([`SILENCE_IS_DEATH`]) tells a dead connection from a live one, but only after
[0m
[0m$ [0mgrep -n "syncing\b" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs | head -20; echo XX; grep -n "KEEP_ALIVE: \|OPEN_STREAM_PATIENCE: \|SYNC_INTERVAL_SECS: \|QUICK_PUSH_RETRIES\|PushRetry\|disjoint" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -20
269:        NodeCommand::Sync { .. } => "syncing",
1732:    syncing: std::collections::BTreeSet<Digest32>,
1733:    /// The peer each running session in [`Self::syncing`] is with. A refusal says **why**
1951:            syncing: std::collections::BTreeSet::new(),
2952:        if self.syncing.contains(channel_id) {
3382:                self.syncing.remove(&channel_id);
3651:        // other operation on that room queued behind it: sending a message, syncing,
4387:            if !self.syncing.contains(&channel_id) {
4850:                if self.syncing.contains(cid) || self.publishing.contains(&(*cid, peer)) {
4895:                if self.syncing.contains(cid) {
5007:        if self.syncing.contains(channel_id) {
5013:        self.syncing.insert(*channel_id);
5061:            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
5132:        self.syncing.insert(channel_id);
5226:        if self.syncing.contains(&channel_id) {
XX
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs:153:const OPEN_STREAM_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs:162:pub(crate) const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(20);
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs:43:pub const SYNC_INTERVAL_SECS: u64 = 30;
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:293:        NetEvent::PushRetry { .. } => "retrying a push that failed",
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:621:    PushRetry {
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:3361:            NetEvent::PushRetry { channel_id, peer } => {
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:3414:                            let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
[0m
[0m$ [0mgrep -n "poison" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs | head -20; echo XX; grep -rn "208" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
6454:        // A rotation that cannot persist poisons the channel, which the *next*
XX
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md:261:| the room was poisoned | the room's ports retire their attempts and are marked `poisoned`, reported once. **No retry** until the room is reopened (by a person, or by #208's reopen at unlock), which re-creates its ports |
[0m
[0m$ [0mgrep -n "QUICK\|jitter\|20.*100\|disjoint" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -20; echo XX; awk 'NR>=3395 && NR<=3430 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
3404:                // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
3409:                        let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
3410:                        let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
XX
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
[0m
[0m$ [0mawk 'NR>=1725 && NR<=1750 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; echo XX; awk 'NR>=6440 && NR<=6470 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; echo XX; grep -n "reopen\|unlock" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs | head -20
1725:     /// and silently dropped the protection.
1726:     ///
1727:     /// Without it two nodes that reconcile at the same moment deadlock on each other: each holds its
1728:     /// own room's lock for its initiated session and waits for frames from a peer whose lock is held
1729:     /// by *its* initiated session. Nothing breaks it but `SYNC_FRAME_TIMEOUT`. Measured as a user, a
1730:     /// message posted right after a join crossed in 20s or 40s — one and two frame timeouts — instead
1731:     /// of the 0-1s it takes when the rooms are free.
1732:     syncing: std::collections::BTreeSet<Digest32>,
1733:     /// The peer each running session in [`Self::syncing`] is with. A refusal says **why**
1734:     /// (`SessionBusy`) only to that peer: it is a room peer this node chose to sync with, so the
1735:     /// reason tells it nothing new. Anyone else is refused with the uninformative code, because
1736:     /// the busy check runs before the membership check, and a reason would let a non-member
1737:     /// probe whether this node holds a room (#202).
1738:     syncing_with: BTreeMap<Digest32, Digest32>,
1739:     /// Rooms this node is joining right now (their join is on a `Joiner` task).
1740:     joining: std::collections::BTreeSet<Digest32>,
1741:     /// Pairwise streams for a room still being joined, held until the join reports back: see
1742:     /// `take_inbound_skdm`.
1743:     held_pairwise: Vec<(
1744:         Digest32,
1745:         Digest32,
1746:         crate::node::pairwise_stream::PairwiseFrame,
1747:         quinn::SendStream,
1748:         quinn::RecvStream,
1749:     )>,
1750:     /// Rooms whose anchor publish found them mid-session: run when that session's `SyncDone`
XX
6440:         let mut ch = shared.lock().await;
6441:         // One read, in milliseconds. NOT `now * 1000` and not seconds-plus-a-second-read: a value
6442:         // composed from two clock reads can go backwards across a second boundary, which is the
6443:         // ordering inversion this change exists to remove.
6444:         let now_millis = (self.millis_clock)();
6445:         let appended = match ch.append_text(profile, text, now_millis) {
6446:             Ok(r) => row_of(r),
6447:             Err(e) => return Outcome::Failed(fault_of(&e)),
6448:         };
6449:         // ADR-006's scheduled rotation: at `N` messages or `T` elapsed the sender key
6450:         // is retired and the next message rides a generation nobody holds yet, so the
6451:         // reach of any one compromised key is bounded in both directions. The
6452:         // remaining consenters are re-keyed below and by the tick.
6453:         //
6454:         // A rotation that cannot persist poisons the channel, which the *next*
6455:         // command reports; it does not un-send the message that just went out, so the
6456:         // append is still reported as the success it was.
6457:         let rotated =
6458:             ch.should_rotate_sender(now) && ch.rotate_sender(profile.store(), now).is_ok();
6459:         self.fresh_details
6460:             .insert(*channel_id, (summary_of(&ch), detail_of(&ch)));
6461:         drop(ch);
6462:         let channel_id = *channel_id;
6463:         let _ = self.event_tx.send(NodeEvent::NewEntry {
6464:             channel_id,
6465:             row: appended,
6466:         });
6467:         // ADR-016: push immediately after a local append. Marking it here and
6468:         // letting the tick do the work keeps authoring off the network path.
6469:         self.note_local_append(&channel_id);
6470:         if rotated {
XX
26://!   is marked **poisoned** and refuses further appends until reopened — the
30://! - Double-lock (ADR-010): opening needs the unlocked identity (the identity
251:/// An open (SEK-unlocked) channel on this device.
697:    /// A local name over the limit, no unlocked signer, or a genesis or key that cannot be made.
722:    /// No unlocked signer, a segment that cannot be sealed, or a store write that fails.
1092:    /// What must hold before a joined room is made: a name within the limit, an unlocked signer,
1622:                "channel is poisoned after a failed persist; reopen it",
1888:                "channel is poisoned after a failed persist; reopen it",
1977:                "channel is poisoned after a failed persist; reopen it",
2104:                    "channel is poisoned after a failed persist; reopen it",
2144:                "channel is poisoned after a failed persist; reopen it",
2310:            // reopen would re-derive a consumed key. Poison instead.
2332:                "channel is poisoned after a failed persist; reopen it",
2427:                "channel is poisoned after a failed persist; reopen it",
2589:    /// Whether a failed persist has poisoned this channel (reopen to continue).
2607:        // can neither unseal nor answer a join until it is reopened (ADR-010/015).
[0m
[0m$ [0mgrep -rn "208" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/*.md | grep -v "ADR-025-sync" | grep -i "reopen\|#208" | head; echo XX; grep -rn "#208\|V210-3[0-9]\|#212\|V210-39" /opt/vox/.claude/worktrees/ac-adr025/docs --include="*.md" -l | head
XX
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-kimi-k3.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md
[0m
[0m$ [0mgrep -n "disjoint\|window" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head; echo XX; grep -n "backoff\|Backoff" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -20
654:    /// window").
2255:    /// answering *everyone* — and a request arriving in that window waits out its own patience and
3193:                // ForwardOnly window f4d13d8 closed on the host's side (see `apply_join_outcome`) was
3458:                    // readable to it, so every tick of delay is a window of posts lost to the
3460:                    // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
3771:        // opened a window in which anything this node posted was unreadable to the
6208:        // announced an address over a window where nothing was listening — a person who
XX
591:    /// A sender key written to `peer` was taken: any backoff on re-sending to it ends.
1777:    key_backoff: BTreeMap<(Digest32, Digest32), (u32, u64)>,
1956:            key_backoff: BTreeMap::new(),
3320:                let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
3359:                self.key_backoff.remove(&(channel_id, peer));
4622:            // A member whose last keys were not taken waits out its backoff, unless a person asked.
4625:                    .key_backoff
4973:        // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
[0m
[0m$ [0mcat /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-kimi-k3.md; echo XX; grep -n "41\b\|disjoint" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs | head; grep -rn "V210-34\|#209\|#212\|#208\|#211" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md | head -5
...output truncated...

Full output saved to: /Users/robert.lee/.local/share/opencode/tool-output/tool_0de8c589f001Vfo2wi2MbtkI99

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
XX
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
[0m$ [0msed -n '336,442p' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/dag-202.rs | awk '{printf "%d: %s\n", NR+335, $0}'
336:             if let Some(existing) = feed.get(seq) {
337:                 // Same seq, different hash (duplicate handled above) ⇒ a fork.
338:                 let outcome = self.classify_fork(existing.clone(), entry);
339:                 if let ForkOutcome::Attributable(ref proof) = outcome {
340:                     // `conflicting` verified just above. `existing` was verified
341:                     // when it was accepted (only this path stores entries); the
342:                     // re-check is an invariant guard so the recorded proof is
343:                     // self-authenticating regardless of how `existing` arrived.
344:                     if existing.verify(author_root).is_ok() {
345:                         self.frozen.insert(author, (**proof).clone());
346:                     }
347:                 }
348:                 return Err(Rejected::Fork(outcome));
349:             }
350:         }
351: 
352:         // Feed link: `append` validates seq/prev_hash/lipmaa_backlink/end-of-feed
353:         // and leaves the feed untouched on a rejection. Then index by hash.
354:         self.feeds
355:             .entry(author)
356:             .or_default()
357:             .append(entry)
358:             .map_err(Rejected::Feed)?;
359:         self.by_hash.insert(hash, (author, seq));
360:         Ok(hash)
361:     }
362: 
363:     /// Classify a `(author, seq)` conflict by the **authenticator type** of the
364:     /// conflicting entries (ADR-008 §"Fork / equivocation handling"). A conflict
365:     /// is a self-authenticating fork proof only if *both* entries are attributable
366:     /// (composite-signed): governance entries are forced composite at acceptance,
367:     /// so this rule alone covers them — no caller hint is consulted. If either
368:     /// entry carries a forgeable (deniable) authenticator, the conflict is a
369:     /// non-attributable alarm (auto-freeze would be a framing/DoS primitive).
370:     fn classify_fork(&self, existing: Entry, conflicting: Entry) -> ForkOutcome {
371:         let author_id = conflicting.skeleton.author_id;
372:         let seq = conflicting.skeleton.seq;
373:         let attributable =
374:             conflicting.authenticator.is_attributable() && existing.authenticator.is_attributable();
375:         if attributable {
376:             ForkOutcome::Attributable(Box::new(ForkProof {
377:                 author_id,
378:                 seq,
379:                 existing,
380:                 conflicting,
381:             }))
382:         } else {
383:             ForkOutcome::DeniableAlarm { author_id, seq }
384:         }
385:     }
386: 
387:     /// A deterministic causal (topological) order of every stored entry: each
388:     /// entry appears after all of its causal predecessors (its own feed's earlier
389:     /// entries). Ties between concurrent entries are broken on `(author_id, seq)`,
390:     /// so two replicas holding the same entry set yield the **identical** order —
391:     /// the observable form of Strong Eventual Consistency.
392:     ///
393:     /// The visible causal edges in M5 are the per-author `seq` chains; cross-author
394:     /// causal references travel inside (opaque, encrypted) payloads and surface in
395:     /// later milestones, so the merge here is the union of per-author total orders,
396:     /// deterministically interleaved.
397:     #[must_use]
398:     pub fn causal_order(&self) -> Vec<Digest32> {
399:         // Within an author, seq order is the causal order. Across authors there is
400:         // no edge visible to M5, so we interleave deterministically by author id,
401:         // emitting all entries in (author_id, seq) lexicographic order. This is a
402:         // valid topological order (per-author predecessors precede successors) and
403:         // is identical on any replica with the same set.
404:         let mut keyed: BTreeMap<(Digest32, u64), Digest32> = BTreeMap::new();
405:         for (author, feed) in &self.feeds {
406:             for entry in feed.iter() {
407:                 keyed.insert((*author, entry.skeleton.seq), entry.entry_hash());
408:             }
409:         }
410:         keyed.into_values().collect()
411:     }
412: 
413:     /// Render-gating seam (ADR-008): attempt to decrypt+render the payload of the
414:     /// entry at `hash` with `decrypt`. The store holds ciphertext regardless of
415:     /// readability; this returns `Some(plaintext)` only if a payload is retained
416:     /// **and** `decrypt` succeeds (the holder has keys). A `None` means "store it,
417:     /// replicate it, but do not render" — exactly the data-side of per-sender
418:     /// consent. The real decryptor is M4/M6; M5 only owns this seam.
419:     pub fn render<F>(&self, hash: &Digest32, decrypt: F) -> Option<Vec<u8>>
420:     where
421:         F: FnOnce(&Entry, &[u8]) -> Option<Vec<u8>>,
422:     {
423:         let entry = self.get_by_hash(hash)?;
424:         let payload = entry.payload.as_deref()?;
425:         decrypt(entry, payload)
426:     }
427: 
428:     /// Verify the entire DAG: every feed's chain + signatures, given a resolver
429:     /// from author fingerprint to that author's composite root key. Used after a
430:     /// bulk import / sync to confirm convergence integrity.
431:     pub fn verify_all<F>(&self, mut author_key: F) -> Result<()>
432:     where
433:         F: FnMut(&Digest32) -> Option<CompositePublicKey>,
434:     {
435:         for (author, feed) in &self.feeds {
436:             let key = author_key(author).ok_or(Error::MalformedBundle("dag missing author key"))?;
437:             feed.verify()?;
438:             feed.verify_all_signatures(&key)?;
439:         }
440:         Ok(())
441:     }
442: }
[0m
[0m$ [0mawk 'NR>=170 && NR<=180 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=230 && NR<=258 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=1755 && NR<=1770 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
XX
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
XX
1755:     /// When a background dial to each member was last started: see `reach_member`.
1756:     member_dialed_at: BTreeMap<Digest32, u64>,
1757:     /// Explicit consents waiting on the network: for a member's dial (answered on `Dialed` by
1758:     /// delivering, or on `ReachFailed` as `Unreachable`), or for that member's bundle record to
1759:     /// reach this node's board (retried on the room's `SyncDone`). Each carries its attempts so
1760:     /// far, so one that cannot succeed is answered rather than kept. The person gets the real
1761:     /// outcome and the node keeps answering meanwhile.
1762:     pending_consents: Vec<(Digest32, Digest32, oneshot::Sender<Outcome>, u8)>,
1763:     /// Consecutive failed sessions per `(room, peer)`; see `MAX_PUSH_RETRIES`.
1764:     push_failures: BTreeMap<(Digest32, Digest32), u32>,
1765:     /// Each room's view summary and detail as this node's own latest write left them, taken under the room's lock
1766:     /// by the write itself. `view_of` uses it when a session holds the room, so a person always sees
1767:     /// their own post in what they read straight after, however long that session holds on. A room's
1768:     /// entry is removed once a view reads the room under its lock, since that read includes the
1769:     /// write: an entry here is therefore always newer than the published one.
1770:     fresh_details: BTreeMap<Digest32, (ChannelSummary, ChannelDetail)>,
[0m
[0m$ [0mawk 'NR>=3365 && NR<=3385 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=4350 && NR<=4395 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
XX
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
[0m
Now let me check the actor.rs sections cited by the ADR and reviews.
[0m$ [0mawk 'NR>=5195 && NR<=5230 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs; echo XX; awk 'NR>=3430 && NR<=3460 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
XX
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
[0m
[0m$ [0mawk 'NR>=4720 && NR<=4810 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
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
[0m
[0m$ [0mawk 'NR>=85 && NR<=120 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs; echo XX; awk 'NR>=210 && NR<=230 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-180.rs
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
XX
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
[0m
[0m$ [0mawk 'NR>=400 && NR<=430 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/anchor-180.rs; echo XX; awk 'NR>=5220 && NR<=5245 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; echo XX; grep -n "SILENCE_IS_DEATH\|OPEN_STREAM_PATIENCE\|MAX_IDLE_MS" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs | head
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
XX
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
XX
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:336:pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:394:    /// sampled, and when that count last moved. The evidence [`SILENCE_IS_DEATH`] reads.
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:445:    /// [`SILENCE_IS_DEATH`] is not handed out, because what is behind it is a process that has
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:478:    /// Whether `conn` has been silent past [`SILENCE_IS_DEATH`].
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:480:        self.silent_for(conn) > SILENCE_IS_DEATH
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:484:    /// [`SILENCE_IS_DEATH`], or relayed over a circuit this node no longer has
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:499:    /// holds nothing else — uses it. Once the old one passes [`SILENCE_IS_DEATH`] the two ends
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:538:    /// look freshly heard after any gap, and its death would be noticed one [`SILENCE_IS_DEATH`]
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:670:    /// - except that a held connection **silent past [`SILENCE_IS_DEATH`]** is no rival at
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs:727:    /// Silence ([`SILENCE_IS_DEATH`]) tells a dead connection from a live one, but only after
[0m
[0m$ [0mgrep -n "syncing\b" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs | head -20; echo XX; grep -n "KEEP_ALIVE: \|OPEN_STREAM_PATIENCE: \|SYNC_INTERVAL_SECS: \|QUICK_PUSH_RETRIES\|PushRetry\|disjoint" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/net-202.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -20
269:        NodeCommand::Sync { .. } => "syncing",
1732:    syncing: std::collections::BTreeSet<Digest32>,
1733:    /// The peer each running session in [`Self::syncing`] is with. A refusal says **why**
1951:            syncing: std::collections::BTreeSet::new(),
2952:        if self.syncing.contains(channel_id) {
3382:                self.syncing.remove(&channel_id);
3651:        // other operation on that room queued behind it: sending a message, syncing,
4387:            if !self.syncing.contains(&channel_id) {
4850:                if self.syncing.contains(cid) || self.publishing.contains(&(*cid, peer)) {
4895:                if self.syncing.contains(cid) {
5007:        if self.syncing.contains(channel_id) {
5013:        self.syncing.insert(*channel_id);
5061:            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
5132:        self.syncing.insert(channel_id);
5226:        if self.syncing.contains(&channel_id) {
XX
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs:153:const OPEN_STREAM_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/quic-202.rs:162:pub(crate) const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(20);
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs:43:pub const SYNC_INTERVAL_SECS: u64 = 30;
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:293:        NetEvent::PushRetry { .. } => "retrying a push that failed",
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:621:    PushRetry {
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:3361:            NetEvent::PushRetry { channel_id, peer } => {
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs:3414:                            let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
[0m
[0m$ [0mgrep -n "poison" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs | head -20; echo XX; grep -rn "208" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
6454:        // A rotation that cannot persist poisons the channel, which the *next*
XX
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md:261:| the room was poisoned | the room's ports retire their attempts and are marked `poisoned`, reported once. **No retry** until the room is reopened (by a person, or by #208's reopen at unlock), which re-creates its ports |
[0m
[0m$ [0mgrep -n "QUICK\|jitter\|20.*100\|disjoint" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -20; echo XX; awk 'NR>=3395 && NR<=3430 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs
3404:                // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
3409:                        let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
3410:                        let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
XX
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
[0m
[0m$ [0mawk 'NR>=1725 && NR<=1750 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; echo XX; awk 'NR>=6440 && NR<=6470 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs; echo XX; grep -n "reopen\|unlock" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs | head -20
1725:     /// and silently dropped the protection.
1726:     ///
1727:     /// Without it two nodes that reconcile at the same moment deadlock on each other: each holds its
1728:     /// own room's lock for its initiated session and waits for frames from a peer whose lock is held
1729:     /// by *its* initiated session. Nothing breaks it but `SYNC_FRAME_TIMEOUT`. Measured as a user, a
1730:     /// message posted right after a join crossed in 20s or 40s — one and two frame timeouts — instead
1731:     /// of the 0-1s it takes when the rooms are free.
1732:     syncing: std::collections::BTreeSet<Digest32>,
1733:     /// The peer each running session in [`Self::syncing`] is with. A refusal says **why**
1734:     /// (`SessionBusy`) only to that peer: it is a room peer this node chose to sync with, so the
1735:     /// reason tells it nothing new. Anyone else is refused with the uninformative code, because
1736:     /// the busy check runs before the membership check, and a reason would let a non-member
1737:     /// probe whether this node holds a room (#202).
1738:     syncing_with: BTreeMap<Digest32, Digest32>,
1739:     /// Rooms this node is joining right now (their join is on a `Joiner` task).
1740:     joining: std::collections::BTreeSet<Digest32>,
1741:     /// Pairwise streams for a room still being joined, held until the join reports back: see
1742:     /// `take_inbound_skdm`.
1743:     held_pairwise: Vec<(
1744:         Digest32,
1745:         Digest32,
1746:         crate::node::pairwise_stream::PairwiseFrame,
1747:         quinn::SendStream,
1748:         quinn::RecvStream,
1749:     )>,
1750:     /// Rooms whose anchor publish found them mid-session: run when that session's `SyncDone`
XX
6440:         let mut ch = shared.lock().await;
6441:         // One read, in milliseconds. NOT `now * 1000` and not seconds-plus-a-second-read: a value
6442:         // composed from two clock reads can go backwards across a second boundary, which is the
6443:         // ordering inversion this change exists to remove.
6444:         let now_millis = (self.millis_clock)();
6445:         let appended = match ch.append_text(profile, text, now_millis) {
6446:             Ok(r) => row_of(r),
6447:             Err(e) => return Outcome::Failed(fault_of(&e)),
6448:         };
6449:         // ADR-006's scheduled rotation: at `N` messages or `T` elapsed the sender key
6450:         // is retired and the next message rides a generation nobody holds yet, so the
6451:         // reach of any one compromised key is bounded in both directions. The
6452:         // remaining consenters are re-keyed below and by the tick.
6453:         //
6454:         // A rotation that cannot persist poisons the channel, which the *next*
6455:         // command reports; it does not un-send the message that just went out, so the
6456:         // append is still reported as the success it was.
6457:         let rotated =
6458:             ch.should_rotate_sender(now) && ch.rotate_sender(profile.store(), now).is_ok();
6459:         self.fresh_details
6460:             .insert(*channel_id, (summary_of(&ch), detail_of(&ch)));
6461:         drop(ch);
6462:         let channel_id = *channel_id;
6463:         let _ = self.event_tx.send(NodeEvent::NewEntry {
6464:             channel_id,
6465:             row: appended,
6466:         });
6467:         // ADR-016: push immediately after a local append. Marking it here and
6468:         // letting the tick do the work keeps authoring off the network path.
6469:         self.note_local_append(&channel_id);
6470:         if rotated {
XX
26://!   is marked **poisoned** and refuses further appends until reopened — the
30://! - Double-lock (ADR-010): opening needs the unlocked identity (the identity
251:/// An open (SEK-unlocked) channel on this device.
697:    /// A local name over the limit, no unlocked signer, or a genesis or key that cannot be made.
722:    /// No unlocked signer, a segment that cannot be sealed, or a store write that fails.
1092:    /// What must hold before a joined room is made: a name within the limit, an unlocked signer,
1622:                "channel is poisoned after a failed persist; reopen it",
1888:                "channel is poisoned after a failed persist; reopen it",
1977:                "channel is poisoned after a failed persist; reopen it",
2104:                    "channel is poisoned after a failed persist; reopen it",
2144:                "channel is poisoned after a failed persist; reopen it",
2310:            // reopen would re-derive a consumed key. Poison instead.
2332:                "channel is poisoned after a failed persist; reopen it",
2427:                "channel is poisoned after a failed persist; reopen it",
2589:    /// Whether a failed persist has poisoned this channel (reopen to continue).
2607:        // can neither unseal nor answer a join until it is reopened (ADR-010/015).
[0m
[0m$ [0mgrep -rn "208" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/*.md | grep -v "ADR-025-sync" | grep -i "reopen\|#208" | head; echo XX; grep -rn "#208\|V210-3[0-9]\|#212\|V210-39" /opt/vox/.claude/worktrees/ac-adr025/docs --include="*.md" -l | head
XX
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-kimi-k3.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review2-astra.md
[0m
[0m$ [0mgrep -n "disjoint\|window" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head; echo XX; grep -n "backoff\|Backoff" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -20
654:    /// window").
2255:    /// answering *everyone* — and a request arriving in that window waits out its own patience and
3193:                // ForwardOnly window f4d13d8 closed on the host's side (see `apply_join_outcome`) was
3458:                    // readable to it, so every tick of delay is a window of posts lost to the
3460:                    // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
3771:        // opened a window in which anything this node posted was unreadable to the
6208:        // announced an address over a window where nothing was listening — a person who
XX
591:    /// A sender key written to `peer` was taken: any backoff on re-sending to it ends.
1777:    key_backoff: BTreeMap<(Digest32, Digest32), (u32, u64)>,
1956:            key_backoff: BTreeMap::new(),
3320:                let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
3359:                self.key_backoff.remove(&(channel_id, peer));
4622:            // A member whose last keys were not taken waits out its backoff, unless a person asked.
4625:                    .key_backoff
4973:        // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
[0m
XX
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md:1835:{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V210-34 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.10.md` at `cde30171222a91d9d8b4466adf56680c61889a0d` (`a224d571633c4af19b76882a47a10fab0f062a88`), V210-34\nAcceptance:\n- As ADR-025 decides.\n\nValidation: ADR-025's proof table, each measured on the base first.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release.\n<!-- work-accountability:end -->\n\n**Sync is scheduled like a switch, not a hub (ADR-025).**\n\nThe decider asked for sync to behave like a switch, \"with slots and queues\". Today:\n- two members posting at once refuse each other's sessions (`SessionBusy`) and retry after a random wait: about 2.3 refused streams per simultaneous round with #180, and 0 late posts;\n- a push past the 16-slot cap is *skipped, not queued*, and can wait for the 30 s interval;\n- a truncated serve counts as done;\n- a receiver stores entries it did not ask for.\n\n**ADR-025** (branch `docs/adr-025-sync-switch`, `docs/adr/ADR-025-sync-scheduling-switch-not-hub.md`) is under three-model review. Revision 3 recommends **full duplex**: inbound sessions are never refused for busy, and both directions run at once, with no collision, tie-break or random wait. It also specifies a per-(room, peer) port with tokens, requests captured at admission, receive coverage, a fair queue over slots, and backoff only for real failures.\n\nNot decided: the option (full duplex / designated opener / glare rule) and whether the collision change goes in v0.2.10 are the decider's.\n\nChecklist (ADR-025 Plan):\n- [ ] S0 #180 and #202 integrated\n- [ ] S0b observability in `vox status --json`\n- [ ] S0c the base measured\n- [ ] S1–S4 implementation\n- [ ] S5 proofs P1–P9\n- [ ] S6 independent verifier\n","number":209,"state":"OPEN","title":"V210-34: Sync is scheduled like a switch, not a hub (ADR-025)"}
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md:1935:### M4. #212 is owned, but its required binary proof is not an acceptance dependency
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md:1937:The inherited deadlock is now explicitly owned by #212, with concurrent serve/drain and an S5 dependency. That resolves the previously missing fix direction and release ownership.
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md:1939:However, the earlier astra/glm requirement included a **bilateral large-backlog binary proof**. P3 remains unilateral, and S5 requires only “#212,” without specifying that its acceptance includes bilateral backlog and concurrent sessions sharing connection credit (`ADR:403,428`).
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md:1974:| K-B2: deadlock omitted/unowned | **RESOLVED** | Explicit #212 ownership and prerequisite answer this finding. |
[0m
[0m$ [0mgrep -rn "#208" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md | head -5; echo XX; grep -rn "disjoint\|window" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | grep -in "retry\|backoff\|half\|halves" | head
XX
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review4-kimi-k3.md
[0m
[0m$ [0mgrep -n "^## \|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md | tail -40; echo XX; grep -n "^## \|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-glm-5.3.md | tail -30
1841:## BLOCKER
1843:### B1. D1a releases accounting resources without establishing worker termination
1864:## MAJOR
1866:### M1. D3’s predicates are obtainable, but `stored` still has the wrong durability boundary
1885:### M2. D5 needs exhaustive outcomes and precedence across concurrent completions
1900:### M3. S0b and several proofs still lack causal discrimination
1935:### M4. #212 is owned, but its required binary proof is not an acceptance dependency
1943:## MINOR
1945:### The headline still promises something D4 explicitly permits
1951:### Remaining implementation decisions
1963:## NIT
1967:## Round-3 finding disposition
1999:## VERDICT
XX
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review4-astra.md[90m [limit=180, offset=1841][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/wire.rs > /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/wire-202.rs; grep -n "ProtocolViolation\|SessionBusy\|EpochMismatch" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/wire-202.rs | head; echo XX; grep -n "fn owed_a_reason" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs
282:    EpochMismatch = 0x08,
308:    SessionBusy = 0x0B,
327:            0x08 => Some(WireError::EpochMismatch),
330:            0x0B => Some(WireError::SessionBusy),
XX
5306:    fn owed_a_reason(&self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
[0m
[0m$ [0mawk 'NR>=290 && NR<=360 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/anchor-180.rs; echo XX; awk 'NR>=440 && NR<=468 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/anchor-180.rs
290:                 }
291:             }
292:         }
293:         let mut out = SyncOutcome {
294:             applied: arrived.len(),
295:             ..SyncOutcome::default()
296:         };
297:         for entry_hash in arrived {
298:             let entry = self
299:                 .dag
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
XX
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
Let me verify a few remaining code facts: the wire error enum, `owed_a_reason`, and the anchor's apply/absorb paths.
[0m$ [0mawk 'NR>=5295 && NR<=5330 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs
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
5321:                 {
5322:                     return true;
5323:                 }
5324:             }
5325:             let (Some(net), Some(store)) = (
5326:                 self.net.as_ref().map(Arc::clone),
5327:                 self.profile.as_ref().map(Profile::store_handle),
5328:             ) else {
5329:                 return false;
5330:             };
[0m
[0m$ [0mgrep -n "absorb_arrived" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs | head; awk 'NR>=1990 && NR<=2040 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs
1991:        let mut out = self.absorb_arrived(store, &before, now_secs)?;
2001:    /// Each author's head, for [`ChannelState::absorb_arrived`] to find what a sync added.
2010:    fn absorb_arrived(
2710:        match ch.absorb_arrived(self.store, &before, self.now_secs) {
1990:         // store (the borrow of `self.dag` ends here).
1991:         let mut out = self.absorb_arrived(store, &before, now_secs)?;
1992:         if let Ok(n) = session {
1993:             out.applied = n;
1994:         }
1995:         match session {
1996:             Ok(_) => Ok(out),
1997:             Err(code) => Err(sync_failure(code)),
1998:         }
1999:     }
2000: 
2001:     /// Each author's head, for [`ChannelState::absorb_arrived`] to find what a sync added.
2002:     fn heads(&self) -> BTreeMap<Digest32, u64> {
2003:         self.authors
2004:             .keys()
2005:             .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
2006:             .collect()
2007:     }
2008: 
2009:     /// Persist, fold and render every entry a sync added past `before`'s heads.
2010:     fn absorb_arrived(
2011:         &mut self,
2012:         store: &Store,
2013:         before: &BTreeMap<Digest32, u64>,
2014:         now_secs: u64,
2015:     ) -> Result<SyncOutcome> {
2016:         let mut arrived: Vec<(Digest32, Digest32, Vec<u8>)> = Vec::new();
2017:         for (author, head) in before {
2018:             let Some(feed) = self.dag.feed(author) else {
2019:                 continue;
2020:             };
2021:             for seq in (head + 1)..=feed.max_seq() {
2022:                 if let Some(entry) = feed.get(seq) {
2023:                     let Some(payload) = entry.payload.clone() else {
2024:                         continue;
2025:                     };
2026:                     arrived.push((*author, entry.entry_hash(), payload));
2027:                 }
2028:             }
2029:         }
2030: 
2031:         let mut out = SyncOutcome {
2032:             applied: arrived.len(),
2033:             ..SyncOutcome::default()
2034:         };
2035:         for (author, entry_hash, payload) in arrived {
2036:             let key = self
2037:                 .authors
2038:                 .get(&author)
2039:                 .ok_or(Error::MalformedGovernance(
2040:                     "synced entry from an unadmitted author",
[0m
[0m$ [0mgrep -n "#208" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review-astra.md | head -3; grep -rn "208" /opt/vox/.claude/worktrees/ac-adr025/docs/release/*.md 2>/dev/null | grep -i "poison\|reopen\|unlock" | head -5; ls /opt/vox/.claude/worktrees/ac-adr025/docs/release/ 2>/dev/null | head
zsh:1: no matches found: /opt/vox/.claude/worktrees/ac-adr025/docs/release/*.md
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review4-glm-5.3.md[90m [limit=120, offset=270][0m
[0m
[0m$ [0mgrep -rn "#208\b" /opt/vox/.claude/worktrees/ac-adr025 --include="*.md" | grep -v "ADR-025-reviews/review4" | head; echo XX; ls /opt/vox/.claude/worktrees/ac-adr025/docs/ | head -20
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md:261:| the room was poisoned | the room's ports retire their attempts and are marked `poisoned`, reported once. **No retry** until the room is reopened (by a person, or by #208's reopen at unlock), which re-creates its ports |
XX
adr
prd
[0m
[0m$ [0mgrep -n "^## VERDICT" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-glm-5.3.md; awk 'NR>=430 && NR<=460 {printf "%d: %s\n", NR, $0}' /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-glm-5.3.md 2>/dev/null | head -40
430: /// `to_vec` so a hostile frame cannot force a large allocation ahead of
431: /// [`Entry::from_wire`]'s own per-field caps (ADR-008 anti-abuse). It is the sum
432: /// of the entry's structural maxima — the payload, the authenticator, and a
433: /// - for every remote feed whose `max_seq` **exceeds** what we hold, request
434: ///   `(local_max + 1 ..= remote_max)` (the ordinary tail-extension case);
435: /// - **and** — the equal-length fork case — when the remote's `max_seq` **equals**
436: ///   our `max_seq` but its `head_hash` **differs** from ours, request the head
437: ///   `(max_seq ..= max_seq)`. Two partitions each holding `(author, seq = N)` with
438: ///   different valid hashes would otherwise never exchange the conflicting entry
439: ///   and no fork proof would form (ADR-008 §"Fork / equivocation handling"). The
440: ///   pulled conflicting entry is fed into DAG fork handling, which freezes the
441: ///   author on an attributable proof and raises an alarm on a deniable one.
442: #[must_use]
443: pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
444:     let mut wants = Vec::new();
445:     for rf in remote {
446:         let local = dag.feed(&rf.author_id);
447:         let local_max = local.map_or(0, |f| f.max_seq());
448:         if rf.max_seq > local_max {
449:             wants.push(WantRange {
450:                 author_id: rf.author_id,
451:                 from_seq: local_max + 1,
452:                 to_seq: rf.max_seq,
453:             });
454:         } else if rf.max_seq == local_max && local_max > 0 {
455:             // Equal head seq: compare the gossiped head hashes. A mismatch is a
456:             // divergence (equal-length fork) — pull the remote head entry so the
457:             // conflict reaches DAG fork handling.
458:             let local_head = local.map_or(crate::log::entry::ZERO_HASH, |f| f.head_hash());
459:             if local_head != rf.head_hash {
460:                 wants.push(WantRange {
[0m
[0m$ [0mgrep -n "^## \(BLOCKER\|MAJOR\|MINOR\|NIT\|VERDICT\)\|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-glm-5.3.md
(no output)
[0m
[0m$ [0mgrep -n "fn unlock\|Unlock" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs | head; echo XX; awk 'NR>=2108 && NR<=2140 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/channel-202.rs
275:        NodeCommand::Unlock { .. } => "unlocking the identity",
2141:            NodeCommand::Unlock { passphrase } => self.unlock(&passphrase).await,
2317:    async fn unlock(&mut self, passphrase: &Secret) -> Outcome {
2334:                let _ = self.event_tx.send(NodeEvent::Unlocked);
6817:        Error::AtRestUnlockFailed => Fault::WrongPassphrase,
XX
2108:         };
2109:         let room = ChannelSessionRoom {
2110:             shared,
2111:             store,
2112:             now_secs,
2113:             epoch,
2114:             out: std::cell::RefCell::new(SyncOutcome::default()),
2115:             fatal: std::cell::RefCell::new(None),
2116:         };
2117:         let session = crate::log::sync::frontier_session_room(transport, &room);
2118:         if let Some(e) = room.fatal.take() {
2119:             return Err(e);
2120:         }
2121:         let mut out = room.out.into_inner();
2122:         match session {
2123:             Ok(n) => {
2124:                 out.applied = n;
2125:                 Ok(out)
2126:             }
2127:             Err(code) => Err(sync_failure(code)),
2128:         }
2129:     }
2130: 
2131:     /// Accept a **sender-key distribution message** from `author` (ADR-006/ADR-007
2132:     /// step 2/3): the sender key that member released to this identity, delivered
2133:     /// over the ADR-004 pairwise session (M14.5b `node::pairwise`).
2134:     ///
2135:     /// The SKDM is verified against the author's admitted key and bound to this
2136:     /// channel and epoch. On acceptance the chain is persisted **and every content
2137:     /// entry already stored from that author is retried**, so a message that arrived
2138:     /// as ciphertext before consent renders as soon as the key arrives — the
2139:     /// monotone per-sender fill-in ADR-007 describes. Returns how many entries that
2140:     /// backfill rendered.
[0m
[0m$ [0mgrep -rn "QUICK" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/*.rs | head; echo XX; grep -rn "disjoint" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/syncstream-180.rs /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-180.rs | head -5; echo XX; grep -rn "vox-0e" /opt/vox/.claude/worktrees/ac-adr025/docs/adr/*.md 2>/dev/null | head -3
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs:178:const QUICK_PUSH_RETRIES: u32 = 3;
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs:3425:                // `QUICK_PUSH_RETRIES` keep the 20–100ms random wait, and past them the push is
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs:3435:                    let wait = if *failures <= QUICK_PUSH_RETRIES {
/var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs:3444:                        let w = (200u64 << (*failures - QUICK_PUSH_RETRIES - 1).min(6)).min(
XX
XX
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md:73:   - **Measured** (vox-0e's harness and #202's proof): 35–47 collisions per 40 simultaneous rounds.
/opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-sync-scheduling-switch-not-hub.md:406:| P6 | vox-0e's gate (3bb6ca1): 2 members, anchor stopped, 60 rounds | as P1 | `busy-refused = 0`; every post within its bound | as P1 |
[0m
[0m$ [0mawk 'NR>=3420 && NR<=3455 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs
3420:                 // **Backed off, desynchronised, and never handed to the 30s tick.** A retry capped at
3421:                 // three and then left to the periodic interval lost messages for up to 30s whenever
3422:                 // both ends kept colliding: the V29-06 verdict caught alice and bob refusing each
3423:                 // other six times in ~200ms, because their 20–100ms random waits kept landing within
3424:                 // 0–8ms of each other, and then a message sat 29.7s. Now the first
3425:                 // `QUICK_PUSH_RETRIES` keep the 20–100ms random wait, and past them the push is
3426:                 // never left to the tick: it backs off with the two ends drawing from disjoint ranges
3427:                 // by fingerprint order. (Doubling from 25ms on the first failure instead was
3428:                 // measured worse: 3 of 60 both-ends relayed runs had a message over 1s, against 0 of
3429:                 // 60 with the quick retries kept.)
3430:                 if outcome.is_err() {
3431:                     let failures = self.push_failures.entry((channel_id, peer)).or_insert(0);
3432:                     *failures = failures.saturating_add(1);
3433:                     let jitter = crate::identity::rng::random_array::<2>()
3434:                         .map_or(0, |b| u64::from(u16::from_le_bytes(b)));
3435:                     let wait = if *failures <= QUICK_PUSH_RETRIES {
3436:                         // A collision almost always clears in one of these: measured 0 of 1,500
3437:                         // relayed rounds with both ends posting at once over 1 s.
3438:                         Duration::from_millis(20 + jitter % 81)
3439:                     } else {
3440:                         // Past them, never the 30 s interval: back off from 200 ms to
3441:                         // `MAX_PUSH_RETRY_WAIT`, the two ends drawing from disjoint halves by
3442:                         // fingerprint order (the lower [w/2, w), the higher [w, 2w)) so two nodes
3443:                         // that keep colliding cannot keep doing it in lockstep.
3444:                         let w = (200u64 << (*failures - QUICK_PUSH_RETRIES - 1).min(6)).min(
3445:                             u64::try_from(MAX_PUSH_RETRY_WAIT.as_millis()).unwrap_or(8_000) / 2,
3446:                         );
3447:                         let lower = self.net.as_ref().is_some_and(|n| n.local_id() < peer);
3448:                         let (from, span) = if lower { (w / 2, w / 2) } else { (w, w) };
3449:                         Duration::from_millis(from + jitter % span.max(1))
3450:                     };
3451:                     let tx = self.net_tx.clone();
3452:                     tokio::spawn(async move {
3453:                         tokio::time::sleep(wait).await;
3454:                         let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
3455:                     });
[0m
[0m$ [0mgrep -n "MAX_PUSH_RETRY_WAIT" /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs | head -3; awk 'NR>=170 && NR<=185 {printf "%d: %s\n", NR, $0}' /var/folders/bd/84n3hd3120sdr990qkfbgvj00000gp/T/opencode/actor-202.rs
174:const MAX_PUSH_RETRY_WAIT: Duration = Duration::from_secs(8);
3441:                        // `MAX_PUSH_RETRY_WAIT`, the two ends drawing from disjoint halves by
3445:                            u64::try_from(MAX_PUSH_RETRY_WAIT.as_millis()).unwrap_or(8_000) / 2,
170: /// The longest a failed `(room, peer)` push waits before its next try; see the `SyncDone` handler.
171: /// Long enough that a peer whose sessions always fail (an anchor keeping no log for the room) costs
172: /// one session every few seconds, not a stream; far shorter than the 30s interval it used to fall
173: /// back to.
174: const MAX_PUSH_RETRY_WAIT: Duration = Duration::from_secs(8);
175: /// How many failed sessions in a row a `(room, peer)` push retries after a short random 20–100ms
176: /// wait, before it backs off (see the `SyncDone` handler). Enough to ride out a collision (both
177: /// sides pushing at once).
178: const QUICK_PUSH_RETRIES: u32 = 3;
179: 
180: /// How often a peer reached over a relay is retried for a direct path.
181: ///
182: /// A relayed path works, so nothing forces a retry — but it costs a third party's bandwidth
183: /// and a round trip, and the conditions that prevented a direct path are usually temporary:
184: /// a NAT mapping expires, a firewall state clears, a laptop leaves a captive network. One
185: /// attempt at dial time is a snapshot of the worst moment, when neither side has learned the
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline -1 3bb6ca1 2>&1 | head -2; git -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline -3 58fde36 2>&1 | head -4; git log --oneline -3 -C /opt/vox/.claude/worktrees/ac-adr025 2>&1 | head -4; git -C /opt/vox/.claude/worktrees/ac-adr025 status --short | head -5; git -C /opt/vox/.claude/worktrees/ac-adr025 log --oneline -1 -- docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
3bb6ca1 test(sync): two members posting at once, with no other path, never wait out the 30 s interval
58fde36 fix(sync): owed publish and new-member pushes no longer wait for a session-free room (#180)
69aaff5 fix(net): a node that stops closes its relayed connections first, so its peers are told rather than left to infer
33da864 fix(sync): one dead member no longer stalls a room for everyone — sync sessions are guarded per room and peer
5846720 docs(adr): ADR-025 revision 4 — retirement, receive classes, backoff kinds, schedule points, journals; round-3 reviews (all BLOCK)
141dc11 docs(adr): ADR-025 revision 3 — full duplex (no busy refusals), request lifecycle, receive coverage, observable proofs; round-2 astra review
16951fe docs(adr): ADR-025 revision 2 — designated opener, observable completion, rebuilt proofs; round-1 reviews (astra BLOCK, glm REVISE, kimi REVISE)
?? docs/adr/ADR-025-reviews/review4-astra.md
?? docs/adr/ADR-025-reviews/review4-glm-5.3.md
?? docs/adr/ADR-025-reviews/review4-kimi-k3.md
5846720 docs(adr): ADR-025 revision 4 — retirement, receive classes, backoff kinds, schedule points, journals; round-3 reviews (all BLOCK)
[0m
Let me verify a couple of last references — the `3bb6ca1` gate commit and the "702–703 refusals" claim's plausibility — then I have everything.
I have everything I need. I read revision 4 (5846720), all three round-3 findings sections, and verified every load-bearing citation against both trees (`58fde36` and `8436100`, including `log/sync.rs`, `log/dag.rs`, `node/actor.rs`, `node/channel.rs`, `node/anchor.rs`, `node/net.rs`, `node/syncstream.rs`, `transport/quic.rs`, `wire.rs`). Nothing was modified.

## 1. Round-3 finding dispositions

**review3-astra.md**
- **B1 (bilateral serve-before-drain deadlock): PARTIAL.** Owned as #212 with a fix direction (concurrent serve/drain) and an S5 dependency — the finding's spec half is met. Its other half, "add a real-binary bilateral large-backlog proof," is not met anywhere: P3 stays one-directional, which is the one shape that works without #212 (the empty side drains while the full side serves). See MAJOR-6.
- **B2 (peer-trusted bounds): RESOLVED.** The held queue is gone (`INBOUND_PER_PORT=3`, then immediate `SessionBusy`), coverage is interval arithmetic, and zero-progress is paced by D3's no-progress row + D5 `NoProgress`. The manufacture-failures-for-correct-peers hole dies with holding.
- **M1 (stale completion as filtering, not lifecycle): PARTIAL.** D1a retires and unwedges the port, but it misdescribes the mechanism (MAJOR-4), and consent-waiter migration is still only the planned keying change (ADR:334–335).
- **M2 (classes need policy/durability definitions): PARTIAL.** Split marked as a code change, "revoked" correctly dropped (verified: revocation never touches the author map, `202:node/channel.rs:1806–1836`; resolver reads `self.authors`, 1936–1943), poison is terminal. Residue: a session that hard-fails mid-batch (Verification/Feed) has absorbed a durable prefix (`202:node/channel.rs:2701–2721`) but gets no class row or D5 kind at all (MAJOR-5).
- **M3 (proof discrimination): PARTIAL.** P1/P2/P3/P5/P9/P10 adequately fixed; P4, P7(second mutant), P8 still don't discriminate (MAJOR-1–3).
- **M4 (S0b can't supply the evidence): PARTIAL.** Sequenced journals with overflow counters and the field list cover most preconditions; residuals in MINOR-9.
- **m1: RESOLVED** (`done_gen = max(...)`, ADR:220). **m2: RESOLVED** (the right case is now named, ADR:306–309). **m3: RESOLVED** (1+3 stated; consent bullet now marked planned).

**review3-glm-5.3.md**
- **B1: PARTIAL** (as astra B1). The ADR's rebuttal of glm's "the glare serialises it" is correct: one session already carries both directions and serves before draining (`180:log/sync.rs:886–914`), so the deadlock never needed two sessions.
- **B2 (stale `SyncDone` wedges the port): RESOLVED.** D1a retires the attempt out of `out`/`inbound`, which is the wedge glm named.
- **M1 (holding unsafe): RESOLVED** — holding is removed.
- **M2 (classes not computable): RESOLVED.** The `NotAdmitted` split is explicitly a `dag.rs` code change (ADR:244), and the predicates check out at both apply sites (`202:node/channel.rs:2694–2721`; `180:node/anchor.rs:450–467`; frozen-vs-unadmitted at `202:log/dag.rs:313–315` vs 323–324; missing key at `180:log/sync.rs:608–611`; poison at `202:node/channel.rs:2050–2052`).
- **M3: PARTIAL** (P4/P7/P8). **M4: PARTIAL.**
- **m1, m2, m3, m4, m5: RESOLVED** (D5 cleared-by rules, ADR:297; consent bullet, ADR:334; envelope 1+3, ADR:147,181–182).

**review3-kimi-k3.md**
- **B1: RESOLVED** (D1a). **B2: RESOLVED** — the finding demanded "claimed or explicitly deferred"; the ADR does exactly that (#212, ADR:27–28, 102–107, 386).
- **B3 (zero-progress loop): RESOLVED.** Progress is monotone per position (each requested position fills once; duplicates count but cannot be re-filled), so the only unbounded case left is paced by `NoProgress`. One residual amplifier at MINOR-10.
- **B4: PARTIAL.** P3's byte leg is fixed (140 MiB > 2×64 MiB ⇒ ≥2 truncations); P7/P8 are not (MAJOR-1, MAJOR-3).
- **M1: RESOLVED. M2: PARTIAL** (durable boundary is handled via poison, but per-entry classes on a hard-failed batch are unmapped — MAJOR-5). **M3: RESOLVED** — D6a (ADR:311–326) is the right answer; the replaced wake sites exist as cited (`180:node/actor.rs:3450–3453, 4730–4740, 4788–4801`).
- **m1, m3, m4, m5, m6: RESOLVED** (the #202-rewrite setup does pin `owed_a_reason` — the board-record disjunct at `202:node/actor.rs:5306–5313` matches the ADR's new setup). **m2: RESOLVED in design, but its justification is false** (MINOR-11).

## 2. D1a retirement

**Safety:** yes, with a misdescription. The actual structure is an async supervisor awaiting `spawn_blocking` (`180:node/actor.rs:5117–5142`); neither aborting the supervisor nor the join handle interrupts a started blocking closure. But the room lock is only ever held inside a `SessionRoom` step (`202:node/channel.rs:2694–2721`, `180:node/anchor.rs:450–467`), never across transport I/O — so no abort can leave the lock held, and each retirement cause independently kills the worker anyway: epoch change and poison are fenced at the next room step (`202:node/channel.rs:2660–2666`; `180:node/anchor.rs:415–422`), connection death fails the next transport op within the 20 s frame timeout, shutdown exits the process. Stores are durable and idempotent (`202:log/dag.rs:317–319`). So the claim "stores the old worker made **before the abort** stay" is wrong — the worker keeps storing **after** the abort until fencing stops it — but the safety conclusion stands. **MAJOR-4**: say this, and say the slot bounds admitted attempts, not running workers (a retired worker drains beside its replacement), and whether a retired worker's completion still reports — P7's second mutant depends on the answer (MAJOR-3).

**Permit exactly-once:** yes, structurally — the permit lives in the `Attempt`, which is removed from `out`/`inbound` exactly once (retirement or current-token completion); both paths take the map entry. Panics still funnel through `SyncDone` (`180:node/actor.rs:5137–5142`). No double-release path exists.

**"Displaced but carried is not death": consistent.** A displaced live connection is retired and kept serving (`202:node/net.rs:846–855`), and is closed only when grace has elapsed *and* nothing carries it, or it is dead (874–898). A sync worker holding its `Arc` keeps the connection alive; the attempt stays attributed. New outbound sessions simply use the current connection. Consistent with D1a.

## 3. D3 classes

**Predicates are available at the apply point.** Both `apply` implementations hold the room lock with `dag`, `resolver()`, `admission` in scope (`202:node/channel.rs:2694–2700`; `180:node/anchor.rs:450–456`). The frozen/unadmitted split is implementable inside `Dag::accept`, where both rejections are produced on adjacent branches (`202:log/dag.rs:313–315`, 323–324). "No resolver key" is observable before acceptance (`180:log/sync.rs:608–611`). Poison is observable in `absorb_arrived` (`202:node/channel.rs:2050–2052`). All marked as code changes; accurate.

**"Classify and continue" is safe.** `Dag::accept`'s ordered predicate (governance-attributable → frozen → duplicate → admission → verify → equivocation → feed-link, `202:log/dag.rs:296–360`) still runs per entry. Skipping an unadmitted entry cannot admit a later same-feed entry: the feed-link check (354–358) rejects it as `Rejected::Feed`, which remains a hard fail. There are no cross-author causal edges at this layer (`202:log/dag.rs:393–396`). What changes versus failing: the rest of the batch and stream is applied (each entry fully checked — nothing gets stored that failing would have prevented) and the sender is no longer told by a stream close. That is a deliberate, safe semantics change.

One inaccuracy: the class table's "Today: fails the session" for fork is **false** — today a fork already continues (`180:log/sync.rs:618` maps `Rejected::Fork` to `Ok(ApplyOutcome::Fork)`; `apply_staged` continues, 924–940). Only the *classification* is new. (MINOR-11.)

## 4. D4 / D5 / D6a — loops, starvation, wedges

- **No remaining unbounded loop.** `NoProgress` paces the one kimi found (B3); filled-position progress is monotone, so a duplicate-serving peer terminates as "clean"; a serve-nothing peer backs off (P10's arithmetic checks: 1→2→4→8→16 gives ~5 sessions in 30 s ≤ 6). Residual: "a newly admitted author" is peer-manufacturable progress — a member feeding one fresh valid board record per session resets `failures` forever (MINOR-10).
- **No wedge.** Retirement frees the port; `SessionBusy` is immediate; `BackoffExpired` re-arms with token staleness handled; D6a's event list covers every transition I could trace (generation bump, request, `SyncDone`, slot release, expiry, connection open/close, epoch, room open/poison).
- **Starvation:** the 4 stalled peers × 4 slots = 16 case is now disclosed with the right victim (ADR:306–309). Note the stall is longer than "a frame timeout of 20 s, plus the budgets": an outbound attempt also spans the learn-members round trips and stream open (`180:node/actor.rs:5033–5112`). NIT.
- **Gap:** D1's needs-session iff omits the backoff gate; it currently rests on D5's "ordinary triggers wait it out." Fold "no active backoff" into the predicate (MINOR-8).

## 5. S0b and P1–P10

- **P1, P2, P3, P5, P6, P9, P10 discriminate** as written (P2 via the CANNOT-MEASURE rule on its queued-event precondition; P3's mutant goes red through the generation arithmetic: a truncated serve counted clean leaves Bob short at the 20 s bound; P5/P6 inherit their fixes' caveats below).
- **P4: mutant green (MAJOR-2).** "learn_members first" is the ordinary outbound setup (`180:node/actor.rs:5033–5089`) that every outbound attempt runs — the ADR says so itself (ADR:260). With the unadmitted-specific request removed, the outcome still falls into "some unfilled, no progress" → request + `NoProgress` backoff (first step 1 s), and the retry admits Carol and fetches within the ≤2 s assert. The mutant removes only immediacy. The assert must bound below the first backoff step, or the journal must name request *causes* and the assert must name the retry's cause.
- **P7: second mutant green (MAJOR-3).** Retirement aborts the supervisor, so the old `SyncDone` is never sent (`180:node/actor.rs:5129–5142` never runs); a removed stale-result guard has nothing to admit. The mutant only bites if retired workers still report — which is exactly the D1a decision in MAJOR-4. (First mutant — retirement removed — is red: the port wedges, no new outbound in 2 s.)
- **P8: still broken (MAJOR-1).** Revision 4 fixed the direction check but not the rescue. "Bob down 5 s, then back" is a new connection at both ends (the old one is dead by silence: `SILENCE_IS_DEATH` = 1.5×`KEEP_ALIVE` = 30 s, `202:node/net.rs:336`, `202:transport/quic.rs:162`). D5 **clears** backoff on a new connection (ADR:297), D2 raises a request on it (ADR:212), D6a schedules on it (ADR:320) — Alice's outbound completes with no `BackoffExpired`, mutant green. Worse, if "cleared" is journaled distinctly from "expired," the *precondition* ("entered, then expired") is unmet on the correct build → CANNOT MEASURE. kimi's round-3 finding was only half-answered: the same reconnect rescue now operates on Alice's side by design. Rebuild the scenario with the connection held up while sessions fail (Busy or a session-erroring peer).
- **P9/P10 are legitimate real-use proofs.** The receiver under test is the production binary driving the real QUIC path; the mutant is a minimally-altered build of the same shipped binary. An honest peer never produces these inputs, so this is the *only* way to prove receiver-side defenses under the project rule — provided the mutant changes only sender behavior and (for P9) the extra entry is otherwise valid and admissible, so no earlier rejection masks the coverage mutant. P9's `ProtocolViolation` clause alone would red on a reason-string mismatch; keep the valid-entry requirement so the stored/absent clause is the one that matters.
- **S0b residuals (MINOR-9):** no request-raise events with cause — D7's "no proof passes because of it" is unenforceable (P8's 9 s window can contain a 30 s tick indistinguishably); served-ids capped at 32 cannot prove an id was *not* served (P5's precondition) once a session serves more; state the rule.
- `ProtocolViolation` is not in the wire enum (`202:wire.rs` has `EpochMismatch` 0x08, `SessionBusy` 0x0B, no such variant). Wire change is allowed; say which it is (MINOR-7).

## 6. Specificity, open decisions, tree accuracy

Implementable except for: (1) the D5 kind mapping for the remaining hard fails (Verification/Feed/malformed-frame/local non-persist) — MAJOR-5; (2) `ProtocolViolation` wire-vs-local; (3) the backoff clause in the needs-session predicate; (4) D1a's reporting rule (retired worker's completion: reported or not); (5) `vox room sync`'s reply when the port is queued — "Done once a session starts" (`180:node/actor.rs:5202–5223`) is incoherent with queueing, since a queued port starts nothing and today's code would answer `Unreachable`; (6) consent-waiter migration on retirement, beyond the planned keying; (7) what "newly from P" means for `nP` when a session stores third-party authors' entries.

**False about the trees:** the fork row's "fails the session" (above); D5's Policy row "as today, not every 8 s" — against the ADR's own #202 baseline, today a permanently-refused push backs off on the disjoint windows capped at `MAX_PUSH_RETRY_WAIT = 8 s`, never the tick (`202:node/actor.rs:174, 3430–3449`), so 30 s flat is a change (a defensible one — *less* chatter), not "as today"; "#208's reopen at unlock" (ADR:261) — no trace of #208 anywhere in the repo's docs, and the only reopen in the tree is manual ("reopen it", `202:node/channel.rs:2104`): unverifiable citation, drop or ground it. **Planned work described as done:** none found — the consent keying, the `NotAdmitted` split, and the class semantics are all marked planned, and #212 is "not yet reproduced" with the fix owned elsewhere.

Not verifiable read-only: the harness numbers (35–47 collisions, 702–703 refusals) and vox-0e's gate (3bb6ca1 exists).

## BLOCKER

None. I specifically looked for corruption, deadlock, and wedge in D1–D7 as specified and found none that survives the fencing checks.

## MAJOR

1. **P8 cannot discriminate:** D5's cleared-by-new-connection + D2's request-on-connect + D6a's connection-opened pass rescue the mutant on Alice's side; the precondition may be unmeetable on the correct build.
2. **P4's mutant is green:** every outbound runs learn-members anyway, and the general no-progress row re-raises the request with only a 1 s delay.
3. **P7's second mutant is green** while retirement aborts the supervisor (no stale `SyncDone` ever exists for the removed guard to admit).
4. **D1a misdescribes its mechanism:** abort doesn't stop a started worker; the fencing does. State it, state that slots bound attempts not workers, and decide whether retired completions report.
5. **D5 is not exhaustive:** Verification/Feed/malformed/local-non-persist failures have no kind; an implementer must invent retry policy in exactly the adversary-facing cases.
6. **#212's bilateral proof is not an acceptance item:** S5 "depends on #212" but no row exercises simultaneous large backlogs in both directions; P3 is the one shape that works without the fix.

## MINOR

7. `ProtocolViolation`: wire-visible (new code) or local reason — undecided.
8. Backoff missing from the needs-session iff.
9. S0b: no request-cause events (D7 unenforceable); 32-id served cap can't prove absence (P5).
10. "Newly admitted author" is peer-manufacturable progress; resets `NoProgress`.
11. Tree inaccuracies: fork "fails today" (it continues, `180:log/sync.rs:618`, 924–940); Policy "as today" (today is ≤8 s, `202:node/actor.rs:174,3440–3449`).
12. "#208's reopen at unlock" — unverifiable citation.

## NIT

13. "1 out + 3 in" counts attempts, not draining workers. 14. `vox room sync` reply vs queued ports. 15. D6's stall bound omits the learn-members/open span. 16. The revision table's "not yet reviewed" will be stale on landing, as revision 3's was.

## VERDICT

**REVISE.** The architecture survives attack: full duplex with per-port retirement, interval coverage, computable classes, and kind-based backoff has no remaining corruption, deadlock, or wedge that I could construct against the two trees. What fails is the proof table's discrimination (P4, P7, P8) and the finish on the specification (D1a's mechanism, D5's exhaustiveness). Both are revisable without touching the design.

The three changes I would most insist on:

1. **Rewrite D1a's mechanism and take its consequence:** the abort does not stop a started `spawn_blocking` worker; each retirement cause's existing fencing does (epoch/poison at the next room step, connection death at the next transport op). Say slots bound admitted attempts, not running workers; decide whether a retired worker's completion still reports — then make P7's second mutant real against that decision.
2. **Make P4 and P8 discriminate:** P8's scenario must enter backoff with the connection held up (a reconnect clears backoff and raises a request, rescuing the mutant on Alice's side exactly as round 3 found on Bob's); P4's mutant must remove the retry itself, or S0b must record request causes and the assert must name the retry's cause.
3. **Close the failure-mapping and release-gate gaps:** an exhaustive D5 kind mapping (or explicit terminal/default rule) for every hard-fail path, `ProtocolViolation` declared wire-visible or local, the backoff clause folded into D1's predicate — and a bilateral concurrent-session large-backlog proof named as part of #212's acceptance inside S5, since full duplex makes that shape the common case.
