[0m
> build · gpt-6-astra
[0m
[0m⚙ [0mak_skill_search {"query":"github-work-accountability","limit":1}
[0m→ [0mSkill "github-work-accountability"
[0m✱ [0mGlob "**/AGENTS.md"[90m in . · 0 matches[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m✱ [0mGlob "*"[90m in docs/adr/ADR-025-reviews · 7 matches[0m
[0m
[0m$ [0mawa status --json
{"host": "github.com", "managed": true, "managed_issue_count": 201, "repository": "robertelee78/vox", "schema": "agent-work-accountability/status-v1", "transport": "github-rest-search"}
[0m
[0m✱ [0mGrep "^## (BLOCKER|MAJOR|MINOR|NIT|VERDICT)|^###|^## "[90m in docs/adr/ADR-025-reviews/review2-astra.md · 39 matches[0m
[0m✱ [0mGrep "^## BLOCKER"[90m in docs/adr/ADR-025-reviews/review-astra.md · 4 matches[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-kimi-k3.md
[0m→ [0mRead docs/adr/ADR-025-reviews/review-glm-5.3.md
[0m→ [0mRead /Users/robert.lee/.config/opencode/skills/github-work-accountability/references/work-model.md[90m [limit=100][0m
[0m
[0m$ [0mgit log -1 --format='%h %s' && git -C /opt/vox/.claude/worktrees/ac-fix202 log -1 --format='%h %s'
141dc11 docs(adr): ADR-025 revision 3 — full duplex (no busy refusals), request lifecycle, receive coverage, observable proofs; round-2 astra review
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review2-astra.md[90m [offset=4133, limit=190][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-astra.md[90m [offset=1607, limit=165][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | nl -ba
...output truncated...

Full output saved to: /Users/robert.lee/.local/share/opencode/tool-output/tool_0dd401589001bj4h5OxAIo7BZp

    58	use crate::log::negentropy::{self, Role, MAX_MESSAGE_LEN as MAX_NEG_MESSAGE_LEN};
    59	use crate::wire::{FrameId, WireError, SYNC_MODE_FRONTIER, SYNC_MODE_RANGE_RECONCILIATION};
    60	
    61	/// The whole drain phase's budget, however many frames arrive.
    62	///
    63	/// Chosen absolutely, not derived from the per-frame timeout. A room's lock is held for the entire
    64	/// session, so this is how long one member may stop every other operation on that room — a bound on
    65	/// what the rest of the node will tolerate, which is a different question from how patient any one
    66	/// frame should be. The two must not be tied: a per-frame bound tightened to abandon a dead peer
    67	/// sooner would otherwise also abandon an honest sync that is merely slow.
    68	///
    69	/// The references bound the total as well as the gap, for this reason: go-libp2p's relay sets a
    70	/// per-stream timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor
    71	/// reclaims a circuit on total idle. A per-frame bound alone defends only against a peer that
    72	/// stops, never against one that drips.
    73	const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
    74	
    75	/// The most entries one session serves to a peer's `WANT`.
    76	///
    77	/// The session holds the room's lock throughout, so what one peer may ask for is
    78	/// what every other operation on the room waits behind. This bounds one session,
    79	/// not a catch-up: the requester applies what it got and, because it applied
    80	/// something, syncs again at once for the rest (see the module docs). A thousand
    81	/// entries verify and file in well under the requester's `DRAIN_BUDGET`.
    82	pub const MAX_SERVE_ENTRIES: usize = 1024;
    83	
    84	/// The most entry bytes one session serves, for the same reason as
    85	/// [`MAX_SERVE_ENTRIES`]: a single entry may be up to [`MAX_PAYLOAD_LEN`], so a
    86	/// count alone would still let one `WANT` pull gigabytes into memory. At least one
    87	/// entry is always served, so an entry larger than this still gets through.
    88	pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;
    89	
    90	/// The serve phase's wall-clock budget. Each frame is bounded by the transport,
    91	/// but a peer that *reads* one frame every nineteen seconds would otherwise keep
    92	/// the room's lock for as long as there are entries to send — the drip that
    93	/// `DRAIN_BUDGET` closes on the other direction. Stopping here is not a failure:
    94	/// what was served is kept, and the requester comes back for the rest.
    95	pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
    96	
    97	/// Hard upper bound on an `ENTRY` frame's carried wire bytes, checked **before**
    98	/// `to_vec` so a hostile frame cannot force a large allocation ahead of
    99	/// [`Entry::from_wire`]'s own per-field caps (ADR-008 anti-abuse). It is the sum
   100	/// of the entry's structural maxima — the payload, the authenticator, and a
   101	/// generous fixed overhead for the skeleton/CBOR framing.
   102	pub const MAX_ENTRY_WIRE: usize = MAX_PAYLOAD_LEN + MAX_AUTHENTICATOR_LEN + 4096;
   103	
   104	/// An abstract bidirectional, reliable, ordered byte-frame transport.
   105	///
   106	/// M5 defines this trait so the sync logic is transport-agnostic; the real QUIC
   107	/// stream is M9 (ADR-011). A frame is an opaque byte vector (the caller frames
   108	/// with [`FrameId`] + CBOR). `close` carries the M0 wire error code on a hard
   109	/// fail (the QUIC application-close mapping is M9).
   110	pub trait Transport {
   111	    /// Send one framed message. Errors are surfaced; the sync engine treats a
   112	    /// send error as a transport failure and aborts.
   113	    fn send(&mut self, frame: &[u8]) -> Result<()>;
   114	
   115	    /// Receive the next framed message, or `Ok(None)` if the peer half-closed
   116	    /// (no more frames).
   117	    fn recv(&mut self) -> Result<Option<Vec<u8>>>;
   118	
   119	    /// Close the stream with a Vox application error code (ADR-008). After a
   120	    /// close the peer must not send/receive further frames.
   121	    fn close(&mut self, code: WireError);
   122	
   123	    /// Cleanly finish the **send** direction: no more frames will be sent, and the
   124	    /// peer's [`Transport::recv`] should observe end-of-stream (`Ok(None)`) once it
   125	    /// has drained the frames already sent. This is the *success* terminator,
   126	    /// distinct from the hard-fail [`Transport::close`].
   127	    ///
   128	    /// The default is a no-op: the in-memory [`DuplexTransport`] signals
   129	    /// end-of-stream implicitly (an empty inbox reads as `Ok(None)`), so it needs
   130	    /// nothing here. A real ordered byte transport (the QUIC mapping, M9) overrides
   131	    /// this to FIN its send stream so the peer's blocking read terminates.
   132	    fn finish(&mut self) {}
   133	}
   134	
   135	/// An in-memory duplex transport pairing two endpoints by shared queues, for
   136	/// tests and local reconciliation. Not used in production (QUIC is M9).
   137	#[derive(Debug, Default)]
   138	pub struct DuplexTransport {
   139	    /// Frames this endpoint will read (pushed by the peer).
   140	    inbox: VecDeque<Vec<u8>>,
   141	    /// Frames this endpoint writes (the peer reads from here).
   142	    outbox: VecDeque<Vec<u8>>,
   143	    /// The last close code observed on this endpoint, if any.
   144	    closed: Option<WireError>,
   145	}
   146	
   147	impl DuplexTransport {
   148	    /// Create a connected pair `(a, b)`: `a`'s outbox feeds `b`'s inbox via
   149	    /// [`DuplexTransport::pump`].
   150	    #[must_use]
   151	    pub fn pair() -> (Self, Self) {
   152	        (Self::default(), Self::default())
   153	    }
   154	
   155	    /// Move all of `a`'s outbox into `b`'s inbox and vice-versa (one exchange
   156	    /// step). Returns the number of frames moved in total.
   157	    pub fn pump(a: &mut Self, b: &mut Self) -> usize {
   158	        let mut moved = 0;
   159	        while let Some(f) = a.outbox.pop_front() {
   160	            b.inbox.push_back(f);
   161	            moved += 1;
   162	        }
   163	        while let Some(f) = b.outbox.pop_front() {
   164	            a.inbox.push_back(f);
   165	            moved += 1;
   166	        }
   167	        moved
   168	    }
   169	
   170	    /// Whether this endpoint was closed, and with what code.
   171	    #[must_use]
   172	    pub fn close_code(&self) -> Option<WireError> {
   173	        self.closed
   174	    }
   175	}
   176	
   177	impl Transport for DuplexTransport {
   178	    fn send(&mut self, frame: &[u8]) -> Result<()> {
   179	        if self.closed.is_some() {
   180	            return Err(Error::MalformedBundle("sync: send on closed transport"));
   181	        }
   182	        self.outbox.push_back(frame.to_vec());
   183	        Ok(())
   184	    }
   185	
   186	    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
   187	        Ok(self.inbox.pop_front())
   188	    }
   189	
   190	    fn close(&mut self, code: WireError) {
   191	        self.closed = Some(code);
   192	    }
   193	}
   194	
   195	/// One feed's frontier summary: `(author_id, max_seq, head_hash)` (ADR-008 HAVE).
   196	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
   197	pub struct FeedFrontier {
   198	    /// The feed's author fingerprint.
   199	    pub author_id: Digest32,
   200	    /// The highest seq the peer holds.
   201	    pub max_seq: u64,
   202	    /// The hash of the head entry (for fork-head comparison).
   203	    pub head_hash: Digest32,
   204	}
   205	
   206	/// A requested range `(author_id, from_seq, to_seq)` inclusive (ADR-008 WANT).
   207	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
   208	pub struct WantRange {
   209	    /// The feed's author fingerprint.
   210	    pub author_id: Digest32,
   211	    /// The first missing seq (inclusive).
   212	    pub from_seq: u64,
   213	    /// The last missing seq (inclusive).
   214	    pub to_seq: u64,
   215	}
   216	
   217	// ---------------------------------------------------------------------------
   218	// Frame encode / decode
   219	// ---------------------------------------------------------------------------
   220	
   221	/// Encode a `HELLO {mode_bitmap}` frame.
   222	#[must_use]
   223	pub fn encode_hello(mode_bitmap: u8) -> Vec<u8> {
   224	    let mut e = Encoder::new();
   225	    e.uint(u64::from(mode_bitmap));
   226	    framed(FrameId::Hello, e.finish())
   227	}
   228	
   229	/// Encode a `HAVE` frame from a peer's feed frontiers.
   230	#[must_use]
   231	pub fn encode_have(frontiers: &[FeedFrontier]) -> Vec<u8> {
   232	    let mut e = Encoder::new();
   233	    e.array(frontiers.len());
   234	    for f in frontiers {
   235	        e.array(3)
   236	            .bytes(&f.author_id)
   237	            .uint(f.max_seq)
   238	            .bytes(&f.head_hash);
   239	    }
   240	    framed(FrameId::Have, e.finish())
   241	}
   242	
   243	/// Encode a `WANT` frame.
   244	#[must_use]
   245	pub fn encode_want(ranges: &[WantRange]) -> Vec<u8> {
   246	    let mut e = Encoder::new();
   247	    e.array(ranges.len());
   248	    for r in ranges {
   249	        e.array(3)
   250	            .bytes(&r.author_id)
   251	            .uint(r.from_seq)
   252	            .uint(r.to_seq);
   253	    }
   254	    framed(FrameId::Want, e.finish())
   255	}
   256	
   257	/// Encode an `ENTRY` frame carrying a framed entry's wire bytes.
   258	#[must_use]
   259	pub fn encode_entry(entry_wire: &[u8]) -> Vec<u8> {
   260	    let mut e = Encoder::new();
   261	    e.bytes(entry_wire);
   262	    framed(FrameId::Entry, e.finish())
   263	}
   264	
   265	/// Encode a `NEG` frame carrying a Negentropy message's wire bytes.
   266	#[must_use]
   267	pub fn encode_neg(neg_msg: &[u8]) -> Vec<u8> {
   268	    let mut e = Encoder::new();
   269	    e.bytes(neg_msg);
   270	    framed(FrameId::Neg, e.finish())
   271	}
   272	
   273	/// Prefix a CBOR body with its 1-byte frame id.
   274	fn framed(id: FrameId, body: Vec<u8>) -> Vec<u8> {
   275	    let mut out = Vec::with_capacity(body.len() + 1);
   276	    out.push(id.as_u8());
   277	    out.extend_from_slice(&body);
   278	    out
   279	}
   280	
   281	/// A decoded sync frame.
   282	#[derive(Debug, Clone, PartialEq, Eq)]
   283	pub enum SyncFrame {
   284	    /// `HELLO {mode_bitmap}`.
   285	    Hello(u8),
   286	    /// `HAVE {frontiers}`.
   287	    Have(Vec<FeedFrontier>),
   288	    /// `WANT {ranges}`.
   289	    Want(Vec<WantRange>),
   290	    /// `ENTRY {entry_wire}` — the raw framed entry bytes (parsed by the caller).
   291	    Entry(Vec<u8>),
   292	    /// `NEG {negentropy_msg}` — the raw Negentropy wire bytes.
   293	    Neg(Vec<u8>),
   294	}
   295	
   296	/// Decode a sync frame. Rejects an unknown frame id (→ a
   297	/// [`WireError::SyncModeUnsupported`] close at the caller) or a malformed body.
   298	pub fn decode_frame(bytes: &[u8]) -> Result<SyncFrame> {
   299	    let id_byte = *bytes
   300	        .first()
   301	        .ok_or(Error::MalformedBundle("sync empty frame"))?;
   302	    let id = FrameId::from_u8(id_byte).ok_or(Error::MalformedBundle("sync unknown frame id"))?;
   303	    let body = &bytes[1..];
   304	    match id {
   305	        FrameId::Hello => {
   306	            let mut d = Decoder::new(body);
   307	            let bitmap = u8::try_from(d.uint()?)
   308	                .map_err(|_| Error::MalformedBundle("hello bitmap range"))?;
   309	            d.finish()?;
   310	            Ok(SyncFrame::Hello(bitmap))
   311	        }
   312	        FrameId::Have => {
   313	            let mut d = Decoder::new(body);
   314	            let n = d.array()?;
   315	            let mut v = Vec::with_capacity(n.min(1024));
   316	            for _ in 0..n {
   317	                if d.array()? != 3 {
   318	                    return Err(Error::MalformedBundle("have tuple arity"));
   319	                }
   320	                let author_id = take_digest(&mut d)?;
   321	                let max_seq = d.uint()?;
   322	                let head_hash = take_digest(&mut d)?;
   323	                v.push(FeedFrontier {
   324	                    author_id,
   325	                    max_seq,
   326	                    head_hash,
   327	                });
   328	            }
   329	            d.finish()?;
   330	            Ok(SyncFrame::Have(v))
   331	        }
   332	        FrameId::Want => {
   333	            let mut d = Decoder::new(body);
   334	            let n = d.array()?;
   335	            let mut v = Vec::with_capacity(n.min(1024));
   336	            for _ in 0..n {
   337	                if d.array()? != 3 {
   338	                    return Err(Error::MalformedBundle("want tuple arity"));
   339	                }
   340	                let author_id = take_digest(&mut d)?;
   341	                let from_seq = d.uint()?;
   342	                let to_seq = d.uint()?;
   343	                v.push(WantRange {
   344	                    author_id,
   345	                    from_seq,
   346	                    to_seq,
   347	                });
   348	            }
   349	            d.finish()?;
   350	            Ok(SyncFrame::Want(v))
   351	        }
   352	        FrameId::Entry => {
   353	            let mut d = Decoder::new(body);
   354	            // `d.bytes()` borrows (length bounded by remaining input, no alloc);
   355	            // check the borrowed length against the cap BEFORE `to_vec`.
   356	            let slice = d.bytes()?;
   357	            if slice.len() > MAX_ENTRY_WIRE {
   358	                return Err(Error::SizeLimitExceeded("sync ENTRY frame"));
   359	            }
   360	            let wire = slice.to_vec();
   361	            d.finish()?;
   362	            Ok(SyncFrame::Entry(wire))
   363	        }
   364	        FrameId::Neg => {
   365	            let mut d = Decoder::new(body);
   366	            let slice = d.bytes()?;
   367	            if slice.len() > MAX_NEG_MESSAGE_LEN {
   368	                return Err(Error::SizeLimitExceeded("sync NEG frame"));
   369	            }
   370	            let msg = slice.to_vec();
   371	            d.finish()?;
   372	            Ok(SyncFrame::Neg(msg))
   373	        }
   374	    }
   375	}
   376	
   377	fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
   378	    d.bytes()?
   379	        .try_into()
   380	        .map_err(|_| Error::MalformedBundle("sync digest length"))
   381	}
   382	
   383	/// Negotiate the sync mode from two mode bitmaps: the highest bit both set
   384	/// (range-reconciliation preferred over frontier). Frontier is mandatory, so if
   385	/// both at least set frontier the result is always at least frontier; if a peer
   386	/// sets *no* common bit, [`WireError::SyncModeUnsupported`] is returned.
   387	pub fn negotiate_mode(local: u8, remote: u8) -> std::result::Result<u8, WireError> {
   388	    let common = local & remote;
   389	    if common & SYNC_MODE_RANGE_RECONCILIATION != 0 {
   390	        Ok(SYNC_MODE_RANGE_RECONCILIATION)
   391	    } else if common & SYNC_MODE_FRONTIER != 0 {
   392	        Ok(SYNC_MODE_FRONTIER)
   393	    } else {
   394	        Err(WireError::SyncModeUnsupported)
   395	    }
   396	}
   397	
   398	// ---------------------------------------------------------------------------
   399	// Resolver — maps an author fingerprint to its composite root key.
   400	// ---------------------------------------------------------------------------
   401	
   402	/// Resolves an author fingerprint to that author's composite root public key and
   403	/// entry kind, so received entries can be verified + classified. The population
   404	/// of this mapping is the identity/consent layers' job (M1/M6); sync only
   405	/// consumes it.
   406	pub trait AuthorResolver {
   407	    /// The composite root key for `author`, or `None` if unknown (an entry from an
   408	    /// unknown author is refused — it cannot be verified).
   409	    fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey>;
   410	
   411	    /// The entry kind for an entry, used to choose the fork remedy. M5 has no way
   412	    /// to read encrypted payloads, so the default is [`EntryKind::Content`]; M6/M7
   413	    /// override for governance entries.
   414	    fn kind_for(&self, _entry: &Entry) -> EntryKind {
   415	        EntryKind::Content
   416	    }
   417	}
   418	
   419	// ---------------------------------------------------------------------------
   420	// Frontier-mode sync.
   421	// ---------------------------------------------------------------------------
   422	
   423	/// Build the local `HAVE` frontiers from a [`Dag`] (one per author feed).
   424	#[must_use]
   425	pub fn frontiers_of(dag: &Dag) -> Vec<FeedFrontier> {
   426	    dag.authors()
   427	        .into_iter()
   428	        .filter_map(|author| {
   429	            dag.feed(&author).map(|feed| FeedFrontier {
   430	                author_id: author,
   431	                max_seq: feed.max_seq(),
   432	                head_hash: feed.head_hash(),
   433	            })
   434	        })
   435	        .collect()
   436	}
   437	
   438	/// Given the *remote* peer's `HAVE` frontiers and the local [`Dag`], compute the
   439	/// `WANT` ranges the local peer needs:
   440	/// - for every remote feed whose `max_seq` **exceeds** what we hold, request
   441	///   `(local_max + 1 ..= remote_max)` (the ordinary tail-extension case);
   442	/// - **and** — the equal-length fork case — when the remote's `max_seq` **equals**
   443	///   our `max_seq` but its `head_hash` **differs** from ours, request the head
   444	///   `(max_seq ..= max_seq)`. Two partitions each holding `(author, seq = N)` with
   445	///   different valid hashes would otherwise never exchange the conflicting entry
   446	///   and no fork proof would form (ADR-008 §"Fork / equivocation handling"). The
   447	///   pulled conflicting entry is fed into DAG fork handling, which freezes the
   448	///   author on an attributable proof and raises an alarm on a deniable one.
   449	#[must_use]
   450	pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
   451	    let mut wants = Vec::new();
   452	    for rf in remote {
   453	        let local = dag.feed(&rf.author_id);
   454	        let local_max = local.map_or(0, |f| f.max_seq());
   455	        if rf.max_seq > local_max {
   456	            wants.push(WantRange {
   457	                author_id: rf.author_id,
   458	                from_seq: local_max + 1,
   459	                to_seq: rf.max_seq,
   460	            });
   461	        } else if rf.max_seq == local_max && local_max > 0 {
   462	            // Equal head seq: compare the gossiped head hashes. A mismatch is a
   463	            // divergence (equal-length fork) — pull the remote head entry so the
   464	            // conflict reaches DAG fork handling.
   465	            let local_head = local.map_or(crate::log::entry::ZERO_HASH, |f| f.head_hash());
   466	            if local_head != rf.head_hash {
   467	                wants.push(WantRange {
   468	                    author_id: rf.author_id,
   469	                    from_seq: local_max,
   470	                    to_seq: local_max,
   471	                });
   472	            }
   473	        }
   474	    }
   475	    wants
   476	}
   477	
   478	/// Collect the `ENTRY` wire frames satisfying a peer's `WANT` ranges from the
   479	/// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
   480	/// [`MAX_SERVE_BYTES`].
   481	///
   482	/// **The work is bounded by what this node holds, never by the ranges' numbers.**
   483	/// This used to loop `from_seq..=to_seq` doing one lookup per number, collecting
   484	/// into memory with the room's lock held, so a single `WANT (author, 1,
   485	/// u64::MAX)` — any member may send one — pinned a core on a loop that would not
   486	/// finish in the life of the machine, and nothing else could touch that room
   487	/// again (PRD-001 D2). Now each author's ranges are merged, so duplicates and
   488	/// overlaps cost nothing and serve nothing twice, and each merged range walks
   489	/// only the entries the feed actually has. Entries not held are simply omitted.
   490	#[must_use]
   491	pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
   492	    let mut out = Vec::new();
   493	    let mut bytes = 0usize;
   494	    for (author, ranges) in merged_wants(wants) {
   495	        let Some(feed) = dag.feed(&author) else {
   496	            continue;
   497	        };
   498	        for (from, to) in ranges {
   499	            for entry in feed.range(from, to) {
   500	                let wire = entry.to_wire();
   501	                if !out.is_empty()
   502	                    && (out.len() >= MAX_SERVE_ENTRIES
   503	                        || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
   504	                {
   505	                    return out;
   506	                }
   507	                bytes = bytes.saturating_add(wire.len());
   508	                out.push(wire);
   509	            }
   510	        }
   511	    }
   512	    out
   513	}
   514	
   515	/// A `WANT`'s ranges grouped by author (in author order) with each author's
   516	/// ranges sorted and merged, so the ranges are disjoint and ascending. Inverted
   517	/// ranges are dropped. The cost is `O(n log n)` in the number of ranges, which
   518	/// the frame size already bounds.
   519	fn merged_wants(wants: &[WantRange]) -> std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> {
   520	    let mut by_author: std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> =
   521	        std::collections::BTreeMap::new();
   522	    for w in wants.iter().filter(|w| w.from_seq <= w.to_seq) {
   523	        by_author
   524	            .entry(w.author_id)
   525	            .or_default()
   526	            .push((w.from_seq, w.to_seq));
   527	    }
   528	    for ranges in by_author.values_mut() {
   529	        ranges.sort_unstable();
   530	        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
   531	        for &(from, to) in ranges.iter() {
   532	            match merged.last_mut() {
   533	                Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
   534	                _ => merged.push((from, to)),
   535	            }
   536	        }
   537	        *ranges = merged;
   538	    }
   539	    by_author
   540	}
   541	
   542	/// Map a parse/verify [`Error`] to the M0 wire application-error code (ADR-008
   543	/// §"Abort / error signalling"). This is the single place the structured error
   544	/// taxonomy is collapsed onto the coded wire contract, so an unknown struct
   545	/// tag / unsupported version / unknown algo is **never** misreported as a generic
   546	/// authenticator failure.
   547	#[must_use]
   548	pub fn wire_error_for(err: &Error) -> WireError {
   549	    match err {
   550	        Error::UnknownStructTag(_) => WireError::UnknownStructTag,
   551	        Error::UnsupportedVersion { .. } => WireError::ProtocolVersionUnsupported,
   552	        Error::UnknownAlgoId(_) | Error::UnexpectedAlgo { .. } => WireError::UnknownAlgoId,
   553	        Error::SuiteBelowFloor { .. } => WireError::SuiteBelowFloor,
   554	        // Signature/authenticator failures, malformed structures, the deniable
   555	        // boundary, and oversize/CBOR malformation are all "this authenticator/
   556	        // structure is not acceptable" → AuthenticatorInvalid. (Size limits are a
   557	        // structural rejection; there is no dedicated size code in the M0 table.)
   558	        _ => WireError::AuthenticatorInvalid,
   559	    }
   560	}
   561	
   562	/// Map a DAG [`Rejected`] to the M0 wire application-error code.
   563	#[must_use]
   564	pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
   565	    match rej {
   566	        Rejected::NotAdmitted => WireError::EpochMismatch,
   567	        Rejected::Verification(e) => wire_error_for(e),
   568	        Rejected::Feed(_) => WireError::AuthenticatorInvalid,
   569	        Rejected::Fork(_) => WireError::AuthenticatorInvalid,
   570	        Rejected::GovernanceNotAttributable => WireError::AuthenticatorInvalid,
   571	        // A duplicate is not a hard fail; callers handle it before mapping. If it
   572	        // ever reaches here, treat as a benign authenticator-class rejection.
   573	        Rejected::Duplicate => WireError::AuthenticatorInvalid,
   574	    }
   575	}
   576	
   577	/// The outcome of applying a received `ENTRY` frame.
   578	#[derive(Debug)]
   579	#[non_exhaustive]
   580	pub enum ApplyOutcome {
   581	    /// The entry was newly stored.
   582	    Stored,
   583	    /// The entry was a duplicate (idempotent — already held).
   584	    Duplicate,
   585	    /// The entry conflicted with a stored one at the same `(author, seq)`: a fork.
   586	    /// This is a *local security event*, NOT a wire-protocol violation — it is
   587	    /// recorded/surfaced (an attributable fork freezes the author; a deniable one
   588	    /// raises an alarm) and sync **continues**. The stream is not closed for a
   589	    /// fork (ADR-008 §"Fork / equivocation handling").
   590	    Fork,
   591	}
   592	
   593	/// Apply a received `ENTRY` wire frame to the local [`Dag`] under the full
   594	/// acceptance predicate.
   595	///
   596	/// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
   597	/// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
   598	/// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
   599	/// (unknown tag, unsupported version, unknown algo, authenticator, …). A
   600	/// **fork is not a wire fail**: it is surfaced and sync continues, so two
   601	/// partitions can exchange conflicting heads and form the proof.
   602	pub fn apply_entry<R: AuthorResolver>(
   603	    dag: &mut Dag,
   604	    resolver: &R,
   605	    admission: &AdmissionPolicy,
   606	    entry_wire: &[u8],
   607	) -> std::result::Result<ApplyOutcome, WireError> {
   608	    let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
   609	    let key = resolver
   610	        .key_for(&entry.skeleton.author_id)
   611	        .ok_or(WireError::AuthenticatorInvalid)?;
   612	    let kind = resolver.kind_for(&entry);
   613	    match dag.accept(entry, kind, &key, admission) {
   614	        Ok(_) => Ok(ApplyOutcome::Stored),
   615	        Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
   616	        // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
   617	        // not close the stream.
   618	        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
   619	        Err(other) => Err(wire_error_for_rejected(&other)),
   620	    }
   621	}
   622	
   623	/// Drive a complete **frontier-mode** session between two peers, each over its
   624	/// own [`Transport`] endpoint, to convergence — exercising the real frame path
   625	/// (`HELLO`/`HAVE`/`WANT`/`ENTRY`) over the abstract transport. `a` is the
   626	/// initiator. `pump` moves frames between the two endpoints (for the in-memory
   627	/// duplex it is [`DuplexTransport::pump`]; over QUIC the network is the pump).
   628	/// Returns `(applied_into_a, applied_into_b)`.
   629	///
   630	/// Protocol per side: send `HELLO` (offering frontier); both compute and send
   631	/// `HAVE`; each replies `WANT` for what it lacks; each streams the requested
   632	/// `ENTRY` frames; each applies the entries it receives under the full acceptance
   633	/// predicate. A malformed/unknown frame or a hard acceptance failure closes the
   634	/// transport with the mapped [`WireError`].
   635	#[allow(clippy::too_many_arguments)]
   636	pub fn frontier_session<TA, TB, R, P>(
   637	    ta: &mut TA,
   638	    tb: &mut TB,
   639	    a: &mut Dag,
   640	    b: &mut Dag,
   641	    resolver: &R,
   642	    admission: &AdmissionPolicy,
   643	    pump: P,
   644	) -> std::result::Result<(usize, usize), WireError>
   645	where
   646	    TA: Transport,
   647	    TB: Transport,
   648	    R: AuthorResolver,
   649	    P: FnMut(&mut TA, &mut TB) -> usize,
   650	{
   651	    // Centralized fail-and-close: ANY hard fail closes BOTH endpoints with the
   652	    // exact coded reason (ADR-008 §"Abort / error signalling" — never a silent
   653	    // downgrade, never an unclosed stream).
   654	    match frontier_session_inner(ta, tb, a, b, resolver, admission, pump) {
   655	        Ok(counts) => Ok(counts),
   656	        Err(code) => {
   657	            ta.close(code);
   658	            tb.close(code);
   659	            Err(code)
   660	        }
   661	    }
   662	}
   663	
   664	#[allow(clippy::too_many_arguments)]
   665	fn frontier_session_inner<TA, TB, R, P>(
   666	    ta: &mut TA,
   667	    tb: &mut TB,
   668	    a: &mut Dag,
   669	    b: &mut Dag,
   670	    resolver: &R,
   671	    admission: &AdmissionPolicy,
   672	    mut pump: P,
   673	) -> std::result::Result<(usize, usize), WireError>
   674	where
   675	    TA: Transport,
   676	    TB: Transport,
   677	    R: AuthorResolver,
   678	    P: FnMut(&mut TA, &mut TB) -> usize,
   679	{
   680	    let send_a = |t: &mut TA, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
   681	    let send_b = |t: &mut TB, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
   682	
   683	    // 1. HELLO exchange + mode negotiation.
   684	    send_a(ta, encode_hello(SYNC_MODE_FRONTIER))?;
   685	    send_b(tb, encode_hello(SYNC_MODE_FRONTIER))?;
   686	    pump(ta, tb);
   687	    let a_remote_hello = expect_hello(ta.recv())?;
   688	    let b_remote_hello = expect_hello(tb.recv())?;
   689	    negotiate_mode(SYNC_MODE_FRONTIER, a_remote_hello)?;
   690	    negotiate_mode(SYNC_MODE_FRONTIER, b_remote_hello)?;
   691	
   692	    // 2. HAVE exchange.
   693	    send_a(ta, encode_have(&frontiers_of(a)))?;
   694	    send_b(tb, encode_have(&frontiers_of(b)))?;
   695	    pump(ta, tb);
   696	    let a_sees = expect_have(ta.recv())?; // b's frontiers, seen by a
   697	    let b_sees = expect_have(tb.recv())?; // a's frontiers, seen by b
   698	
   699	    // 3. WANT exchange (each asks for what it lacks, including equal-seq forks).
   700	    let a_wants = wants_for(a, &a_sees);
   701	    let b_wants = wants_for(b, &b_sees);
   702	    send_a(ta, encode_want(&a_wants))?;
   703	    send_b(tb, encode_want(&b_wants))?;
   704	    pump(ta, tb);
   705	    let a_got_want = expect_want(ta.recv())?; // what b wants from a
   706	    let b_got_want = expect_want(tb.recv())?; // what a wants from b
   707	
   708	    // 4. ENTRY streaming (each serves the other's WANT).
   709	    for wire in entries_for_wants(a, &a_got_want) {
   710	        send_a(ta, encode_entry(&wire))?;
   711	    }
   712	    for wire in entries_for_wants(b, &b_got_want) {
   713	        send_b(tb, encode_entry(&wire))?;
   714	    }
   715	    pump(ta, tb);
   716	
   717	    // 5. Apply received entries. A fork at an equal-seq divergent head surfaces
   718	    //    here as the conflicting entry is fed into DAG fork handling; an
   719	    //    attributable fork freezes the equivocator (its WireError is the coded
   720	    //    close). Both peers drain independently.
   721	    let into_a = drain_entries(ta, a, resolver, admission)?;
   722	    let into_b = drain_entries(tb, b, resolver, admission)?;
   723	    Ok((into_a, into_b))
   724	}
   725	
   726	/// Drive **one peer's** half of a frontier-mode session over a single
   727	/// [`Transport`] endpoint, to completion. Unlike [`frontier_session`] (which pumps
   728	/// both in-process duplex sides in one thread), this runs a single side over a
   729	/// real bidirectional transport — the QUIC mapping (M9), where the network moves
   730	/// bytes, so no `pump` is needed. Both peers are protocol-symmetric, so the same
   731	/// function serves the initiator and the responder; run one on each peer
   732	/// concurrently and both converge.
   733	///
   734	/// The phases mirror [`frontier_session`]: `HELLO` → `HAVE` → `WANT` → serve the
   735	/// peer's `WANT` with `ENTRY` frames, then drain and apply the peer's `ENTRY`
   736	/// frames. After serving its entries the peer half-closes its send direction
   737	/// ([`Transport::close`] is **not** called on the success path — a clean
   738	/// end-of-stream is signalled by [`Transport::recv`] returning `Ok(None)`), so the
   739	/// drain loop terminates. A hard fail closes the transport with the mapped
   740	/// [`WireError`].
   741	///
   742	/// Returns the number of entries newly applied into `dag`.
   743	pub fn frontier_session_peer<T, R>(
   744	    t: &mut T,
   745	    dag: &mut Dag,
   746	    resolver: &R,
   747	    admission: &AdmissionPolicy,
   748	) -> std::result::Result<usize, WireError>
   749	where
   750	    T: Transport,
   751	    R: AuthorResolver,
   752	{
   753	    match frontier_session_peer_inner(t, dag, resolver, admission) {
   754	        Ok(applied) => Ok(applied),
   755	        Err(code) => {
   756	            t.close(code);
   757	            Err(code)
   758	        }
   759	    }
   760	}
   761	
   762	fn frontier_session_peer_inner<T, R>(
   763	    t: &mut T,
   764	    dag: &mut Dag,
   765	    resolver: &R,
   766	    admission: &AdmissionPolicy,
   767	) -> std::result::Result<usize, WireError>
   768	where
   769	    T: Transport,
   770	    R: AuthorResolver,
   771	{
   772	    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
   773	
   774	    // 1. HELLO exchange + mode negotiation.
   775	    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
   776	    let remote_hello = expect_hello(t.recv())?;
   777	    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;
   778	
   779	    // 2. HAVE exchange.
   780	    send(t, encode_have(&frontiers_of(dag)))?;
   781	    let remote_have = expect_have(t.recv())?;
   782	
   783	    // 3. WANT exchange (ask for what we lack, including equal-seq forks).
   784	    let my_wants = wants_for(dag, &remote_have);
   785	    send(t, encode_want(&my_wants))?;
   786	    let their_wants = expect_want(t.recv())?;
   787	
   788	    // 4. Serve their WANT with ENTRY frames, then signal end-of-stream by
   789	    //    half-closing the send side via a benign close. We must NOT use
   790	    //    `Transport::close` here (that is the hard-fail path); a clean FIN is the
   791	    //    success terminator. The QUIC mapping finishes the send stream; the
   792	    //    in-memory duplex relies on the drain loop observing an empty inbox.
   793	    //    Bounded in count, bytes and time (see the module docs); stopping at the
   794	    //    time bound is a clean end, not a failure — the peer keeps what it got.
   795	    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
   796	    for wire in entries_for_wants(dag, &their_wants) {
   797	        if std::time::Instant::now() >= serve_deadline {
   798	            break;
   799	        }
   800	        send(t, encode_entry(&wire))?;
   801	    }
   802	    // Signal a clean end-of-stream on our send side (success terminator, not a
   803	    // hard close), so the peer's drain loop terminates at FIN.
   804	    t.finish();
   805	
   806	    // 5. Drain and apply the entries the peer serves us, until the peer's clean
   807	    //    half-close (recv → Ok(None)).
   808	    drain_entries(t, dag, resolver, admission)
   809	}
   810	
   811	/// What a frontier session may do to a room, **one step at a time**. Each method takes the room's
   812	/// lock, does its step, releases the lock and returns owned data; none of them sees the transport.
   813	/// [`frontier_session_room`] sees the transport and never the room. So no lock can be held across a
   814	/// network wait, and the compiler keeps it that way: there is no scope in which both exist.
   815	///
   816	/// This replaces a session that held the room's mutex from its first frame to its last. A peer that
   817	/// was slow to answer then held the room for up to the frame timeout, and every other use of the
   818	/// room — a message being posted, the node's view being published after every event — waited
   819	/// behind it (ADR-008's own implementation note named the fix).
   820	pub trait SessionRoom {
   821	    /// The room's frontiers, for `HAVE`.
   822	    ///
   823	    /// # Errors
   824	    /// The room is unusable (poisoned, or moved to another epoch).
   825	    fn frontiers(&self) -> std::result::Result<Vec<FeedFrontier>, WireError>;
   826	    /// What to ask the peer for, given its `HAVE`.
   827	    ///
   828	    /// # Errors
   829	    /// As [`SessionRoom::frontiers`].
   830	    fn wants(&self, remote: &[FeedFrontier]) -> std::result::Result<Vec<WantRange>, WireError>;
   831	    /// The entries to serve for the peer's `WANT` — owned and bounded.
   832	    ///
   833	    /// # Errors
   834	    /// As [`SessionRoom::frontiers`].
   835	    fn entries(&self, wants: &[WantRange]) -> std::result::Result<Vec<Vec<u8>>, WireError>;
   836	    /// Apply a batch of received entries under a fresh lock, **against the room's current rules**: an
   837	    /// author revoked while the batch was on the wire is refused, and a room that moved to another
   838	    /// epoch refuses the whole batch. Returns how many were newly stored.
   839	    ///
   840	    /// # Errors
   841	    /// A hard sync failure from an entry, or the room is unusable.
   842	    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, WireError>;
   843	}
   844	
   845	/// How many received entries are staged before a batch is applied. Bounds what a session holds in
   846	/// memory between locks; each batch is one short hold of the room.
   847	pub const MAX_STAGED: usize = 256;
   848	
   849	/// One peer's half of a frontier session, over `t`, against `room` — the same protocol as
   850	/// [`frontier_session_peer`], with the room locked only inside each [`SessionRoom`] step and never
   851	/// across a send or a receive.
   852	///
   853	/// # Errors
   854	/// The coded [`WireError`] of a hard fail; the transport is closed with it.
   855	pub fn frontier_session_room<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
   856	where
   857	    T: Transport,
   858	    S: SessionRoom + ?Sized,
   859	{
   860	    match frontier_session_room_inner(t, room) {
   861	        Ok(applied) => Ok(applied),
   862	        Err(code) => {
   863	            t.close(code);
   864	            Err(code)
   865	        }
   866	    }
   867	}
   868	
   869	fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
   870	where
   871	    T: Transport,
   872	    S: SessionRoom + ?Sized,
   873	{
   874	    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
   875	
   876	    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
   877	    let remote_hello = expect_hello(t.recv())?;
   878	    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;
   879	
   880	    send(t, encode_have(&room.frontiers()?))?;
   881	    let remote_have = expect_have(t.recv())?;
   882	
   883	    send(t, encode_want(&room.wants(&remote_have)?))?;
   884	    let their_wants = expect_want(t.recv())?;
   885	
   886	    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
   887	    for wire in room.entries(&their_wants)? {
   888	        if std::time::Instant::now() >= serve_deadline {
   889	            break;
   890	        }
   891	        send(t, encode_entry(&wire))?;
   892	    }
   893	    t.finish();
   894	
   895	    // Drained with no lock held; applied a batch at a time under a fresh one.
   896	    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
   897	    let mut staged: Vec<Vec<u8>> = Vec::new();
   898	    let mut applied = 0;
   899	    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
   900	        if std::time::Instant::now() >= deadline {
   901	            return Err(WireError::SyncModeUnsupported);
   902	        }
   903	        match decode_frame(&frame) {
   904	            Ok(SyncFrame::Entry(wire)) => {
   905	                staged.push(wire);
   906	                if staged.len() >= MAX_STAGED {
   907	                    applied += room.apply(std::mem::take(&mut staged))?;
   908	                }
   909	            }
   910	            Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
   911	        }
   912	    }
   913	    if !staged.is_empty() {
   914	        applied += room.apply(staged)?;
   915	    }
   916	    Ok(applied)
   917	}
   918	
   919	/// Apply staged entries into `dag`, returning how many were newly stored — the apply half of
   920	/// [`SessionRoom::apply`], for a caller that already holds its room.
   921	///
   922	/// # Errors
   923	/// The first hard sync failure.
   924	pub fn apply_staged<R: AuthorResolver>(
   925	    dag: &mut Dag,
   926	    resolver: &R,
   927	    admission: &AdmissionPolicy,
   928	    staged: &[Vec<u8>],
   929	) -> std::result::Result<usize, WireError> {
   930	    let mut stored = 0;
   931	    for wire in staged {
   932	        if matches!(
   933	            apply_entry(dag, resolver, admission, wire)?,
   934	            ApplyOutcome::Stored
   935	        ) {
   936	            stored += 1;
   937	        }
   938	    }
   939	    Ok(stored)
   940	}
   941	
   942	/// Read and apply every queued `ENTRY` frame on `t` into `dag`. A hard fail
   943	/// returns the mapped [`WireError`]; the caller ([`frontier_session`]) performs
   944	/// the coded stream close, so this function does not close itself (one central
   945	/// fail-and-close path). An undecodable frame is a sync-protocol violation
   946	/// (`SyncModeUnsupported`); an `ENTRY` that fails acceptance carries its own code
   947	/// from [`apply_entry`].
   948	fn drain_entries<T: Transport, R: AuthorResolver>(
   949	    t: &mut T,
   950	    dag: &mut Dag,
   951	    resolver: &R,
   952	    admission: &AdmissionPolicy,
   953	) -> std::result::Result<usize, WireError> {
   954	    let mut applied = 0;
   955	    // **The whole phase is bounded, not just the gap between frames.**
   956	    //
   957	    // The transport's timeout is per frame, and this loop had no limit on how many frames it
   958	    // would take, so a peer that sent one frame every nineteen seconds — forever — held this
   959	    // room's lock for ever. The lock is taken for the entire session (see `sync_over`'s caller),
   960	    // so that is every operation on the room stopped by one member, at no cost to it.
   961	    //
   962	    // The references bound the total as well as the gap: go-libp2p's relay sets a per-stream
   963	    // timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor reclaims a
   964	    // circuit on total idle. A per-frame bound alone only defends against a peer that stops, never
   965	    // against one that drips.
   966	    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
   967	    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
   968	        if std::time::Instant::now() >= deadline {
   969	            return Err(WireError::SyncModeUnsupported);
   970	        }
   971	        match decode_frame(&frame) {
   972	            Ok(SyncFrame::Entry(wire)) => {
   973	                if matches!(
   974	                    apply_entry(dag, resolver, admission, &wire)?,
   975	                    ApplyOutcome::Stored
   976	                ) {
   977	                    applied += 1;
   978	                }
   979	            }
   980	            // **A protocol violation, not something to ignore.** This phase is defined as entries
   981	            // only, and silently accepting anything else is what made the hold above free: a
   982	            // non-entry frame costs the sender nothing and never reaches `apply_entry`, so it
   983	            // would buy the whole budget for free.
   984	            Ok(_) => return Err(WireError::SyncModeUnsupported),
   985	            Err(_) => return Err(WireError::SyncModeUnsupported),
   986	        }
   987	    }
   988	    Ok(applied)
   989	}
   990	
   991	fn expect_hello(r: Result<Option<Vec<u8>>>) -> std::result::Result<u8, WireError> {
   992	    match r.map_err(|_| WireError::TransportFailed)? {
   993	        Some(frame) => match decode_frame(&frame) {
   994	            Ok(SyncFrame::Hello(bitmap)) => Ok(bitmap),
   995	            _ => Err(WireError::SyncModeUnsupported),
   996	        },
   997	        // A clean end-of-stream where a frame was due: the peer hung up mid-session.
   998	        None => Err(WireError::TransportFailed),
   999	    }
  1000	}
  1001	
  1002	fn expect_have(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<FeedFrontier>, WireError> {
  1003	    match r.map_err(|_| WireError::TransportFailed)? {
  1004	        Some(frame) => match decode_frame(&frame) {
  1005	            Ok(SyncFrame::Have(v)) => Ok(v),
  1006	            _ => Err(WireError::SyncModeUnsupported),
  1007	        },
  1008	        None => Err(WireError::TransportFailed),
  1009	    }
  1010	}
  1011	
  1012	fn expect_want(r: Result<Option<Vec<u8>>>) -> std::result::Result<Vec<WantRange>, WireError> {
  1013	    match r.map_err(|_| WireError::TransportFailed)? {
  1014	        Some(frame) => match decode_frame(&frame) {
  1015	            Ok(SyncFrame::Want(v)) => Ok(v),
  1016	            _ => Err(WireError::SyncModeUnsupported),
  1017	        },
  1018	        None => Err(WireError::TransportFailed),
  1019	    }
  1020	}
  1021	
  1022	// ---------------------------------------------------------------------------
  1023	// Range-reconciliation (Negentropy) mode.
  1024	// ---------------------------------------------------------------------------
  1025	
  1026	/// Drive a complete **Negentropy range-reconciliation** session between two
  1027	/// in-memory DAGs to convergence, applying the entries each side learns it needs.
  1028	/// `a` is the Negentropy initiator. Returns `(applied_into_a, applied_into_b)`.
  1029	///
  1030	/// The Negentropy engine resolves which entry *hashes* differ; the hashes drive
  1031	/// `ENTRY` exchange via the content-addressed DAG index. Acceptance is the same
  1032	/// predicate as frontier mode.
  1033	pub fn range_reconcile_exchange<R: AuthorResolver>(
  1034	    a: &mut Dag,
  1035	    b: &mut Dag,
  1036	    resolver: &R,
  1037	    admission: &AdmissionPolicy,
  1038	) -> std::result::Result<(usize, usize), WireError> {
  1039	    let _mode = negotiate_mode(
  1040	        SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION,
  1041	        SYNC_MODE_FRONTIER | SYNC_MODE_RANGE_RECONCILIATION,
  1042	    )?;
  1043	
  1044	    let a_items = negentropy::items_from_ids(&hashes_of(a));
  1045	    let b_items = negentropy::items_from_ids(&hashes_of(b));
  1046	
  1047	    // a initiates; messages bounce until a's response is empty. a collects the
  1048	    // have/need diff (have = a-only hashes, need = b-only hashes).
  1049	    let mut msg = negentropy::reconcile_initiate(&a_items);
  1050	    let mut a_need = Vec::new();
  1051	    let mut a_have = Vec::new();
  1052	    let mut rounds = 0;
  1053	    loop {
  1054	        rounds += 1;
  1055	        if rounds > 64 {
  1056	            return Err(WireError::SyncModeUnsupported);
  1057	        }
  1058	        // Carry NEG over the wire frame to exercise the codec.
  1059	        let neg_wire = encode_neg(&negentropy::encode_message(&msg));
  1060	        let b_msg = decode_neg_frame(&neg_wire)?;
  1061	        let b_res = negentropy::reconcile(Role::Responder, &b_items, &b_msg);
  1062	        if b_res.response.is_empty() {
  1063	            break;
  1064	        }
  1065	        let resp_wire = encode_neg(&negentropy::encode_message(&b_res.response));
  1066	        let a_msg = decode_neg_frame(&resp_wire)?;
  1067	        let a_res = negentropy::reconcile(Role::Initiator, &a_items, &a_msg);
  1068	        a_have.extend(a_res.have);
  1069	        a_need.extend(a_res.need);
  1070	        if a_res.response.is_empty() {
  1071	            break;
  1072	        }
  1073	        msg = a_res.response;
  1074	    }
  1075	
  1076	    // Apply: a pulls its `need` from b; b pulls its `need` (= a's `have`) from a.
  1077	    let applied_into_a = apply_hashes(a, b, resolver, admission, &a_need)?;
  1078	    let applied_into_b = apply_hashes(b, a, resolver, admission, &a_have)?;
  1079	    Ok((applied_into_a, applied_into_b))
  1080	}
  1081	
  1082	/// All entry hashes in a DAG, in causal order (deterministic).
  1083	fn hashes_of(dag: &Dag) -> Vec<Digest32> {
  1084	    dag.causal_order()
  1085	}
  1086	
  1087	/// Decode a `NEG` frame into a Negentropy message.
  1088	fn decode_neg_frame(frame: &[u8]) -> std::result::Result<negentropy::Message, WireError> {
  1089	    match decode_frame(frame) {
  1090	        Ok(SyncFrame::Neg(bytes)) => {
  1091	            negentropy::decode_message(&bytes).map_err(|_| WireError::SyncModeUnsupported)
  1092	        }
  1093	        _ => Err(WireError::SyncModeUnsupported),
  1094	    }
  1095	}
  1096	
  1097	/// Apply, into `dst`, the entries at `hashes` fetched from `src` (content-address
  1098	/// lookup), under the full acceptance predicate. Entries `src` does not hold are
  1099	/// skipped. Entries are applied in seq order per author so feed links resolve.
  1100	fn apply_hashes<R: AuthorResolver>(
  1101	    dst: &mut Dag,
  1102	    src: &Dag,
  1103	    resolver: &R,
  1104	    admission: &AdmissionPolicy,
  1105	    hashes: &[Digest32],
  1106	) -> std::result::Result<usize, WireError> {
  1107	    // Gather the source entries, then order by (author, seq) so prev/lipmaa links
  1108	    // are satisfiable as they are appended.
  1109	    let mut wires: Vec<(Digest32, u64, Vec<u8>)> = hashes
  1110	        .iter()
  1111	        .filter_map(|h| {
  1112	            src.get_by_hash(h)
  1113	                .map(|e| (e.skeleton.author_id, e.skeleton.seq, e.to_wire()))
  1114	        })
  1115	        .collect();
  1116	    wires.sort_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(&y.1)));
  1117	    let mut applied = 0;
  1118	    for (_, _, wire) in wires {
  1119	        if matches!(
  1120	            apply_entry(dst, resolver, admission, &wire)?,
  1121	            ApplyOutcome::Stored
  1122	        ) {
  1123	            applied += 1;
  1124	        }
  1125	    }
  1126	    Ok(applied)
  1127	}
  1128	
  1129	const _: () = assert!(DIGEST_LEN == 32);
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 diff 58fde36 8436100 -- crates/vox-core/src/node/channel.rs crates/vox-core/src/log/sync.rs crates/vox-core/src/log/dag.rs crates/vox-core/src/node/anchor.rs
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
[0m
[0m$ [0mgh issue list --repo robertelee78/vox --state all --search 'ADR-025' --json number,title,body --limit 10
[]
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=2070, limit=155][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | nl -ba | sed -n '3360,3510p;4340,4405p;4680,5355p'
...output truncated...

Full output saved to: /Users/robert.lee/.local/share/opencode/tool-output/tool_0dd403670001G4kMtLNsXYTNNr

  3410	                        let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
  3411	                        let tx = self.net_tx.clone();
  3412	                        tokio::spawn(async move {
  3413	                            tokio::time::sleep(wait).await;
  3414	                            let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
  3415	                        });
  3416	                    }
  3417	                } else {
  3418	                    self.push_failures.remove(&(channel_id, peer));
  3419	                }
  3420	                // The room is free now **whatever the outcome**: a push that found it mid-session
  3421	                // is owed and goes at once. Gating this on success left an owed push waiting for the
  3422	                // tick whenever the session that held the room failed — which a log-less anchor's
  3423	                // always does — and put a 1.00s ceiling on exactly the messages it delayed.
  3424	                if !self.pending_push.is_empty() {
  3425	                    // A push that found this room mid-session is owed; the room is free now.
  3426	                    self.push_now = true;
  3427	                }
  3428	                self.refresh_network_view().await;
  3429	                if let Ok(o) = outcome {
  3430	                    // **Event, not interval.** Propagation was event-driven in one direction only:
  3431	                    // an append here pushed at once, but a sync that *brought entries in* marked
  3432	                    // nothing, so this node sat on them until its own `SYNC_INTERVAL_SECS`. For an
  3433	                    // anchor that is the entire job undone — it holds the log for whoever is away and
  3434	                    // then forwards it a half-minute late. End to end the worst case was 30s to reach
  3435	                    // the anchor plus 30s for the next member to pull.
  3436	                    //
  3437	                    // Self-limiting rather than a storm: reconciliation is idempotent, so the peer
  3438	                    // this came from applies nothing on the way back and marks nothing onward.
  3439	                    // The actor-side half of what the slot just did: a session may have admitted
  3440	                    // authors and mirrored records onto this node's board, and both change who may
  3441	                    // reach whom and what the anchors should hold. `learn_members` used to do this
  3442	                    // inline, which is how a round trip ended up on the single writer.
  3443	                    //
  3444	                    // **Only when the session actually brought something in**, which is the guard
  3445	                    // the original had (`if learned > 0`, `if gained > 0`) and I dropped when moving
  3446	                    // this out. Without it the actor did a publish round trip after *every* sync,
  3447	                    // and syncs are frequent: measured, that turned a 0-1s crossing into 20s in
  3448	                    // seven runs of ten while removing the losses. Losses gone is the right trade;
  3449	                    // paying a publish per sync for it is not.
  3450	                    if o.applied > 0 {
  3451	                        self.note_local_append(&channel_id);
  3452	                        self.refresh_reachers().await;
  3453	                        self.publish_channel_to_anchors(&channel_id).await;
  3454	                    }
  3455	                    // **A newcomer this session admitted is consented to now, not on the tick.** Two
  3456	                    // members who joined the same room learn of each other only here, from the board.
  3457	                    // Under ForwardOnly a post sealed before the author consents to a reader is never
  3458	                    // readable to it, so every tick of delay is a window of posts lost to the
  3459	                    // newcomer. Measured in room_of_three_keys_proof: the joiners' keys to each other
  3460	                    // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
  3461	                    // close it, since nobody can consent to a member it has not yet heard of.
  3462	                    if !self.trust.is_empty() {
  3463	                        let trusted = self.trust.trusted();
  3464	                        let owes = match self.channels.get(&channel_id).map(Arc::clone) {
  3465	                            Some(shared) => !shared.lock().await.owed_consents(&trusted).is_empty(),
  3466	                            None => false,
  3467	                        };
  3468	                        if owes {
  3469	                            self.deliver_owed_consents(None).await;
  3470	                        }
  3471	                    }
  3472	                    if o.rendered > 0 || o.governance > 0 {
  3473	                        let _ = self.event_tx.send(NodeEvent::Synced {
  3474	                            channel_id,
  3475	                            applied: o.applied as u64,
  3476	                            rendered: o.rendered as u64,
  3477	                        });
  3478	                    }
  3479	                }
  3480	            }
  3481	            NetEvent::Stream { conn, inbound } => {
  3482	                // Held for the whole handler: the connection must outlive the streams
  3483	                // opened on it, or the peer sees it close mid-exchange.
  3484	                let connection = conn;
  3485	                match inbound {
  3486	                    Inbound::Join { .. } => {
  3487	                        // Unreachable: the stream loop turns these into
  3488	                        // `NetEvent::JoinRequest` once the request is read.
  3489	                    }
  3490	                    Inbound::Pairwise { peer, send, recv } => {
  3491	                        self.take_inbound_skdm(peer, send, recv).await;
  3492	                    }
  3493	                    Inbound::Sync { .. } => {
  3494	                        // Unreachable: the stream loop converts these into
  3495	                        // `NetEvent::SyncRequest` once the preamble is read.
  3496	                    }
  3497	                    Inbound::Punch {
  3498	                        peer,
  3499	                        coordinator,
  3500	                        send,
  3501	                        recv,
  3502	                    } => {
  3503	                        self.answer_punch(peer, coordinator, send, recv);
  3504	                    }
  3505	                    Inbound::Tunnel { peer, send, recv } => {
  3506	                        // The snapshot is taken here (only the actor reads channel
  3507	                        // state) and the tunnel runs on its own task: it lives as long
  3508	                        // as the TCP connection it carries, which may be hours.
  3509	                        let snapshot = self.host_snapshot().await;
  3510	                        // The host is told who reached what, because the carried
  4340	            .is_some_and(|n| n.manager().existing(&target).is_some());
  4341	        if connected {
  4342	            // Started or not (a session with this same member may already be running), the retry
  4343	            // rides the next `SyncDone` of a session **with the target**. Checking for any session
  4344	            // on the room kept a consent waiting on sessions with other members, which, now that
  4345	            // sessions are guarded per (room, peer), need never all end.
  4346	            let _ = self.sync_one(&channel_id, target).await;
  4347	            if !self.in_session_with(&channel_id, &target) {
  4348	                let _ = reply.send(outcome);
  4349	                return;
  4350	            }
  4351	        } else if attempts > 0 {
  4352	            // A dial already landed once for this consent and the connection is gone again.
  4353	            let _ = reply.send(outcome);
  4354	            return;
  4355	        }
  4356	        self.pending_consents
  4357	            .push((channel_id, target, reply, attempts.saturating_add(1)));
  4358	    }
  4359	
  4360	    /// Retry the explicit consents `matches` selects (`Dialed` passes its peer, `SyncDone` its
  4361	    /// room), or answer them all with `failed` (`ReachFailed`).
  4362	    async fn answer_pending_consents(
  4363	        &mut self,
  4364	        matches: impl Fn(&Digest32, &Digest32) -> bool,
  4365	        failed: Option<Outcome>,
  4366	    ) {
  4367	        let (waiting, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_consents)
  4368	            .into_iter()
  4369	            .partition(|(room, target, _, _)| matches(room, target));
  4370	        self.pending_consents = rest;
  4371	        if waiting.is_empty() {
  4372	            return;
  4373	        }
  4374	        for (channel_id, target, reply, attempts) in waiting {
  4375	            match failed {
  4376	                Some(o) => {
  4377	                    let _ = reply.send(o);
  4378	                }
  4379	                None => {
  4380	                    // Still waiting on its dial: that is `Dialed`'s or `ReachFailed`'s to answer, not
  4381	                    // a session with somebody else that happened to finish first.
  4382	                    let connected = self
  4383	                        .net
  4384	                        .as_ref()
  4385	                        .is_some_and(|n| n.manager().existing(&target).is_some());
  4386	                    if !connected {
  4387	                        self.pending_consents
  4388	                            .push((channel_id, target, reply, attempts));
  4389	                        continue;
  4390	                    }
  4391	                    let outcome = self.consent(&channel_id, target, false).await;
  4392	                    self.settle_consent(channel_id, target, reply, outcome, attempts)
  4393	                        .await;
  4394	                }
  4395	            }
  4396	        }
  4397	        // The view reflects whatever was granted before anyone reads it.
  4398	        self.publish().await;
  4399	    }
  4400	
  4401	    /// Consent to `target` reading this identity's messages — ADR-007 step 3, the
  4402	    /// human decision, taken per sender.
  4403	    async fn consent(&mut self, channel_id: &Digest32, target: Digest32, asked: bool) -> Outcome {
  4404	        let outcome = self.release_key_to(channel_id, target, asked).await;
  4405	        if outcome.is_done() {
  4680	    /// third member saw a new one 24–28 s after the join returned; with the interval forced to
  4681	    /// 5 s, 1.9–2.6 s. So when this node's board gains a bundle record from an author it has
  4682	    /// not seen, it admits what the evidence allows and pushes the room to its connected members.
  4683	    /// That push offers their boards the records they lack (`sync_one`), and each receiving
  4684	    /// member does the same once, when the newcomer is new to it.
  4685	    ///
  4686	    /// **Bounded, not a storm.** Only a *new author* triggers this: a member's periodic refresh of
  4687	    /// its own records does not. Each node therefore pushes at most once per newcomer, which is
  4688	    /// the same fan-out one chat message already has, and in a 500-member room it is one pass per
  4689	    /// member per join, over the connections it already holds, with nothing forwarded twice
  4690	    /// because a board that already holds the record does not grow.
  4691	    async fn note_new_members(&mut self, channel_id: &Digest32) {
  4692	        // Not deferred while a session runs; see `publish_channel_to_anchors`.
  4693	        let (Some(net), Some(shared)) = (
  4694	            self.net.as_ref().map(Arc::clone),
  4695	            self.channels.get(channel_id).map(Arc::clone),
  4696	        ) else {
  4697	            return;
  4698	        };
  4699	        let epoch = shared.lock().await.epoch();
  4700	        let bundles = net.board_bundles(channel_id, epoch);
  4701	        let known = self.board_authors.entry(*channel_id).or_default();
  4702	        let fresh = bundles.iter().filter(|b| known.insert(b.author_id)).count();
  4703	        if fresh == 0 {
  4704	            return;
  4705	        }
  4706	        if let Some(store) = self.profile.as_ref().map(Profile::store_handle) {
  4707	            let now = self.now();
  4708	            let mut channel = shared.lock().await;
  4709	            let _ = admit_board_records(
  4710	                &mut channel,
  4711	                &store,
  4712	                &bundles,
  4713	                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
  4714	                now,
  4715	            )
  4716	            .await;
  4717	        }
  4718	        self.refresh_network_view().await;
  4719	        self.note_local_append(channel_id);
  4720	    }
  4721	
  4722	    /// Whether a sync session with `peer` is running on `channel_id`: the collision a new
  4723	    /// session with that peer for that room must not start into (see `syncing`).
  4724	    fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
  4725	        self.syncing.contains(&(*channel_id, *peer))
  4726	    }
  4727	
  4728	    /// Mark a channel as having a local append to push, and make every peer's
  4729	    /// schedule due (ADR-016: "a push immediately after a local append").
  4730	    fn note_local_append(&mut self, channel_id: &Digest32) {
  4731	        if self.net.is_none() {
  4732	            return;
  4733	        }
  4734	        self.push_now = true;
  4735	        self.pending_push.insert(*channel_id);
  4736	        // Something new: every peer is owed it again, including those that had the last one.
  4737	        self.pushed_to.remove(channel_id);
  4738	        for schedule in self.schedules.values_mut() {
  4739	            schedule.note_local_append();
  4740	        }
  4741	    }
  4742	
  4743	    /// Run whatever the ADR-016 sync schedule says is due. Returns whether anything
  4744	    /// ran, so the caller only republishes the view when it might have changed.
  4745	    ///
  4746	    /// A peer with no live connection is skipped, not retried in place: it gets a
  4747	    /// fresh schedule when it reconnects.
  4748	    /// Re-run the ladder's publish side when the granted mappings are halfway through
  4749	    /// their lifetime, so a node that outlives a two-hour mapping stays dialable.
  4750	    ///
  4751	    /// Nothing happens while the network is down: the renewal instant is left in place
  4752	    /// so the next unlock's discovery supersedes it.
  4753	    ///
  4754	    /// The re-request runs on its own task (it talks to a gateway) and lands back as
  4755	    /// [`NetEvent::AddressesDiscovered`], which republishes the address records too —
  4756	    /// a renewal that came back with a *different* external port must be advertised.
  4757	    fn renew_mappings_if_due(&mut self) {
  4758	        let Some(due) = self.renew_mappings_at else {
  4759	            return;
  4760	        };
  4761	        if self.now() < due {
  4762	            return;
  4763	        }
  4764	        let Some(net) = self.net.as_ref().map(Arc::clone) else {
  4765	            return;
  4766	        };
  4767	        // Cleared now, not when the refresh returns: one renewal in flight at a time.
  4768	        self.renew_mappings_at = None;
  4769	        let tx = self.net_tx.clone();
  4770	        tokio::spawn(async move {
  4771	            let mappings = net.refresh_advertised().await;
  4772	            let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
  4773	        });
  4774	    }
  4775	
  4776	    /// Push what a local append made due **now**, rather than at the next tick.
  4777	    ///
  4778	    /// A message was marked due by `note_local_append` and then waited for `TICK` — up to a full
  4779	    /// second — before anything sent it: PRD-001 R40 asks for chat under a second, and measured
  4780	    /// through the real binary the median was 322–894ms with a maximum of 1.021s, the tick's own
  4781	    /// shape. Run after the command or event that made the push due, and after its reply, so the
  4782	    /// command's own latency is unchanged.
  4783	    ///
  4784	    /// A burst coalesces for free: a room mid-session is owed rather than re-sent (see
  4785	    /// `run_due_syncs`), and the session's `SyncDone` re-arms this while pushes are still owed, so
  4786	    /// posts go out back to back instead of one per tick.
  4787	    async fn push_if_owed(&mut self) {
  4788	        if std::mem::take(&mut self.push_now) && self.run_due_syncs().await {
  4789	            self.publish().await;
  4790	        }
  4791	    }
  4792	
  4793	    async fn run_due_syncs(&mut self) -> bool {
  4794	        let Some(net) = self.net.as_ref().map(Arc::clone) else {
  4795	            return false;
  4796	        };
  4797	        let now = self.now();
  4798	        let mut due: Vec<(Digest32, SyncTrigger)> = self
  4799	            .schedules
  4800	            .iter()
  4801	            .filter_map(|(peer, s)| s.due(now).map(|t| (*peer, t)))
  4802	            .collect();
  4803	        // **Owed peers first.** `schedules` is keyed by fingerprint, so without this every pass
  4804	        // visited peers in the same order, and one that sorted first and took the room each time
  4805	        // left the rest skipped each time. A stable sort keeps fingerprint order within each group.
  4806	        due.sort_by_key(|(peer, _)| !self.owed_first.contains(peer));
  4807	        for (peer, _) in &due {
  4808	            self.owed_first.remove(peer);
  4809	        }
  4810	        if due.is_empty() {
  4811	            return false;
  4812	        }
  4813	        let mut ran = false;
  4814	        // Which channels a local-append push actually got out. Everything else stays owed.
  4815	        let mut pushed: std::collections::BTreeSet<Digest32> = std::collections::BTreeSet::new();
  4816	        // Rooms any peer was skipped for because they were mid-session. Added to `pending_push`
  4817	        // only **after** the `retain` below — see there.
  4818	        let mut owed_rooms: std::collections::BTreeSet<Digest32> =
  4819	            std::collections::BTreeSet::new();
  4820	        for (peer, trigger) in due {
  4821	            if net.manager().existing(&peer).is_none() {
  4822	                continue;
  4823	            }
  4824	            // Which channels this pass covers: a local-append push touches only the
  4825	            // channels that changed; a connect or interval pass covers every channel
  4826	            // shared with this peer.
  4827	            let mut channels: Vec<Digest32> = Vec::new();
  4828	            // Rooms this pass wanted with this peer but found **already mid-session**. See the
  4829	            // `owed` handling after the loop: they are retried next tick, not forgotten.
  4830	            let mut owed: Vec<Digest32> = Vec::new();
  4831	            // A member reconciles a channel with its co-authors — and with that channel's
  4832	            // anchors, which keep the log for whoever is away (M15.2b). Both are decided per room
  4833	            // by `may_sync` below.
  4834	
  4835	            // **Learn who this peer is before deciding we share nothing with it.**
  4836	            //
  4837	            // The filter below asks `is_author(&peer)`, and the thing that admits a newly joined
  4838	            // peer as an author — `learn_members`, reading the bundle records off this node's own
  4839	            // board — lives inside `sync_one`, which only runs for channels that already passed the
  4840	            // filter. So a peer that has just joined is skipped for having no entries, by the node
  4841	            // holding the evidence that it belongs, and the only code that would fix that sits
  4842	            // behind the check it is meant to satisfy. `learn_members`' own comment says reading
  4843	            // membership from the board "is a precondition for reconciling at all"; it was not one.
  4844	            //
  4845	            // The consequence, measured as a user: a message posted seconds after somebody joins is
  4846	            // **lost, not delayed** — the sender skips them, the connect trigger is consumed, and
  4847	            // the next chance is a full `SYNC_INTERVAL_SECS`. With the daemons settled, twelve posts
  4848	            // crossed twelve times in 0-1s; posting immediately after a join lost one in six even
  4849	            // after the owed-push fix below.
  4850	            //
  4851	            // Done only on a connect, not every tick: this reads the board and admits authors, which
  4852	            // is exactly the work a new connection warrants and would be waste on the interval.
  4853	            // Candidates first, decided after: the membership test below needs `&mut self` (it may
  4854	            // admit a member from this node's own board), which the maps cannot be borrowed across.
  4855	            let mut member_rooms: Vec<Digest32> = Vec::new();
  4856	            for cid in self.channels.keys() {
  4857	                if trigger == SyncTrigger::LocalAppend
  4858	                    && (!self.pending_push.contains(cid)
  4859	                        || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
  4860	                {
  4861	                    continue;
  4862	                }
  4863	                if self.in_session_with(cid, &peer) || self.publishing.contains(&(*cid, peer)) {
  4864	                    owed.push(*cid);
  4865	                    continue;
  4866	                }
  4867	                member_rooms.push(*cid);
  4868	            }
  4869	            // **A room goes only to a peer that belongs to it.** On a fresh connection this pushed
  4870	            // *every* open room to the peer — the inbound half of D5 refuses a non-member's request,
  4871	            // and this was the outbound half handing the same log over unasked. The bypass existed
  4872	            // because a peer that has just joined is not yet an author in this node's view;
  4873	            // `may_sync` covers that case properly, by admitting the peer from this node's own board
  4874	            // before deciding, which is the evidence the bypass was standing in for.
  4875	            //
  4876	            // **An anchor gets the rooms that name it, not every room** (V29-04, #39). An anchor was
  4877	            // pushed every room this node held because `anchor_ids` held it, and `anchor_ids` holds
  4878	            // the anchors named by ANY room's invite link: an anchor named only by room A's link was
  4879	            // handed room B's log unasked, while that anchor's own `may_sync` would have refused B
  4880	            // inbound. vox-bc's verifier reproduced it with real nodes: the other room's anchor was
  4881	            // pushed room B, one session and five entries. `may_sync` already accepts a room's own
  4882	            // anchors, and the configured ones are in every room's anchor set, so it decides alone.
  4883	            for cid in member_rooms {
  4884	                let belongs = {
  4885	                    let Some(epoch) = (match self.channels.get(&cid) {
  4886	                        Some(shared) => Some(shared.lock().await.epoch()),
  4887	                        None => None,
  4888	                    }) else {
  4889	                        continue;
  4890	                    };
  4891	                    self.may_sync(&cid, &peer, epoch).await
  4892	                };
  4893	                if belongs {
  4894	                    channels.push(cid);
  4895	                }
  4896	            }
  4897	            // An anchor forwards a room it keeps only to that room's authors — read fresh off its
  4898	            // own board first, so a member that has just been vouched for is not skipped. It used to
  4899	            // forward every kept room to any peer that connected or pushed.
  4900	            let mut kept_rooms: Vec<Digest32> = Vec::new();
  4901	            for cid in self.anchored.keys() {
  4902	                if trigger == SyncTrigger::LocalAppend
  4903	                    && (!self.pending_push.contains(cid)
  4904	                        || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
  4905	                {
  4906	                    continue;
  4907	                }
  4908	                if self.in_session_with(cid, &peer) {
  4909	                    owed.push(*cid);
  4910	                    continue;
  4911	                }
  4912	                kept_rooms.push(*cid);
  4913	            }
  4914	            for cid in kept_rooms {
  4915	                self.refresh_anchored_authors(&cid).await;
  4916	                let Some(state) = self.anchored.get(&cid).map(Arc::clone) else {
  4917	                    continue;
  4918	                };
  4919	                if state.lock().await.is_author(&peer) {
  4920	                    channels.push(cid);
  4921	                }
  4922	            }
  4923	            for channel_id in channels {
  4924	                if self.sync_one(&channel_id, peer).await {
  4925	                    ran = true;
  4926	                    // Any session carries the room's latest append, whatever triggered it.
  4927	                    self.pushed_to.entry(channel_id).or_default().insert(peer);
  4928	                    if trigger == SyncTrigger::LocalAppend {
  4929	                        pushed.insert(channel_id);
  4930	                    }
  4931	                }
  4932	            }
  4933	            if let Some(schedule) = self.schedules.get_mut(&peer) {
  4934	                schedule.note_synced(now);
  4935	                // **A room skipped because it was mid-session is owed, not synced.**
  4936	                //
  4937	                // The in-flight mark is per room, so when two peers came due for one room in the
  4938	                // same pass the first took it and the second was skipped — and `note_synced` above
  4939	                // then recorded the skipped peer as synced at the same `now` as the first. Both came
  4940	                // due together again, in the same `BTreeMap` order, and the same peer lost again:
  4941	                // **aligned once, aligned forever.** A local append makes every peer due at once, so
  4942	                // the alignment was the default after the first post, and which peer starved came
  4943	                // down to how the fingerprints sorted.
  4944	                //
  4945	                // Measured in `node_m15_anchor_gate` (instrumented, by the other session): in every
  4946	                // red, each member skipped the *other member* nine rounds running while its only
  4947	                // session — with the anchor — failed each time, so the one leg that could carry the
  4948	                // room never ran. Red about half the time in CI since before v0.2.5.
  4949	                //
  4950	                // Owed is not the unconditional retry the note on `pending_push` below warns
  4951	                // against: nothing here takes a lock, and it is retried only while that room is
  4952	                // mid-session, which is milliseconds. The next tick finds the room free.
  4953	                if !owed.is_empty() {
  4954	                    owed_rooms.extend(owed.iter().copied());
  4955	                    schedule.note_local_append();
  4956	                    self.owed_first.insert(peer);
  4957	                }
  4958	            }
  4959	        }
  4960	        // **Keep what did not go out.** This cleared unconditionally, which discarded the intent to
  4961	        // push an append whenever it had not actually been pushed — and the ordinary case is a peer
  4962	        // that has just joined: `note_local_append` marks "every peer's schedule due", but a peer
  4963	        // whose `NetEvent::Connected` the actor has not handled yet **has no schedule to mark**, so
  4964	        // nothing was owed to it and the entry was dropped rather than delayed. It then waited for
  4965	        // that peer's own `SYNC_INTERVAL_SECS`, and if that raced too, longer.
  4966	        //
  4967	        // Measured as a user: with the daemons settled, twelve posts crossed twelve times in 0-1s;
  4968	        // the proof that posts seconds after joining lost one in three.
  4969	        //
  4970	        // Note what is deliberately NOT changed: `note_synced` above still runs whether or not
  4971	        // anything went out. Making it conditional looks right and is wrong — it leaves the peer due
  4972	        // every tick, so one that cannot sync is retried once a second, each attempt taking the
  4973	        // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
  4974	        // hold on failure; what must survive is the work owed, which is this line.
  4975	        self.pending_push.retain(|cid| !pushed.contains(cid));
  4976	        // **After** the retain, or it undoes this. The skip happens in exactly the pass where the
  4977	        // room *was* pushed — to whichever peer took it first — so an owed room added inside the loop
  4978	        // was then removed here as "pushed", and the skipped peer's retry next tick found nothing
  4979	        // owed and dropped the push. It still arrived, on the next interval: up to 30s late instead
  4980	        // of immediately, and invisible to any gate that only asks whether it arrived. Found in
  4981	        // review by the other session.
  4982	        //
  4983	        // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
  4984	        // push to a peer whose session then fails is counted as done.
  4985	        self.pending_push.extend(owed_rooms);
  4986	        ran
  4987	    }
  4988	
  4989	    /// Start reconciling one channel with one peer: learn who else has joined, then
  4990	    /// hand the channel to a detached session task.
  4991	    ///
  4992	    /// Returns whether a session was *started*. It is deliberately not awaited — see
  4993	    /// [`NetEvent::SyncDone`] for why awaiting deadlocks two nodes that start at the
  4994	    /// same moment. While the channel is away it is invisible to commands (they answer
  4995	    /// `UnknownChannel`) and, usefully, to this function, so a second pass cannot start
  4996	    /// a concurrent session for the same channel.
  4997	    async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
  4998	        let Some(net) = self.net.as_ref().map(Arc::clone) else {
  4999	            return false;
  5000	        };
  5001	        let Some(conn) = net.manager().existing(&peer) else {
  5002	            return false;
  5003	        };
  5004	        let Some(store) = self.log_store() else {
  5005	            return false;
  5006	        };
  5007	        let target = match (
  5008	            self.channels.get(channel_id).map(Arc::clone),
  5009	            self.anchored.get(channel_id).map(Arc::clone),
  5010	        ) {
  5011	            (Some(shared), _) => SessionTarget::Channel(shared),
  5012	            (None, Some(state)) => SessionTarget::Anchored(state),
  5013	            (None, None) => return false,
  5014	        };
  5015	        // An anchor's authors come from its own board, which is local: cheap, and it has to happen
  5016	        // before the session so the anchor can verify what arrives.
  5017	        if matches!(target, SessionTarget::Anchored(_)) {
  5018	            self.refresh_anchored_authors(channel_id).await;
  5019	        }
  5020	        if self.in_session_with(channel_id, &peer) {
  5021	            return false; // a session with this peer already has this room
  5022	        }
  5023	        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
  5024	            return false; // past the cap: skipped, not queued. The schedule comes round again.
  5025	        };
  5026	        self.syncing.insert((*channel_id, peer));
  5027	        let admit_store = self.profile.as_ref().map(Profile::store_handle);
  5028	        let cid = *channel_id;
  5029	        let now = self.now();
  5030	        let tx = self.net_tx.clone();
  5031	        tokio::spawn(async move {
  5032	            let _slot = slot;
  5033	            // 1. Learn who else has joined, or the first entry from a newer member kills the session
  5034	            //    (ADR-008). A round trip, so it belongs here and not on the actor.
  5035	            let epoch = match &target {
  5036	                SessionTarget::Channel(shared) => {
  5037	                    let known = shared.lock().await.epoch();
  5038	                    if let Some(pstore) = admit_store {
  5039	                        if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
  5040	                            {
  5041	                                let mut ch = shared.lock().await;
  5042	                                let _ = admit_board_records(
  5043	                                    &mut ch,
  5044	                                    &pstore,
  5045	                                    &set.bundles,
  5046	                                    ChannelState::MAX_ADMISSIONS_PER_SWEEP,
  5047	                                    now,
  5048	                                )
  5049	                                .await;
  5050	                            }
  5051	                            // What the peer's board holds is filed on this node's own, so its board
  5052	                            // carries the whole membership it knows. Bundles go first: they carry
  5053	                            // the key an address record is verified with (M15.2a). Mirroring to the
  5054	                            // anchors follows on the actor when `SyncDone` lands, because that needs
  5055	                            // channel state.
  5056	                            for wire in set
  5057	                                .bundles
  5058	                                .iter()
  5059	                                .map(MemberBundleRecord::to_wire)
  5060	                                .chain(set.members.iter().map(RendezvousRecord::to_wire))
  5061	                            {
  5062	                                let _ = net.publish_local(&wire);
  5063	                            }
  5064	                            // **And the other way: what this node's board holds that the peer's
  5065	                            // lacks.** A member who joined through this node is on this node's
  5066	                            // board and no other, and the peer learned of it only when *it* next
  5067	                            // read this board, on its own periodic sync: 24–28 s for a third
  5068	                            // member to see a new one, measured. Offered here, a push that follows
  5069	                            // a join carries the newcomer to every connected member at once.
  5070	                            // Best-effort: a refusal (a record the peer's board already holds
  5071	                            // newer) costs nothing, and the peer's own sync still reads this board.
  5072	                            let missing = net.board_records_missing_from(&cid, known, &set);
  5073	                            if !missing.is_empty() {
  5074	                                if let Ok(mut client) =
  5075	                                    crate::nat::service::RendezvousClient::open(&conn).await
  5076	                                {
  5077	                                    for wire in &missing {
  5078	                                        if let Err(e) = client.put(wire).await {
  5079	                                            if !matches!(e, Error::RendezvousRejected(_)) {
  5080	                                                break;
  5081	                                            }
  5082	                                        }
  5083	                                    }
  5084	                                    client.finish();
  5085	                                }
  5086	                            }
  5087	                        }
  5088	                    }
  5089	                    shared.lock().await.epoch()
  5090	                }
  5091	                SessionTarget::Anchored(state) => state.lock().await.epoch(),
  5092	            };
  5093	            // 2. Open the stream. Also a round trip.
  5094	            //
  5095	            // **A stream that will not open still reports.** This returned without a word, and the
  5096	            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
  5097	            // marked mid-session for good: every later sync of it skipped, every inbound one
  5098	            // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
  5099	            let handle = tokio::runtime::Handle::current();
  5100	            let transport =
  5101	                match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
  5102	                    Ok(t) => t,
  5103	                    Err(e) => {
  5104	                        let _ = tx
  5105	                            .send(NetEvent::SyncDone {
  5106	                                channel_id: cid,
  5107	                                peer,
  5108	                                outcome: Err(e),
  5109	                            })
  5110	                            .await;
  5111	                        return;
  5112	                    }
  5113	                };
  5114	            // 3. Run the session. It takes the room's lock inside each protocol step and never across
  5115	            //    a send or a receive (`sync_over_room`), so a peer slow to answer no longer holds the
  5116	            //    room — or, through `publish()` and every other lock on it, the actor.
  5117	            let joined = tokio::task::spawn_blocking(move || {
  5118	                let mut t = transport;
  5119	                match target {
  5120	                    SessionTarget::Channel(shared) => {
  5121	                        crate::node::channel::ChannelState::sync_over_room(
  5122	                            &shared, &store, &mut t, now,
  5123	                        )
  5124	                    }
  5125	                    SessionTarget::Anchored(state) => {
  5126	                        crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
  5127	                    }
  5128	                }
  5129	            })
  5130	            .await;
  5131	            // A session that panicked still hands the room back: `Err` from the join is the panic.
  5132	            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
  5133	                "sync session panicked",
  5134	            )));
  5135	            let _ = tx
  5136	                .send(NetEvent::SyncDone {
  5137	                    channel_id: cid,
  5138	                    peer,
  5139	                    outcome,
  5140	                })
  5141	                .await;
  5142	        });
  5143	        true
  5144	    }
  5145	
  5146	    /// Take the channel out of the actor's map and run a session on its own task,
  5147	    /// returning it through [`NetEvent::SyncDone`].
  5148	    fn start_session(
  5149	        &mut self,
  5150	        channel_id: Digest32,
  5151	        peer: Digest32,
  5152	        transport: crate::transport::quic::QuicStreamTransport,
  5153	    ) {
  5154	        let Some(store) = self.log_store() else {
  5155	            return;
  5156	        };
  5157	        let target = match (
  5158	            self.channels.get(&channel_id).map(Arc::clone),
  5159	            self.anchored.get(&channel_id).map(Arc::clone),
  5160	        ) {
  5161	            (Some(shared), _) => SessionTarget::Channel(shared),
  5162	            (None, Some(state)) => SessionTarget::Anchored(state),
  5163	            (None, None) => return,
  5164	        };
  5165	        // Marked here, past both early returns above, so a session that never starts never
  5166	        // leaves the room marked. Its caller used to mark it first.
  5167	        self.syncing.insert((channel_id, peer));
  5168	        let now = self.now();
  5169	        let tx = self.net_tx.clone();
  5170	        tokio::spawn(async move {
  5171	            let joined = tokio::task::spawn_blocking(move || {
  5172	                // The room is locked inside each protocol step only, never across the
  5173	                // network (`sync_over_room`).
  5174	                let mut t = transport;
  5175	                match target {
  5176	                    SessionTarget::Channel(shared) => {
  5177	                        crate::node::channel::ChannelState::sync_over_room(
  5178	                            &shared, &store, &mut t, now,
  5179	                        )
  5180	                    }
  5181	                    SessionTarget::Anchored(state) => {
  5182	                        crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
  5183	                    }
  5184	                }
  5185	            })
  5186	            .await;
  5187	            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
  5188	                "sync session panicked",
  5189	            )));
  5190	            let _ = tx
  5191	                .send(NetEvent::SyncDone {
  5192	                    channel_id,
  5193	                    peer,
  5194	                    outcome,
  5195	                })
  5196	                .await;
  5197	        });
  5198	    }
  5199	
  5200	    /// Reconcile a channel with every member this node can reach, now (the `Sync`
  5201	    /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
  5202	    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
  5203	        if self.net.is_none() {
  5204	            return Outcome::Failed(Fault::NotNetworked);
  5205	        }
  5206	        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
  5207	            return Outcome::Failed(Fault::UnknownChannel);
  5208	        };
  5209	        let peers: Vec<Digest32> = {
  5210	            let channel = shared.lock().await;
  5211	            let me = channel.me();
  5212	            channel.members().into_iter().filter(|m| *m != me).collect()
  5213	        };
  5214	        let mut synced = 0usize;
  5215	        for peer in peers {
  5216	            if self.sync_one(channel_id, peer).await {
  5217	                synced += 1;
  5218	            }
  5219	        }
  5220	        if synced == 0 {
  5221	            return Outcome::Failed(Fault::Unreachable);
  5222	        }
  5223	        Outcome::Done
  5224	    }
  5225	
  5226	    /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
  5227	    /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
  5228	    /// Serve one sync session for a request that has **already been read**.
  5229	    ///
  5230	    /// The preamble is read on the per-connection stream task (`node::network`), not here: the
  5231	    /// actor is the only writer of channel state and anything it awaits inline stops the whole
  5232	    /// node, so it must never wait on an untrusted peer to speak. What it does here is local
  5233	    /// and ordered, which is what the single-task design is for.
  5234	    /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
  5235	    /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
  5236	    /// of any room this node holds may — and the preamble then names whichever channel the
  5237	    /// peer likes. Nothing here checked the two against each other, so a member of room A who
  5238	    /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
  5239	    /// [`Self::may_sync`] for who counts.
  5240	    async fn run_sync_session(
  5241	        &mut self,
  5242	        peer: Digest32,
  5243	        channel_id: Digest32,
  5244	        epoch: u64,
  5245	        send: quinn::SendStream,
  5246	        recv: quinn::RecvStream,
  5247	    ) {
  5248	        use crate::node::syncstream::accept_sync;
  5249	        // Answering while our own session holds this room is the other half of the deadlock.
  5250	        //
  5251	        // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
  5252	        // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
  5253	        // silent refusal that reads as a hang, which is the shape of defect this whole change
  5254	        // exists to remove. A reset reaches it on the next read, and its schedule brings it
  5255	        // back in a second.
  5256	        //
  5257	        // **Refused before the lock, not after.** A session holds this room's mutex for its whole
  5258	        // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
  5259	        // behind the very session this check exists to detect.
  5260	        if self.in_session_with(&channel_id, &peer) {
  5261	            let (mut send, mut recv) = (send, recv);
  5262	            crate::node::net::refuse_stream(&mut send, &mut recv);
  5263	            return;
  5264	        }
  5265	        // Only a channel we hold open at that epoch — or keep as an anchor — can be
  5266	        // reconciled. An anchor whose board just received the genesis adopts it here
  5267	        // rather than making the member wait for the next tick.
  5268	        if !self.channels.contains_key(&channel_id) {
  5269	            self.adopt_anchored(&channel_id).await;
  5270	            self.refresh_anchored_authors(&channel_id).await;
  5271	        }
  5272	        let matches_epoch = match (
  5273	            self.channels.get(&channel_id),
  5274	            self.anchored.get(&channel_id),
  5275	        ) {
  5276	            (Some(shared), _) => shared.lock().await.epoch() == epoch,
  5277	            (None, Some(state)) => state.lock().await.epoch() == epoch,
  5278	            (None, None) => false,
  5279	        };
  5280	
  5281	        // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
  5282	        // no log for it, most often — or at an epoch it is not at, returned here and let the streams
  5283	        // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
  5284	        // connection that died. Every push to an anchor that keeps no log for the room read as a
  5285	        // network fault. A coded reset says what happened. (It does not recover time: a dropped
  5286	        // stream already ended the initiator's session within milliseconds, measured; the long
  5287	        // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
  5288	        if !matches_epoch {
  5289	            let (mut send, mut recv) = (send, recv);
  5290	            crate::node::net::refuse_stream(&mut send, &mut recv);
  5291	            return;
  5292	        }
  5293	        if !self.may_sync(&channel_id, &peer, epoch).await {
  5294	            // Refused explicitly, with the same coded reset as a stream kind the peer may not
  5295	            // open, rather than left to read for a frame that never comes.
  5296	            let (mut send, mut recv) = (send, recv);
  5297	            crate::node::net::refuse_stream(&mut send, &mut recv);
  5298	            return;
  5299	        }
  5300	        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
  5301	        self.start_session(channel_id, peer, transport);
  5302	    }
  5303	
  5304	    /// Whether `peer` may reconcile `channel_id`'s log with this node.
  5305	    ///
  5306	    /// - An **admitted author** of that room. If it is not one yet, this node's own board is
  5307	    ///   consulted first — local, so cheap — because a member that joined through somebody
  5308	    ///   else is on the board before it is in this node's author table, and refusing it for
  5309	    ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
  5310	    ///   Admission there takes the same M17.6 evidence as everywhere else.
  5311	    /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
  5312	    ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
  5313	    ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
  5314	    ///   room's link is not an anchor of this one.
  5315	    ///
  5316	    /// For a room this node only anchors, the peer must be an author the board knows.
  5317	    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
  5318	        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
  5319	            {
  5320	                let channel = shared.lock().await;
  5321	                if channel.is_author(peer)
  5322	                    || channel.anchors().nodes().iter().any(|a| a.id == *peer)
  5323	                {
  5324	                    return true;
  5325	                }
  5326	            }
  5327	            let (Some(net), Some(store)) = (
  5328	                self.net.as_ref().map(Arc::clone),
  5329	                self.profile.as_ref().map(Profile::store_handle),
  5330	            ) else {
  5331	                return false;
  5332	            };
  5333	            let bundles = net.board_bundles(channel_id, epoch);
  5334	            if !bundles.iter().any(|b| b.author_id == *peer) {
  5335	                return false;
  5336	            }
  5337	            let now = self.now();
  5338	            let mut channel = shared.lock().await;
  5339	            let _ = admit_board_records(
  5340	                &mut channel,
  5341	                &store,
  5342	                &bundles,
  5343	                ChannelState::MAX_ADMISSIONS_PER_SWEEP,
  5344	                now,
  5345	            )
  5346	            .await;
  5347	            return channel.is_author(peer);
  5348	        }
  5349	        if let Some(state) = self.anchored.get(channel_id) {
  5350	            return state.lock().await.is_author(peer);
  5351	        }
  5352	        false
  5353	    }
  5354	
  5355	    /// Accept an inbound [`PairwiseFrame::Hello`], establishing the responder half of
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs[90m [limit=190][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs[90m [offset=235, limit=210][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=2635, limit=100][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs | nl -ba
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
   141	/// Read the preamble from an accepted `sync` stream: which `(channelID, epoch)` the
   142	/// peer wants to reconcile.
   143	pub async fn read_sync_request(recv: &mut quinn::RecvStream) -> Result<(Digest32, u64)> {
   144	    let bytes = read_frame(recv, MAX_SYNC_PREAMBLE)
   145	        .await?
   146	        .ok_or(Error::MalformedGovernance(
   147	            "sync stream closed before preamble",
   148	        ))?;
   149	    let mut d = Decoder::new(&bytes);
   150	    if d.array()? != 2 {
   151	        return Err(Error::MalformedGovernance("sync preamble arity"));
   152	    }
   153	    let channel_id: Digest32 = d
   154	        .bytes()?
   155	        .try_into()
   156	        .map_err(|_| Error::MalformedGovernance("sync preamble channel_id"))?;
   157	    let epoch = d.uint()?;
   158	    d.finish()?;
   159	    Ok((channel_id, epoch))
   160	}
   161	
   162	/// Wrap an already-accepted, already-authorized `sync` stream as the ADR-008
   163	/// transport (the manager accepted and classified it).
   164	#[must_use]
   165	pub fn accept_sync(handle: Handle, send: SendStream, recv: RecvStream) -> QuicStreamTransport {
   166	    QuicStreamTransport::new(handle, send, recv)
   167	}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | nl -ba | sed -n '300,480p'
300	                .get_by_hash(&entry_hash)
   301	                .ok_or(Error::MalformedGovernance("synced entry vanished"))?;
   302	            let wire = entry.to_wire();
   303	            let is_governance = entry
   304	                .payload
   305	                .as_deref()
   306	                .map(classify_payload)
   307	                .transpose()?
   308	                .is_some_and(|k| k == EntryKind::Governance);
   309	            let id = self.next_log_id;
   310	            let seg = seal_segment(&self.sek, SegmentKind::AnchorLog, id, &wire)?;
   311	            if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::AnchorLog, id, &seg) {
   312	                self.poisoned = true;
   313	                return Err(e);
   314	            }
   315	            self.next_log_id = id.saturating_add(1);
   316	            if is_governance {
   317	                out.governance += 1;
   318	            }
   319	        }
   320	        Ok(out)
   321	    }
   322	
   323	    /// Reconcile with a peer over `transport`, holding `shared`'s lock only inside each protocol
   324	    /// step. See [`crate::log::sync::SessionRoom`] and `ChannelState::sync_over_room`.
   325	    ///
   326	    /// # Errors
   327	    /// The copy is poisoned, a persist fails, or the session hard-fails.
   328	    pub fn sync_over_room<T: Transport>(
   329	        shared: &tokio::sync::Mutex<Self>,
   330	        store: &Store,
   331	        transport: &mut T,
   332	    ) -> Result<SyncOutcome> {
   333	        let epoch = {
   334	            let st = shared.blocking_lock();
   335	            if st.poisoned {
   336	                return Err(Error::Profile(
   337	                    "anchored channel is poisoned after a failed persist; reopen it",
   338	                ));
   339	            }
   340	            st.epoch
   341	        };
   342	        let room = AnchorSessionRoom {
   343	            shared,
   344	            store,
   345	            epoch,
   346	            out: std::cell::RefCell::new(SyncOutcome::default()),
   347	            fatal: std::cell::RefCell::new(None),
   348	        };
   349	        let session = crate::log::sync::frontier_session_room(transport, &room);
   350	        if let Some(e) = room.fatal.take() {
   351	            return Err(e);
   352	        }
   353	        let mut out = room.out.into_inner();
   354	        match session {
   355	            Ok(n) => {
   356	                out.applied = n;
   357	                Ok(out)
   358	            }
   359	            Err(code) => Err(sync_failure(code)),
   360	        }
   361	    }
   362	
   363	    fn rebuild_admission(&mut self) {
   364	        let mut admission = AdmissionPolicy::new();
   365	        for author in self.authors.keys() {
   366	            admission.admit(self.channel_id, self.epoch, *author);
   367	        }
   368	        self.admission = admission;
   369	    }
   370	
   371	    fn persist_meta(&mut self, store: &Store) -> Result<()> {
   372	        let mut e = Encoder::new();
   373	        e.array(3)
   374	            .uint(META_VERSION)
   375	            .bytes(&self.genesis.to_wire())
   376	            .bytes(&authors_bytes(&self.authors));
   377	        let seg = seal_segment(&self.sek, SegmentKind::AnchorMeta, SEG_META, &e.finish())?;
   378	        if let Err(err) =
   379	            store.put_segment(&self.channel_id, SegmentKind::AnchorMeta, SEG_META, &seg)
   380	        {
   381	            self.poisoned = true;
   382	            return Err(err);
   383	        }
   384	        Ok(())
   385	    }
   386	}
   387	
   388	fn parse_meta(bytes: &[u8]) -> Result<(Genesis, BTreeMap<Digest32, CompositePublicKey>)> {
   389	    let mut d = Decoder::new(bytes);
   390	    if d.array()? != 3 {
   391	        return Err(Error::MalformedAtRest("anchor meta arity"));
   392	    }
   393	    if d.uint()? != META_VERSION {
   394	        return Err(Error::MalformedAtRest("anchor meta version"));
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
   431	    }
   432	
   433	    fn wants(
   434	        &self,
   435	        remote: &[crate::log::sync::FeedFrontier],
   436	    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
   437	        Ok(crate::log::sync::wants_for(&self.copy()?.dag, remote))
   438	    }
   439	
   440	    fn entries(
   441	        &self,
   442	        wants: &[crate::log::sync::WantRange],
   443	    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
   444	        Ok(crate::log::sync::entries_for_wants(
   445	            &self.copy()?.dag,
   446	            wants,
   447	        ))
   448	    }
   449	
   450	    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
   451	        let mut guard = self.copy()?;
   452	        let st = &mut *guard;
   453	        let before = st.heads();
   454	        let resolver = ChannelAuthors::new(st.authors.clone());
   455	        // Absorb what was stored, then report the failure: see `ChannelSessionRoom::apply`.
   456	        let stored = crate::log::sync::apply_staged(&mut st.dag, &resolver, &st.admission, &staged);
   457	        match st.absorb_arrived(self.store, &before) {
   458	            Ok(got) => {
   459	                self.out.borrow_mut().governance += got.governance;
   460	                stored
   461	            }
   462	            Err(e) => {
   463	                *self.fatal.borrow_mut() = Some(e);
   464	                Err(crate::wire::WireError::TransportFailed)
   465	            }
   466	        }
   467	    }
   468	}
[0m
The main gaps so far are in held-stream bounds and proof observability. The proposed 20-second bound runs on the peer, not on the receiver’s holding queue, and several proof preconditions require fields absent from S0b’s session log. I’m checking the apply and replacement paths for concrete failures before assigning severity.
[0m✱ [0mGrep "revok|frozen|poisoned|fn absorb_arrived|fn resolver|fn heads|epoch ="[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs · 82 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs[90m [offset=650, limit=300][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=725, limit=90][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/net.rs | nl -ba | sed -n '650,825p;950,1030p'
650	        self.file_inner(conn, true)
   651	    }
   652	
   653	    /// [`Self::file_reporting`]'s body. `serve_loser` says whether the caller will read a duplicate
   654	    /// this keeps alive: with it the loser is retired and handed back, without it the loser is
   655	    /// closed. There is no third option — a retired connection nobody reads is the worst of both.
   656	    fn file_inner(&self, conn: VoxConnection, serve_loser: bool) -> Filed {
   657	        let peer = conn.peer_id();
   658	        let mut map = lock(&self.conns);
   659	        if let Some(existing) = map.get(&peer) {
   660	            // **A held connection that has gone silent is not a rival.** The process behind it
   661	            // is gone (see [`SILENCE_IS_DEATH`]), so the newcomer is filed and the dead one
   662	            // closed, whatever the tie-break would have said. Everything else is decided by
   663	            // path class and then by `tie_key`, which both ends compute identically.
   664	            if is_live(existing) && self.is_silent(existing) {
   665	                existing.close(WireError::AuthenticatorInvalid);
   666	            } else if is_live(existing) {
   667	                let existing = Arc::clone(existing);
   668	                let (new_class, held_class) = (
   669	                    path_class(&self.endpoint, &conn),
   670	                    path_class(&self.endpoint, &existing),
   671	                );
   672	                let newcomer_loses = new_class < held_class
   673	                    || (new_class == held_class && tie_key(&conn) >= tie_key(&existing));
   674	                if newcomer_loses {
   675	                    drop(map);
   676	                    if !serve_loser {
   677	                        conn.close(WireError::AuthenticatorInvalid);
   678	                        return Filed {
   679	                            kept: existing,
   680	                            also_serve: None,
   681	                        };
   682	                    }
   683	                    let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
   684	                    let retired = Arc::new(conn);
   685	                    lock(&self.retiring).push((Arc::clone(&retired), retire_at));
   686	                    return Filed {
   687	                        kept: existing,
   688	                        also_serve: Some(retired),
   689	                    };
   690	                }
   691	                let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
   692	                lock(&self.retiring).push((existing, retire_at));
   693	            }
   694	        }
   695	        let conn = Arc::new(conn);
   696	        // The baseline for its silence: it has just completed a handshake, so it was heard now.
   697	        let _ = self.silent_for(&conn);
   698	        map.insert(peer, Arc::clone(&conn));
   699	        Filed {
   700	            kept: conn,
   701	            also_serve: None,
   702	        }
   703	    }
   704	
   705	    /// How long a retired connection is kept readable before it is closed.
   706	    #[must_use]
   707	    pub fn retire_grace_secs(&self) -> u64 {
   708	        self.retire_grace_secs
   709	    }
   710	
   711	    /// Close every retired connection whose grace has elapsed (or that the peer
   712	    /// already closed). Returns how many were closed. The node's tick calls this.
   713	    pub fn retire_expired(&self) -> usize {
   714	        let now = (self.clock)();
   715	        let mut retiring = lock(&self.retiring);
   716	        let before = retiring.len();
   717	        retiring.retain(|(conn, at)| {
   718	            // **Still carried** means somebody other than this list holds the connection:
   719	            // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
   720	            // long as they run, so the strong count is the liveness signal, and it needs no
   721	            // bookkeeping that could disagree with reality.
   722	            //
   723	            // The grace alone is not enough to close on. It is sized for a request finishing
   724	            // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
   725	            // file transfer is in flight for hours. Closing on the timer killed live sessions
   726	            // mid-stream whenever a better path displaced the one they were on, which reached
   727	            // the person as `Connection reset by peer` in the middle of their work.
   728	            let still_carried = Arc::strong_count(conn) > 1;
   729	            if (now >= *at && !still_carried) || !is_live(conn) {
   730	                conn.close(WireError::AuthenticatorInvalid);
   731	                false
   732	            } else {
   733	                true
   734	            }
   735	        });
   736	        before - retiring.len()
   737	    }
   738	
   739	    /// Retire `conn` as [`Self::file`] would when a better path displaces it. For proofs of
   740	    /// the retirement rule, which otherwise needs two real paths to the same peer.
   741	    #[doc(hidden)]
   742	    pub fn retire_for_test(&self, conn: &Arc<VoxConnection>) {
   743	        // Exactly what `file` does: the displaced connection leaves the per-peer map and
   744	        // moves to the retiring list. Leaving it in the map would keep a reference of the
   745	        // manager's own, which is not what "still carried" means.
   746	        lock(&self.conns).retain(|_, c| !Arc::ptr_eq(c, conn));
   747	        let at = (self.clock)().saturating_add(self.retire_grace_secs);
   748	        lock(&self.retiring).push((Arc::clone(conn), at));
   749	    }
   750	
   751	    /// How many displaced connections are still within their grace.
   752	    #[must_use]
   753	    pub fn retiring_count(&self) -> usize {
   754	        lock(&self.retiring).len()
   755	    }
   756	
   757	    /// Drop every connection the peer or the network has closed. Returns how many
   758	    /// were reaped.
   759	    pub fn prune_closed(&self) -> usize {
   760	        let mut map = lock(&self.conns);
   761	        let before = map.len();
   762	        map.retain(|_, c| is_live(c));
   763	        before - map.len()
   764	    }
   765	
   766	    /// The peers with a live connection, in unspecified order.
   767	    #[must_use]
   768	    pub fn peers(&self) -> Vec<Digest32> {
   769	        let held: Vec<(Digest32, Arc<VoxConnection>)> = lock(&self.conns)
   770	            .iter()
   771	            .map(|(p, c)| (*p, Arc::clone(c)))
   772	            .collect();
   773	        held.into_iter()
   774	            .filter(|(_, c)| is_live(c) && !self.is_silent(c))
   775	            .map(|(p, _)| p)
   776	            .collect()
   777	    }
   778	
   779	    /// Close and forget the connection to `peer`, with the coded reason.
   780	    pub fn close_peer(&self, peer: &Digest32, err: WireError) -> bool {
   781	        match lock(&self.conns).remove(peer) {
   782	            Some(conn) => {
   783	                conn.close(err);
   784	                true
   785	            }
   786	            None => false,
   787	        }
   788	    }
   789	
   790	    /// Close every connection that runs **over a relay circuit**, and hand back how many.
   791	    ///
   792	    /// Done before the others at shutdown: a relayed connection's CONNECTION_CLOSE travels inside
   793	    /// a circuit on another connection (the one to the relay), so closing that carrier at the same
   794	    /// moment loses the frame, and the far peer learns only from `SILENCE_IS_DEATH`.
   795	    pub fn close_relayed(&self) -> usize {
   796	        let relayed = |c: &VoxConnection| path_class(&self.endpoint, c) == PathClass::Relayed;
   797	        let mut n = 0;
   798	        for (conn, _) in lock(&self.retiring).iter() {
   799	            if relayed(conn) {
   800	                conn.close(WireError::AuthenticatorInvalid);
   801	                n += 1;
   802	            }
   803	        }
   804	        for conn in lock(&self.conns).values() {
   805	            if relayed(conn) {
   806	                conn.close(WireError::AuthenticatorInvalid);
   807	                n += 1;
   808	            }
   809	        }
   810	        n
   811	    }
   812	
   813	    /// Close every connection (node shutdown).
   814	    pub fn close_all(&self) {
   815	        for (conn, _) in lock(&self.retiring).drain(..) {
   816	            conn.close(WireError::AuthenticatorInvalid);
   817	        }
   818	        for (_, conn) in lock(&self.conns).drain() {
   819	            conn.close(WireError::AuthenticatorInvalid);
   820	        }
   821	    }
   822	}
   823	
   824	/// Whether a connection is still usable.
   825	fn is_live(conn: &VoxConnection) -> bool {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | nl -ba | sed -n '3360,3420p;860,925p;3240,3295p'
860	                // record naming itself for any channel this board serves, and is then
   861	                // classified `PendingJoiner` — which may open `Join`. So the read that used to
   862	                // sit in the actor was reachable by anyone who had ever seen an invite link.
   863	                Ok(Inbound::Join { peer, send, recv }) => {
   864	                    failures = 0;
   865	                    let tx = tx.clone();
   866	                    tokio::spawn(async move {
   867	                        let mut recv = recv;
   868	                        let Ok((channel_id, epoch)) =
   869	                            crate::node::joinstream::read_join_request(&mut recv).await
   870	                        else {
   871	                            crate::node::joinstream::refuse_join(send).await;
   872	                            return;
   873	                        };
   874	                        let _ = tx
   875	                            .send(NetEvent::JoinRequest {
   876	                                peer,
   877	                                channel_id,
   878	                                epoch,
   879	                                send,
   880	                                recv,
   881	                            })
   882	                            .await;
   883	                    });
   884	                }
   885	                Ok(Inbound::Sync { peer, send, recv }) => {
   886	                    failures = 0;
   887	                    let tx = tx.clone();
   888	                    let conn = Arc::clone(&conn);
   889	                    tokio::spawn(async move {
   890	                        let mut recv = recv;
   891	                        let Ok((channel_id, epoch)) =
   892	                            crate::node::syncstream::read_sync_request(&mut recv).await
   893	                        else {
   894	                            return;
   895	                        };
   896	                        let _ = tx
   897	                            .send(NetEvent::SyncRequest {
   898	                                conn,
   899	                                peer,
   900	                                channel_id,
   901	                                epoch,
   902	                                send,
   903	                                recv,
   904	                            })
   905	                            .await;
   906	                    });
   907	                }
   908	                Ok(inbound) => {
   909	                    failures = 0;
   910	                    let event = NetEvent::Stream {
   911	                        conn: Arc::clone(&conn),
   912	                        inbound,
   913	                    };
   914	                    if tx.send(event).await.is_err() {
   915	                        return; // the actor is gone
   916	                    }
   917	                }
   918	                Err(_) => {
   919	                    if quic.close_reason().is_some() {
   920	                        break; // the peer or the network closed it
   921	                    }
   922	                    failures += 1;
   923	                    if failures >= MAX_CONSECUTIVE_STREAM_FAILURES {
   924	                        break;
   925	                    }
  3240	                // an anchor receiving a mirror does not mirror it onward and this cannot ring
  3241	                // around a ring of anchors.
  3242	                if self.channels.contains_key(&channel_id) {
  3243	                    self.publish_channel_to_anchors(&channel_id).await;
  3244	                    self.note_new_members(&channel_id).await;
  3245	                }
  3246	            }
  3247	            NetEvent::SyncRequest {
  3248	                conn,
  3249	                peer,
  3250	                channel_id,
  3251	                epoch,
  3252	                send,
  3253	                recv,
  3254	            } => {
  3255	                let _ = &conn;
  3256	                self.run_sync_session(peer, channel_id, epoch, send, recv)
  3257	                    .await;
  3258	            }
  3259	            NetEvent::AddressesDiscovered { mappings } => {
  3260	                // Re-publish every open channel's records: the addresses in them were
  3261	                // composed before discovery and may name only loopback.
  3262	                self.renew_mappings_at = renew_at(self.now(), &mappings);
  3263	                self.port_mappings = mappings;
  3264	                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
  3265	                for channel_id in channels {
  3266	                    self.publish_channel_locally(&channel_id).await;
  3267	                    self.publish_channel_to_anchors(&channel_id).await;
  3268	                }
  3269	            }
  3270	            NetEvent::ReachFailed { peer, why } => {
  3271	                self.answer_pending_consents(
  3272	                    |_, target| *target == peer,
  3273	                    Some(Outcome::Failed(Fault::Unreachable)),
  3274	                )
  3275	                .await;
  3276	                let _ = self.event_tx.send(NodeEvent::PeerUnreachable { peer, why });
  3277	            }
  3278	            NetEvent::UpgradeFailed { peer, reason } => {
  3279	                let _ = self.event_tx.send(NodeEvent::StillRelayed { peer, reason });
  3280	            }
  3281	            NetEvent::AnchorConnected { conn } => {
  3282	                let peer = conn.peer_id();
  3283	                self.anchor_ids.insert(peer);
  3284	                self.adopt_connection(Arc::clone(&conn));
  3285	                self.refresh_network_view().await;
  3286	                let channels: Vec<Digest32> = self.channels.keys().copied().collect();
  3287	                for channel_id in channels {
  3288	                    self.publish_channel_to_anchor(&channel_id, &conn).await;
  3289	                }
  3290	            }
  3291	            NetEvent::BetterPath { conn } => {
  3292	                self.adopt_connection(conn);
  3293	            }
  3294	            NetEvent::Connected { peer } => {
  3295	                // A fresh connection syncs at once (ADR-016), then on the interval.
  3360	            }
  3361	            NetEvent::PushRetry { channel_id, peer } => {
  3362	                self.pending_push.insert(channel_id);
  3363	                // The failed session carried nothing, so this peer is owed the room again.
  3364	                if let Some(to) = self.pushed_to.get_mut(&channel_id) {
  3365	                    to.remove(&peer);
  3366	                }
  3367	                if let Some(schedule) = self.schedules.get_mut(&peer) {
  3368	                    schedule.note_local_append();
  3369	                }
  3370	                self.owed_first.insert(peer);
  3371	                self.push_now = true;
  3372	            }
  3373	            NetEvent::SyncDone {
  3374	                channel_id,
  3375	                peer,
  3376	                outcome,
  3377	            } => {
  3378	                self.syncing.remove(&(channel_id, peer));
  3379	                self.answer_pending_consents(|room, _| *room == channel_id, None)
  3380	                    .await;
  3381	                // **A session that failed delivered nothing, so its push is owed again.**
  3382	                // `run_due_syncs` counts a push as done when the session *starts*, which is the
  3383	                // only thing it can know then; a session the peer refused — because its own
  3384	                // session for this room was running — or that died on the wire carried nothing, and
  3385	                // the entry waited for the peer's next 30s interval. Measured over a forced relay
  3386	                // once pushes went out at once instead of on the tick: median 40–110ms, and a tail
  3387	                // at exactly 30s (p95 29.7–30.0s) — the collisions an immediate push makes more
  3388	                // likely. Owed again, retried on the *next tick* and not at once: a peer that keeps
  3389	                // refusing must not be answered with a tight loop.
  3390	                //
  3391	                // **Owed to that peer only, and not for ever.** The first version re-owed the room to
  3392	                // *every* peer, every time any session failed. A peer whose sessions always fail —
  3393	                // an anchor that keeps no log for the room refuses every one — was then re-owed
  3394	                // every tick, sorted ahead of the member it shared the room with, took the room each
  3395	                // pass, and the member's owed push lost every round: the independent verdict
  3396	                // measured 2–3 relayed runs in 10 losing a message for 120s (vox-bc, #41). Now the
  3397	                // retry goes to the peer that failed, at most `MAX_PUSH_RETRIES` times running; past
  3398	                // that the pair waits for the periodic interval like any other.
  3399	                //
  3400	                // **After a short random wait, not the next tick.** The commonest failure is a
  3401	                // collision: both ends push on the same event, each refuses the other because its
  3402	                // own session for the room is running, and both fail. Retried on the tick, the two
  3403	                // retries landed together again and a message took up to a second (median 364–531ms
  3404	                // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
  3405	                if outcome.is_err() {
  3406	                    let failures = self.push_failures.entry((channel_id, peer)).or_insert(0);
  3407	                    *failures = failures.saturating_add(1);
  3408	                    if *failures <= MAX_PUSH_RETRIES {
  3409	                        let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
  3410	                        let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
  3411	                        let tx = self.net_tx.clone();
  3412	                        tokio::spawn(async move {
  3413	                            tokio::time::sleep(wait).await;
  3414	                            let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
  3415	                        });
  3416	                    }
  3417	                } else {
  3418	                    self.push_failures.remove(&(channel_id, peer));
  3419	                }
  3420	                // The room is free now **whatever the outcome**: a push that found it mid-session
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=5220, limit=105][0m
[0m
[0m$ [0mgh issue list --repo robertelee78/vox --state all --search 'V210-34' --json number,title,body --limit 10
[{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V210-34 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.10.md` at `cde30171222a91d9d8b4466adf56680c61889a0d` (`a224d571633c4af19b76882a47a10fab0f062a88`), V210-34\nAcceptance:\n- As ADR-025 decides.\n\nValidation: ADR-025's proof table, each measured on the base first.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release.\n<!-- work-accountability:end -->\n\n**Sync is scheduled like a switch, not a hub (ADR-025).**\n\nThe decider asked for sync to behave like a switch, \"with slots and queues\". Today:\n- two members posting at once refuse each other's sessions (`SessionBusy`) and retry after a random wait: about 2.3 refused streams per simultaneous round with #180, and 0 late posts;\n- a push past the 16-slot cap is *skipped, not queued*, and can wait for the 30 s interval;\n- a truncated serve counts as done;\n- a receiver stores entries it did not ask for.\n\n**ADR-025** (branch `docs/adr-025-sync-switch`, `docs/adr/ADR-025-sync-scheduling-switch-not-hub.md`) is under three-model review. Revision 3 recommends **full duplex**: inbound sessions are never refused for busy, and both directions run at once, with no collision, tie-break or random wait. It also specifies a per-(room, peer) port with tokens, requests captured at admission, receive coverage, a fair queue over slots, and backoff only for real failures.\n\nNot decided: the option (full duplex / designated opener / glare rule) and whether the collision change goes in v0.2.10 are the decider's.\n\nChecklist (ADR-025 Plan):\n- [ ] S0 #180 and #202 integrated\n- [ ] S0b observability in `vox status --json`\n- [ ] S0c the base measured\n- [ ] S1–S4 implementation\n- [ ] S5 proofs P1–P9\n- [ ] S6 independent verifier\n","number":209,"title":"V210-34: Sync is scheduled like a switch, not a hub (ADR-025)"},{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V210-32 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.10.md` at `7a83571dd940105e46e017ae616e323474fe6e5b` (`175844279826875f7de599b0134e0cf5e3da182a`), V210-32\nAcceptance:\n- Each named proof runs every participant as the shipped `vox`, or is deleted if a real-use proof already holds its claim.\n\nValidation: no file under `crates/*/tests/` constructs an in-process `Node`, checked by search, and each converted proof is red under its item's mutation.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release.\n<!-- work-accountability:end -->\n\nTwelve proofs drive the shipped `vox` but start another participant as an in-process `Node` (ADR-018). Each keeps its own item:\n\n- [ ] RP-32 #139 `a_daemon_follows_its_anchor`\n- [ ] RP-33 #140 `a_long_room_reopens_proof`\n- [ ] RP-34 #141 `agent_hook_proof`\n- [ ] RP-35 #142 `agent_rehearsal_proof`\n- [ ] RP-36 #143 `daemon_proof`\n- [ ] RP-37 #144 `file_exchange_proof`\n- [ ] RP-38 #145 `it_just_works_with_a_daemon_running`\n- [ ] RP-39 #146 `opencode_plugin_proof`\n- [ ] RP-40 #147 `remote_interrupt_proof`\n- [ ] RP-41 #148 `room_verbs_proof`\n- [ ] RP-43 #150 `work_board_proof`\n- [ ] RP-46 #207 `shutdown_releases_the_profile_proof`\n\nFiled at vox's request.\n\n","number":205,"title":"V210-32: Every binary proof runs every participant as the binary"},{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:V0.2.10:V210-24 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.10.md` at `02e95fb1b899e73676283f8c4c65998d4accbe81` (`edb11c712948c4f5045f19d46d6eb7a4008e52b2`)\nSource excerpts:\n> ### V210-24 — No member can appear as another by matching a short fingerprint prefix (security)\n> **Acceptance.** An author in the reader's trust keyring is shown by the reader's own name for them. Any other author is shown with a prefix long enough that matching it is infeasible (at least 128 bits), and marked as not in the keyring. No surface shows a short prefix alone as an author's identity.\n\nOutcome: No member can appear as another by matching a short fingerprint prefix (security).\n\nAcceptance:\n- An author in the reader's trust keyring is shown by the reader's own name for them. Any other author is shown with a prefix long enough that matching it is infeasible (at least 128 bits), and marked as not in the keyring. No surface shows a short prefix alone as an author's identity.\n\nValidation: A real-binary proof: an identity whose short prefix equals a trusted member's (constructed by grinding at the old length, or by substituting the display function's input) posts in a room. The TUI, the agent drain and `vox room read` each show it as not in the keyring and distinct from the trusted member. A mutation back to the short prefix goes red.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release.\n<!-- work-accountability:end -->\n","number":198,"title":"V210-24: No member can appear as another by matching a short fingerprint prefix (security)"},{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V29-16 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.9.md` at `e98f42aa281b24f5db444d8b40b8827a6acb244f` (`f792df05039cf3fabeaebefeb14ea7874a965bd3`)\nSource excerpts:\n> ### V29-16 — Shutting a node down releases its profile before it reports done\n> **Why.** `Shutdown` replies before cleanup, and something kept the store file open for milliseconds after the store was dropped.\n> **Acceptance.** When `Shutdown` reports done, the profile can be opened by another process.\n\nOutcome: Shutting a node down releases its profile before it reports done.\n\nAcceptance:\n- When `Shutdown` reports done, the profile can be opened by another process.\n\nValidation: Shut down and immediately reopen, repeated.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release (carried from v0.2.9).\n> - **V29-16 (#51):** the change (`9e4ebd4`) ships in v0.2.9. No shipped-binary reproduction exists, so whether the story is Done or Not planned is the decider's call, carried.\n<!-- work-accountability:end -->\n\n","number":51,"title":"V29-16: Shutting a node down releases its profile before it reports done"},{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V29-07 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.9.md` at `e98f42aa281b24f5db444d8b40b8827a6acb244f` (`f792df05039cf3fabeaebefeb14ea7874a965bd3`)\nSource excerpts:\n> ### V29-07 — A message over a relay is delivered\n> **Why.** A message over a relay was not delivered in 3 of 7 runs.\n> **Acceptance.** Messages over a relay are delivered.\n\nOutcome: A message over a relay is delivered.\n\nAcceptance:\n- Messages over a relay are delivered.\n\nValidation: A relayed real-binary run, repeated.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release (carried from v0.2.9).\n> - **V29-07 (#42), V29-14 (#49):** the improvements ship in v0.2.9. Their only evidence is in-process (NAT simulator), and a real-binary relayed run needs a Linux network-namespace harness. The proof is carried.\n<!-- work-accountability:end -->\n\n","number":42,"title":"V29-07: A message over a relay is delivered"},{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V29-26 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.9.md` at `7447dd2fcd0529b86c0c81aa4b73c920b005302e` (`a3481739e0dfa8a398cfa1168c4d5d55970c507a`)\nSource excerpts:\n> ### V29-26 — Path-MTU raising never makes a Linux node's packets smaller\n> **Acceptance.** On Linux and on macOS, a node's path MTU after a bulk transfer is at least what stock quinn reaches. The raised ceiling is used only when the socket's effective buffer can carry it.\n\nOutcome: Path-MTU raising never makes a Linux node's packets smaller.\n\nAcceptance:\n- On Linux and on macOS, a node's path MTU after a bulk transfer is at least what stock quinn reaches. The raised ceiling is used only when the socket's effective buffer can carry it.\n\nValidation: `transport_mtu_and_window_proof` passes in a Linux container (release.yml's gates job reproduced locally) and on macOS, with a mutation (a forced small buffer) showing the ceiling stays at quinn's default rather than collapsing.\nDelivery boundary: Included in the published vox v0.2.9 GitHub release.\n<!-- work-accountability:end -->\n","number":174,"title":"V29-26: Path-MTU raising never makes a Linux node's packets smaller"}]
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=1740, limit=355][0m
[0m✱ [0mGrep "max_concurrent_bidi|receive_window|stream_receive_window|send_window|MAX_PAYLOAD_LEN|MAX_STREAM_FRAME|OPEN_STREAM_PATIENCE"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src · 13 matches[0m
[0m→ [0mRead /Users/robert.lee/.config/opencode/skills/github-work-accountability/references/project-reconciliation.md[90m [limit=160][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/streams.rs[90m [offset=35, limit=125][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 diff --exit-code 8436100 -- crates/vox-core/src/node/actor.rs crates/vox-core/src/node/channel.rs crates/vox-core/src/log/dag.rs crates/vox-core/src/log/sync.rs crates/vox-core/src/node/net.rs crates/vox-core/src/transport/quic.rs crates/vox-core/src/transport/stream_transport.rs
(no output)
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=230, limit=65][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/feed.rs[90m [offset=175, limit=95][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs[90m [offset=25, limit=215][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/framing.rs[90m [limit=180][0m
[0m✱ [0mGrep "authors\.remove|admission\.(revoke|remove)|frozen|Revok|revoke"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src · 78 matches[0m
[0m
[0m$ [0mgh issue view 209 --repo robertelee78/vox --json number,title,state,projectItems
{"number":209,"projectItems":[],"state":"OPEN","title":"V210-34: Sync is scheduled like a switch, not a hub (ADR-025)"}
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=110, limit=48][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=2230, limit=115][0m
[0m✱ [0mGrep "MAX_ADMISSIONS_PER_SWEEP|fn admit_board_records"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node · 5 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=610, limit=85][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | nl -ba | sed -n '210,240p;2094,2140p;2680,2731p'
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
  2094	        Ok(out)
  2095	    }
  2096	
  2097	    /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
  2098	    /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
  2099	    ///
  2100	    /// # Errors
  2101	    /// The room is poisoned, a persist fails, or the session hard-fails.
  2102	    pub fn sync_over_room<T: Transport>(
  2103	        shared: &tokio::sync::Mutex<Self>,
  2104	        store: &Store,
  2105	        transport: &mut T,
  2106	        now_secs: u64,
  2107	    ) -> Result<SyncOutcome> {
  2108	        let epoch = {
  2109	            let ch = shared.blocking_lock();
  2110	            if ch.poisoned {
  2111	                return Err(Error::Profile(
  2112	                    "channel is poisoned after a failed persist; reopen it",
  2113	                ));
  2114	            }
  2115	            ch.epoch
  2116	        };
  2117	        let room = ChannelSessionRoom {
  2118	            shared,
  2119	            store,
  2120	            now_secs,
  2121	            epoch,
  2122	            out: std::cell::RefCell::new(SyncOutcome::default()),
  2123	            fatal: std::cell::RefCell::new(None),
  2124	        };
  2125	        let session = crate::log::sync::frontier_session_room(transport, &room);
  2126	        if let Some(e) = room.fatal.take() {
  2127	            return Err(e);
  2128	        }
  2129	        let mut out = room.out.into_inner();
  2130	        match session {
  2131	            Ok(n) => {
  2132	                out.applied = n;
  2133	                Ok(out)
  2134	            }
  2135	            Err(code) => Err(sync_failure(code)),
  2136	        }
  2137	    }
  2138	
  2139	    /// Accept a **sender-key distribution message** from `author` (ADR-006/ADR-007
  2140	    /// step 2/3): the sender key that member released to this identity, delivered
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
[0m✱ [0mGrep "STREAM_WINDOW|CONNECTION_WINDOW"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport · 6 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=175, limit=34][0m
Reviewed revision 3 at `141dc11`, all four prior reviews, and the specified code trees. No edits, builds, or tests were performed. Findings below are static analysis, not measured failures.

**Citation convention:** `180:` = `58fde36`; `202:` = `8436100`. Code paths are relative to `crates/vox-core/src/`. `ADR:` refers to the revision-3 document.

## BLOCKER

### B1. Both directions can stall while serving, before either starts receiving

Option C inherits a transport-level circular wait that the proposed proofs miss.

Both endpoints **serve their entire bounded batch before draining any received entries** (`180:log/sync.rs:886–914`). A batch may approach **64 MiB** (`180:log/sync.rs:491–508`), but the integrated transport has a **16 MiB stream receive window**, **32 MiB connection receive window**, and **32 MiB send window** (`202:transport/quic.rs:191–203,280–282`).

Give both endpoints distinct backlogs large enough to fill those buffers:

1. Both send entries.
2. Neither reads entries, because neither has finished serving.
3. Both eventually block in a frame write.
4. The 20-second write timeout fails the sessions before their receive/apply loops run.
5. Retrying can repeat the same exchange without durable progress.

Writes await `write_all`; timeout errors propagate out of the serve loop, and the session closes on error (`202:transport/framing.rs:15–23`; `202:transport/stream_transport.rs:88–101`; `180:log/sync.rs:860–865,891–914`).

This is **not a room-lock deadlock**, and C does not introduce it. It is an inherited reconciliation failure relevant to the stated release rule. P3’s one-direction backlog does not exercise it.

**Required:** specify concurrent send/drain or a bounded exchange protocol that guarantees progress under flow control. Add a real-binary **bilateral large-backlog** proof, including simultaneous sessions.

### B2. The resource and retry bounds trust the peer where they must be receiver-enforced

Three related holes remain:

- **Held streams have no specified local cap or deadline.** `held: VecDeque<HeldStream>` is not bounded by `INBOUND_PER_PORT` (ADR:150–151,232–239). The cited 20-second timeout executes inside the caller’s transport operations; it is not a receiver-side holding-queue timer (`202:transport/stream_transport.rs:88–115`). A malicious member need not run that timeout. QUIC’s connection-level limits exist, but are not the claimed two-attempt port bound (`202:transport/quic.rs:195–203`).
- **Holding can manufacture failures for correct peers.** Admission can wait longer than the opener’s HELLO read timeout. Existing serve/drain budgets are each 30 seconds, not an admission guarantee under 20 seconds (`180:log/sync.rs:95,886–901`). D4 therefore replaces some busy refusals with timeout/backoff rather than proving collision-free turnover.
- **Zero-progress truncation retries immediately forever.** A member can advertise a missing tail, send no requested entries, then FIN. D3 raises another request “at once”; D5 backs off zero progress only for `unadmitted`, not missing coverage (ADR:221–223,251–255). Every resulting outbound is “justified,” so P1’s justification assertion does not bound this amplification.

There is also a new allocation hazard: do not literally expand advertised ranges into a set of every `(author, seq)` position. HAVE decoding accepts a `u64` sequence, and WANT uses that remote maximum (`180:log/sync.rs:312–330,450–460`). A compact advertised range can therefore demand enormous receiver bookkeeping. The existing serving implementation explicitly avoids work proportional to range numbers (`180:log/sync.rs:478–539`).

**Required:** receiver-owned held-count/byte/deadline limits, cancellation/reset cleanup, peer/global admission accounting, compact interval coverage, and a no-progress policy covering incomplete receives. If “never refuse busy” remains absolute, specify an actual readiness/credit mechanism.

## MAJOR

### M1. Replacement and stale completion are specified as filtering, not resource lifecycle

“Old attempts become stale” plus “stale `SyncDone` changes nothing” does not specify what happens to:

- `out`, admitted inbound attempts, and held streams;
- global/per-peer permits;
- pending backoff timers;
- consent waiters;
- durable stores performed by an old worker.

If old `out` remains occupied, every future outbound can be blocked while its completion is forbidden to clear it. If replacement clears it immediately, the old worker may still run alongside its replacement. Define cancellation, retirement, and exactly-once permit release independently of whether its **result** may update the port.

This matters beyond crashes: the connection manager deliberately keeps displaced live connections usable and serves retired duplicates (`202:node/net.rs:829–855,874–898`). One `Port.conn` therefore needs an explicit policy for legitimate streams arriving on a non-primary connection.

Current room workers fence **epoch and poison state**, not connection incarnation (`202:node/channel.rs:2654–2666`; `180:node/anchor.rs:411–422`). Ignoring their eventual completion does not prevent their earlier application. D3’s forwarding wakeup must survive this distinction.

D2’s captured request generation correctly preserves requests arriving after admission. However, the design still needs explicit completion/error precedence, backoff reset/cancellation rules, and replacement cleanup.

### M2. D3’s classifications need policy and durability definitions

Matched unique positions address duplicate substitution, and the excluded-author skip addresses repeated permanent prefixes. They are implementable, but not directly available as the proposed six classes:

- `apply_entry` currently collapses missing resolver keys into `AuthenticatorInvalid`, and other rejections into wire codes (`180:log/sync.rs:602–620`).
- Frozen authors and ordinary non-admission both return `NotAdmitted`; the frozen predicate is separately available (`202:log/dag.rs:216–225,312–324`).
- **Consent revocation is not author eviction.** The shipped revocation rotates the sender key, appends revocation, and updates the delivery ledger; the resolver still uses the admitted-author map (`202:node/channel.rs:1806–1836,1936–1943`). Define what “revoked author” means before using it to suppress WANTs permanently.
- Persistence failure poisons the room, and subsequent syncs refuse it until reopen (`202:node/channel.rs:2048–2052,2100–2106`). Backoff alone cannot repair that state.

Define `stored`/`nP` at the durable boundary, retain successful-prefix information on errors, and distinguish retryable network/membership failures from a poisoned local store. Today a partial batch is absorbed before its error is returned, but the session API then returns only the error (`202:node/channel.rs:2694–2720,2117–2128`).

**What I could not break:** ordinary concurrent duplicate delivery does not establish double application or a room-lock deadlock. Application and absorption share one room lock; duplicate hashes are rejected; absorption uses the heads captured under that lock (`202:node/channel.rs:2694–2715,2002–2079`; `202:log/dag.rs:317–320`). For honest contiguous feeds, successful persistence, stable epoch, and matched coverage, I found no additional omission that neither receiver observes. A remote-apply acknowledgement is not required merely to make receiver-driven retry possible.

### M3. The proof table still cannot discriminate several named mutants

These are proof-design assessments, not execution results.

| Proof | Remaining problem |
|---|---|
| **P1** | “Every session started while its port needed one” rejects valid **inbound** sessions: the receiver can be locally clean while the sender has a new post. Apply that predicate to outbound admission, and attribute inbound justification to the remote opener. Overlap alone also does not prove that the restored busy check encountered the overlap; observe arrival/admission while the competing attempt was active. |
| **P2** | The base has neither a four-per-peer cap nor queued-port state. Its required “queued while four slots were in use” cannot establish base saturation. Observe the actual cap rejection/eligible obligation on each implementation. Later posts and reverse sessions can still rescue the skipped port; baseline receiving currently re-arms pushes (`180:node/actor.rs:3450–3453,4730–4740`). |
| **P3** | Does not cover bilateral backpressure, time-budget truncation, or zero-progress truncation. The byte case need not produce two truncated sessions: one bounded prefix followed by a complete suffix suffices. Concurrent sessions can also rescue the double mutant unless their contributions are observed and controlled. |
| **P4** | Observing `unadmitted` establishes the failure, not that **its retry request** caused recovery. A concurrent session, outstanding request, or another propagation path can make the named mutant green. |
| **P5** | Requires the tested entry’s identity, store generation/time, and actual transfer membership. S0b does not explicitly expose those. “Posts repeatedly” also permits later posts to rescue the completion-generation mutant. |
| **P6** | Inherits P1’s causal-overlap and log-retention issues. Historical counts are not a base measurement of this revised proof. |
| **P7** | An old-connection completion does **not** isolate token checking: the unchanged incarnation check still rejects it when only “tokens ignored” is mutated. Either test a superseded token on the same incarnation or name the whole stale-result guard as the mutant. Also distinguish worker termination from actor processing of completion. |
| **P8** | Reconnection itself raises a request, and Bob can initiate an inbound session. Either can recover without `BackoffExpired`. A bound below 30 seconds also does not exclude a periodic tick already due within that window. |
| **P9** | Needs sender-side served-entry identity and receiver-side protocol reason/non-storage evidence, absent from S0b’s listed fields. The extra entry must otherwise be valid and admissible, so another rejection cannot mask the coverage mutant. |
| **#202 replacement** | Plausible, but “anchor keeps no log” alone does not establish the named reason. `EpochMismatch` is disclosed only when `owed_a_reason` permits it; otherwise refusal is uninformative (`202:node/actor.rs:5265–5275,5306–5312`). Observe that authorization precondition and isolate the affected pair. |

Missing decisive binary scenarios remain: bounded inbound holding, hostile/no-progress sessions, partial durable application followed by forwarding despite failure, request consumption during Running, manual backoff override, epoch replacement, and sustained cross-peer fairness.

### M4. S0b cannot supply the advertised causal evidence

ADR:294–302 omits:

- request generation, captured request, consumed request, and `done_gen` at admission/completion;
- queue entry/dequeue, slot occupancy, skip reason, and scheduling cause;
- backoff entry/deadline/expiry and periodic-trigger timestamps;
- epoch and stale-result disposition;
- entry hashes and store generations/timestamps;
- served entries and explicit error reasons.

“Received by class” does not unambiguously specify per-entry identities.

A last-64-session log also cannot establish “every session” over 40 or 60 duplex rounds without continuous collection and detectable overflow. Forty rounds alone can produce 80 endpoint-local session records.

S0b needs an explicit event schema and loss-detectable collection contract. Its base instrumentation must include boundaries needed by S0c; declaring change-only fields absent cannot measure those preconditions.

## MINOR

### m1. D2 should preserve monotonic completion credit

The exact equality condition is now written, but the read/check/update must explicitly share the appropriate synchronization boundary. More importantly, concurrent completions must not execute unconditional assignments that lower `done_gen`:

- newer attempt credits generation 12;
- older attempt completes later with `gH = 10`;
- its fallback overwrites credit with 10.

Use epoch-scoped monotonic advancement. This creates redundant work, not a demonstrated lost update.

Ignoring inbound sessions in the outbound decision does **not by itself** imply an infinite honest-session loop: after finitely many stores/requests and old completions, fresh clean attempts can consume the remaining work. The actual unbounded retry case is B2’s no-progress rule.

### m2. D6 limits one stalled peer, not aggregate stall latency

Four stalled peers can still occupy all 16 outbound slots. Round-robin governs admission once capacity becomes available; it does not preempt occupied slots. Existing outbound permits span preparation and reconciliation (`180:node/actor.rs:5023–5032,5117–5142`).

State that limitation accurately and prove sustained service with both stalled and live peers. “The seventeenth stalled peer” disclaimer does not describe the waiting **live** peer case.

### m3. Tree accuracy and planned-versus-done wording

The corrected principal citations—skip, unconditional scheduling completion, “pushed means started,” `SyncOutcome`, and the running-marker wedge—match the indicated trees.

Two remaining misleading statements:

- **“At most two sessions”** (ADR:130) is not a bound on unfinished endpoint work when turnover permits two inbound attempts plus an outbound, with more held.
- Consent retries keyed by `(room,target,token)` are **planned work**, not supported by the cited baseline: current `SyncDone` selects pending consents by room, and their stored tuple has no token (`180:node/actor.rs:3373–3380,4356–4369`).

I found no wholesale claim that D1–D7 are implemented; the document expressly labels them proposed.

## NIT

Define whether “started,” “ended,” and “completed” mean stream opening, worker execution, or actor event processing, and define endpoint-local counter equations. Those distinctions affect P7 and log conservation checks.

### Round-2 finding disposition

“Resolved” below means resolved in the design, not built.

| Round-2 finding | Revision-3 disposition |
|---|---|
| **1. Turnover after sender completion** | **PARTIAL.** Busy refusal is removed, but holding has no safe admission deadline or complete resource bound. B2. |
| **2. Request/notify lifecycle** | **PARTIAL.** Notify disappears; request capture, manual override, and expiry wakeup are specified. Replacement cleanup and concurrent completion/backoff transitions remain incomplete. M1. |
| **3. Coverage and permanent-prefix progress** | **PARTIAL.** Unique position/head matching and exclusion skipping resolve the original holes. Bounded representation, no-progress pacing, and classification/durability semantics remain. B2/M2. |
| **4. Anchors, preparation, commands, capacity** | **PARTIAL.** C restores both ends’ outbound preparation and retains inbound adoption; command semantics are corrected. Consent attribution and capacity/lifecycle coverage remain incomplete. M1/m2/m3. |
| **5. Amplification** | **PARTIAL.** Notify-specific amplification disappears. Inbound holding and immediate zero-progress retries replace it with unbounded application-level obligations. B2. |
| **6. Proof validity** | **PARTIAL.** Preconditions and honest measurement labels are added, but observability and mutant isolation remain insufficient. M3/M4. |
| **7. Exact atomic D2 condition** | **PARTIAL.** Equality and epoch are explicit; atomic execution and monotonic credit need specification. m1. |
| **8. Wrong-tree citations** | **RESOLVED** for the previously enumerated citation errors. |
| **Nits** | **PARTIAL.** Reviewer disagreement is corrected; unfinished-session bounds and counter semantics remain ambiguous. |

*Accountability: managed work maps to `robertelee78/vox:RELEASE-HARDENING:V210-34`, issue #209. Tracker reconciliation remains pending under the read-only constraint; Project phase/health and a verified reconciliation receipt were not established.*

## VERDICT

**BLOCK**

The three changes I would most insist on:

1. **Make duplex reconciliation bounded and progress-making:** resolve bilateral send-before-read blockage, bound held streams locally, use compact coverage, and pace zero-progress retries.
2. **Specify the complete port transition lifecycle:** cancellation/retirement, permits, epochs/incarnations, monotonic completion credit, durable partial progress, backoff, and consent attribution.
3. **Rebuild S0b and the proofs together:** expose causal events, detect lost observations, isolate each mutant’s recovery path, and measure the actual base preconditions.
