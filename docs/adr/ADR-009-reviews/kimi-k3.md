
> build · kimi-k3

→ Read docs/adr/ADR-009-security-analysis.md
→ Read docs/adr/ADR-009-deniability-mode.md
→ Read crates/vox-core/src/deniable
I'll start by reading the security analysis and design record, then dive into the code.
→ Read crates/vox-core/src/deniable/dgka.rs
→ Read crates/vox-core/src/deniable/epoch.rs
Now let me read the implementation files.
→ Read crates/vox-core/src/deniable/rounds.rs
→ Read crates/vox-core/src/deniable/share.rs
→ Read crates/vox-core/src/deniable/key.rs
→ Read crates/vox-core/src/deniable/rekey.rs
→ Read crates/vox-core/src/deniable/verifier.rs
→ Read crates/vox-core/src/deniable/esk_publication.rs
→ Read crates/vox-core/src/deniable/wire.rs
→ Read crates/vox-core/src/deniable/tests.rs

$ ls /opt/vox/crates/vox-core/src/log/ /opt/vox/crates/vox-core/src/
/opt/vox/crates/vox-core/src/:
atrest
atrest.rs
cbor.rs
deniable
deniable.rs
error.rs
governance
governance.rs
group
group.rs
hash.rs
identity
identity.rs
join
join.rs
lib.rs
log
log.rs
nat
nat.rs
node
node.rs
pairwise
pairwise.rs
suite.rs
time.rs
transport
transport.rs
tunnel
tunnel.rs
wire.rs

/opt/vox/crates/vox-core/src/log/:
dag.rs
entry.rs
feed.rs
negentropy.rs
quota.rs
selfchannel.rs
sync.rs

✱ Grep "from_signed_reveals|from_signed_reveal" in crates/vox-core/src · 6 matches
Now let me examine the log layer the DGKA rides on, to check how entries chain and what the static-signed envelopes actually commit to.
→ Read crates/vox-core/src/log/entry.rs
✱ Grep "from_signed_reveals" in crates/vox-core · 1 match
→ Read crates/vox-core/src/log/feed.rs [limit=120]
✱ Grep "pub fn verify|pub fn sign|pub fn fingerprint|fn public_key" in crates/vox-core/src/identity · 15 matches
Now let me examine the feed/DAG structure and the composite signature implementation to confirm how chaining works.
→ Read crates/vox-core/src/identity/composite.rs [offset=80, limit=120]
✱ Grep "fn accept_with_deniable|fn accept\b|author_id == root|fingerprint\(\) != |admitted|is_admitted|fn admit" in crates/vox-core/src/log/dag.rs · 21 matches
→ Read crates/vox-core/src/log/dag.rs [offset=1, limit=130]
→ Read crates/vox-core/src/log/dag.rs [offset=255, limit=160]
→ Read crates/vox-core/src/log/feed.rs [limit=120, offset=120]
✱ Grep "DgkaMember::start|begin_rekey|EskPublication::build|ingest_verified" in crates · 11 matches
Let me verify the feed-linkage enforcement and check whether the DGKA driver exists anywhere outside tests.
✱ Grep "deniable|feature" in crates/vox-core/src/lib.rs · 100 matches

$ cargo test -p vox-core deniable 2>&1 | tail -25
Running tests/node_m17_serve_gate.rs (target/debug/deps/node_m17_serve_gate-2dd4c9d54408bf40)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s

     Running tests/node_m17_up_gate.rs (target/debug/deps/node_m17_up_gate-da74e7da296c958c)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s

     Running tests/node_m18_revocation_gate.rs (target/debug/deps/node_m18_revocation_gate-817afb9e1cf98f01)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s

     Running tests/watchdog_proof.rs (target/debug/deps/watchdog_proof-69709b5c4cc99d0a)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s

$ cargo test -p vox-core --lib deniable 2>&1 | tail -20
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running unittests src/lib.rs (target/debug/deps/vox_core-4a02ca29c14d2fb7)

running 8 tests
test deniable::tests::dgka_setup_envelope_is_attributable_static_signed ... ok
test deniable::tests::deniable_content_fork_raises_alarm_does_not_freeze ... ok
test deniable::tests::full_dgka_three_members_all_agree_and_confirm ... ok
test deniable::tests::forged_bind_with_wrong_transcript_rejected ... ok
test deniable::tests::deniable_content_accepted_by_dag_with_epoch_verifier ... ok
test deniable::tests::rekey_round_trips_through_the_dgka_setup_codec_and_every_member_agrees ... ok
test deniable::tests::governance_must_stay_attributable_in_deniable_channel ... ok
test deniable::tests::full_dgka_five_members_all_agree ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 89 filtered out; finished in 0.42s

✱ Grep "EskPublication|PublishedEsk" in crates/vox-core · 17 matches
→ Read crates/vox-core/src/deniable.rs
I've read the analysis, the design record, all nine implementation files, the log layer it rides on, and run the test suite (8/8 pass). Here is the review.

## 1. The claims C1–C5

**C1 (key secrecy) — plausible, but the sketch is not a reduction and its premise isn't enforced.** Two gaps:

- The sketch's premise — "the commitment round fixes every `z_i` before any is revealed" (line 76–77) — is not provided by the code or by A5. `DgkaMember::recv_reveal` (`dgka.rs:220`) requires only that *that author's* commit is stored; the state machine never learns the intended member set, so nothing can enforce "all commits complete before any reveal." A rushing adversary fixes its share *after* seeing honest reveals. For C1-as-stated (outsider secrecy) this happens to be harmless (the adversary still can't compute the cross-terms without CDH), but the stated argument is not what the code does.
- "A distinguisher for `K` yields a DDH distinguisher by embedding the challenge in an honest member's `z`" (line 79–80) is wrong as written for `m ≥ 3`. The ring exponent is `Σ x_k·x_{k+1}`; embedding one DDH challenge into a single share leaves the two adjacent cross-terms unknown. The actual Katz–Yung result is a hybrid over the ring. C1 is probably *true*; the sketch doesn't show it.

**C2 (agreement) — sound as stated, matches the code.** `T` commits to channel/epoch/member set/epks/shares (`epoch.rs:369-385`), `T_bind` commits to the exact `X_*` vector (`dgka.rs:403-421`), `verify_confirm` checks a peer's broadcast `X` against the map used to derive `K` (`dgka.rs:377-380`), and the MAC is over `T_bind` under `K_confirm` (`key.rs:89-102`). Split-view is detected, not silently divergent — as claimed. The m=2 vacuity is honestly flagged in §7.4. One caveat belongs to Q3 below: the "member set" being agreed is *whoever showed up with valid reveals*, not the consenting set.

**C3 (live origin authentication) — matches the code.** Bind signature by `esk_i` over `T_bind` (`dgka.rs:320`), verified against the revealed `epk` (`dgka.rs:383-386`), and `epk ↔ static identity` via the static `reveal_sig` over the domain-separated setup input (`dgka.rs:226-236`, `epoch.rs:186-203`), plus the codec-level fingerprint check (`wire.rs:198-202`). Fine, conditioned on the caller feeding the verifier `epk`s from the verified run — an API trust boundary the document flags for re-key (§7.1) but not for the main path.

**C4 (content repudiation after publication) — FALSE as stated.** This is the load-bearing claim of the whole mode ("no transferable proof survives that a particular member authored a particular message, even given every long-term secret", line 18–20), and the sketch commits a category error: it analyzes only the *content signature* and ignores the *log the content lives in*.

- Every entry sits in a single per-author hash chain; `prev_hash` and `lipmaa_backlink` are fields 3–4 of the **signed** canonical body (`entry.rs:225-247`), the signature covers them via `signing_input` (`entry.rs:249-254`), and the feed *enforces* the links (`feed.rs:228-236`, `dag.rs:373-377`). Feeds are keyed by author only — one chain per identity across all channels and epochs (`dag.rs:30`, `feed.rs:102-114`).
- The esk-publication itself is a root-signed envelope on that chain (`esk_publication.rs:27`: "the entry envelope is root-composite-signed by the publisher (M5 `Entry::build_signed`)"). So are the epoch-closing passphrase-rotation entry and all four `dgka-setup` rounds of the *next* epoch (ADR-009 line 35-37; modeled in `tests.rs:371-403`). A member who keeps participating *must* post those.
- Publication is only legal once the epoch is closed (`esk_publication.rs:69`), i.e. *after* the rotation entry exists. So by the time `esk_i` is publishable at all, the author's own static key has already signed entries whose hash links commit to every content skeleton of the epoch — including `payload_hash` (`entry.rs:202-203`).

The judge's transferable proof needs no forgery analysis at all: author's later root-signed entry → chain → content skeleton with `payload_hash H` → payload (the judge can be handed the per-sender content key, ADR-006). Single-writer chain semantics do the attribution. The forgeable authenticator is irrelevant to the judge — the protocol deniable-izes the one piece of evidence that didn't matter while leaving the decisive one statically signed. The only escape is to author content and then never post another root-signed entry — i.e., deniability for your final epoch only, at the cost of leaving the channel — and even then the code offers no path to publish `esk` without the publication entry itself chaining over the content (`Feed::validate_next` rejects a non-chained append). C4 as stated is not overclaimed; it is false in the deployed composition.

**C5 (participation non-deniability) — accurate**, and ironically the mechanism that makes C5 true is part of what kills C4.

## 2. Are A1–A6 sufficient?

No. What's load-bearing but unstated:

- **Round-phase synchronization.** A5 gives authenticated, orderable delivery of entries, but the log has *no cross-author total order* (`dag.rs:11-16`: "no cross-author parent field… across authors entries are concurrent"). "All commits before any reveal" is a synchrony assumption the log cannot supply and the state machine does not enforce. Unstated.
- **Member-set pinning.** C2/C3 silently assume the DGKA member set equals the governance-admitted consenting set. The constructor that would enforce it — `EpochContext::from_signed_reveals` (`epoch.rs:278-313`) — **has no callers anywhere in the workspace** (grep: definition only). The live path, `DgkaMember::epoch_context` (`dgka.rs:264-279`), builds the context from `EpochContext::new` over whoever revealed, with no admitted-set check. The safe constructor is dead code, and the analysis doesn't mention it.
- C4 would need an assumption of the form "no non-repudiable structure attests content before key publication" — which isn't an assumption you can add; it's *contradicted* by ADR-008 as built.

A1 conflating Gap-DH and DDH is sloppy but harmless. A2–A4 are fine for what they're asked to do.

## 3. Does the analysis match the code?

Mostly yes on formulas (commitment, reveal signing input, `X_i`, `T_bind`, confirm MAC, publication gate — all checked line by line and they match). The mismatches:

- **Missed: the esk-publication path has never executed.** `EskPublication::build` and `PublishedEsk::ingest_verified` have no callers and no tests anywhere in the workspace. The analysis made a point of reporting that *re-key* had never run (§7.1) and missed that **the deniability mechanism itself** — the entire basis of C4 and §5 — has never run. That is exactly the kind of thing a self-written analysis misses.
- **Missed: member-set pinning is dead code** (above).
- **Wrong, harmlessly:** §2 says for `m = 2` "`X_i` is the member's own share, ignored by verifiers" (line 49-50). Verifiers do not ignore it: `verify_confirm` equality-checks `confirm.round2` and `bind_transcript` binds the shares at `m=2` (`dgka.rs:294-296`, `dgka.rs:377-380`, `dgka.rs:400-402`). `rounds.rs:80-81` repeats the error. Safe direction, but it is a misdescription.
- **Doc-comment bugs in the code the analysis normatively cites:** `share.rs:121-122` claims `round2_value` "rejects a degenerate (identity) `X_i`" — it performs no such check (`share.rs:127-134`); only the final accumulator is identity-checked (`share.rs:208-210`). `epoch.rs:239-240` says the sort is "by ascending `author_id`"; the code sorts by `author_pubkey` bytes (`epoch.rs:251`) — code right per ADR, comment wrong.
- **Missed: round-1 commits are unauthenticated at the body level.** `recv_commit` keys on the body's `author_id` (`dgka.rs:187-196`); nothing binds a commit to the envelope's actual signer. A malicious member can squat a victim's `author_id` in the commit round; the victim's reveal then fails commit-binding and the epoch aborts. Detectable, but a cheap per-epoch DoS, and nowhere in the document.
- **Missed: re-key vs. verifier impedance.** Re-key mints a fresh `epk'`, but `EpochVerifier::release` rejects a *different* `epk` for an already-released `(channel, epoch, author)` triple (`verifier.rs:91-101`). The rekey test sidesteps this by using `EPOCH + 1` (`tests.rs:429-435`) — i.e., the code implements "mid-epoch re-key" as a *new epoch number*, contrary to ADR-009's "between passphrase-epochs" wording, and the analysis never reconciles this with the esk-publication epoch gate.

## 4. The attack missing from §6

§6 enumerates attacks on the DGKA rounds and stops there. The missing attack is the one that matters: **the judge attacks the log, not the authenticator** — the chain-attribution argument of §1 above. The adversary (a recipient turned witness) ignores the forgeable content signature entirely and presents the author's later root-signed entries plus the hash chain as transferable proof of authorship, constructed before the forgery window opens. Every mechanism in §6 defends the rounds; none defends the property the mode exists for. (Secondarily: commit-squatting DoS, above.)

## 5. Is §7 honest and complete?

Honest in tone, and its specific items (re-key, adaptive corruption, caller-supplied epoch gate, m=2, classical `K`, no test vectors, composability) are accurate as far as they go — §7.1 and §5 are genuinely better than one expects from a self-review. But it is not complete: it hides the chain-attribution falsity of C4, the dead member-set constructor, the never-executed publication path, and the round-synchronization gap. A "what we don't cover" section that omits the attack that defeats the headline claim is not dischargeable as coverage.

## 6. Safe to enable?

**No.** The document's purpose was to discharge the shipping blocker "formal analysis on file." Even if an internal analysis could clear that bar (dubious — the document itself says so, line 168-172), this one cannot, because its central claim C4 is *demonstrably false against its own normative source*. Enabling the mode on this analysis would ship a "deniable" feature whose logs transferably attribute content to authors after every epoch — worse than no deniability claim, because it promises users a property the system affirmatively does not have. The one mitigating fact is that nothing is wired up: every entry point (`DgkaMember::start`, `begin_rekey`, `EskPublication::build`, `ingest_verified`) is test-only today. The "enable" decision is the decision to build that driver, and it must not happen on the strength of this document. Fixing this is not a wording revision: it requires a design change (at minimum, getting deniable content out from under the statically-signed chain — separate non-attested feed, detached/off-log content, or the designated-verifier route ADR-009 already names) plus a new analysis of that design, plus pinning the member set in the live path, plus executing the publication path.

To be fair where due: the DGKA rounds themselves (commit/reveal/bind/confirm, ordering, codec, fork-alarm integration) are implemented carefully and C2, C3, C5 match the code. The failure is at the composition boundary the analysis never looked at.

## VERDICT

**BLOCK.** C4 — the property the mode exists to provide — is false in the implementation as composed with the ADR-008 log: root-signed entries (rotation, next-epoch `dgka-setup`, the esk-publication itself) hash-chain over all deniable content and give a judge transferable proof of authorship that precedes the forgery window (`entry.rs:225-254`, `feed.rs:228-236`, `esk_publication.rs:27,69`). The analysis never considers this. Compounding: the admitted-set-pinning constructor is dead code (`epoch.rs:278` vs `dgka.rs:264-279`), the publication mechanism has never executed, re-key is admittedly unhardened (§7.1), and round synchronization is assumed but nowhere enforced. Do not enable deniable mode on the strength of this analysis.
