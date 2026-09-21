
> build · glm-5.3

# Todos
[•] Read ADR-009-security-analysis.md
[ ] Read ADR-009-deniability-mode.md (design record)
[ ] Read deniable/ implementation (9 files)
[ ] Cross-check claims C1-C5 vs code and reductions
[ ] Check assumptions A1-A6 for sufficiency
[ ] Identify missing attacks in section 6
[ ] Assess section 7 honesty/completeness
[ ] Write verdict

→ Read docs/adr/ADR-009-security-analysis.md
→ Read docs/adr/ADR-009-deniability-mode.md
→ Read crates/vox-core/src/deniable/dgka.rs
→ Read crates/vox-core/src/deniable/epoch.rs
→ Read crates/vox-core/src/deniable/rounds.rs
→ Read crates/vox-core/src/deniable/share.rs
→ Read crates/vox-core/src/deniable/key.rs
→ Read crates/vox-core/src/deniable/rekey.rs
→ Read crates/vox-core/src/deniable/verifier.rs
→ Read crates/vox-core/src/deniable/esk_publication.rs
→ Read crates/vox-core/src/deniable/wire.rs
✱ Glob "crates/vox-core/**/*deniable*" 1 match
✱ Glob "crates/vox-core/tests/**/*.rs" 12 matches
Now let me look at the tests, the module root, and the log-entry seam to see how this is actually driven.
✱ Grep "recv_commit|recv_reveal|DgkaMember::start|begin_rekey|accept_with_deniable" in crates · 23 matches
→ Read crates/vox-core/src/deniable/tests.rs
→ Read crates/vox-core/src/deniable.rs
✱ Grep "EskPublication|ingest_verified|PublishedEsk" in crates/vox-core/src · 19 matches
✱ Grep "pub fn signing_input|DgkaSetup|EskPublication|0x000B|0x0010" in crates/vox-core/src/wire.rs · 55 matches
→ Read crates/vox-core/src/log/dag.rs [limit=120, offset=270]
The tests reveal important details. Let me check the remaining seams: the DAG acceptance path, the wire signing input, and esk-publication tests.
✱ Grep "EskPublication::build|PublishedEsk::ingest|esk_publication::tests|forge_after|forge-after" in . · 3 matches
→ Read crates/vox-core/src/log/entry.rs [limit=120, offset=200]

# Todos
[✓] Read ADR-009-security-analysis.md
[✓] Read ADR-009-deniability-mode.md (design record)
[✓] Read deniable/ implementation (9 files)
[✓] Cross-check claims C1-C5 vs code and reductions
[✓] Check assumptions A1-A6 for sufficiency
[✓] Identify missing attacks in section 6
[✓] Assess section 7 honesty/completeness
[✓] Write verdict

# Review of ADR-009-security-analysis.md

The document is unusually honest for a self-review (§5 and §8 are candid), and most of §2's description of the code is accurate. But it contains one false claim about what the code prevents, one claim whose judge model does all the work, and §7 overstates test coverage of the very mechanism the ADR exists for.

## 1. Claims C1–C5

**C1 (key secrecy) — the sketch has a real gap; §6's corresponding bullet is false as implemented.**
The sketch's premise is "the commitment round fixes every `z_i` before any is revealed" (analysis:76–77). The code enforces no such thing. `recv_commit` (dgka.rs:187–196) accepts a commit at any time, and `recv_reveal` (dgka.rs:237–249) only checks that *the revealer's own* commit was previously recorded. There is no state that rejects a commit arriving after any reveal of the epoch. A corrupt member (allowed by A6) can watch honest reveals hit the log, then compute its commit and reveal and post both; every honest `DgkaMember` accepts the pair, because the commit exists in its map. The test driver simply feeds rounds in the polite order (tests.rs:79–110), which proves nothing about enforcement. So §6's "Adaptive share choice. Prevented in setup by the commitment round (C1)" (analysis:124–125) is **overclaimed/false as implemented** — the commitment prevents a member *changing* its share after committing, not *committing late*. The DDH embedding sketch also silently assumes the simulator can program honest shares independent of adversary shares, which is exactly what late commitment breaks. Second, smaller issue: "against an outsider (no `x_i` for any honest `i`)" is ambiguous about corrupt insiders; the insider case (attacker knows its own `x_j`, must not learn honest–honest pair products) is the argument A6 actually requires and the sketch doesn't give it.

**C2 (agreement) — sound.** T over the canonical order (epoch.rs:369–385), `T_bind` over the exact `X_*` vector (dgka.rs:403–421), the `confirm.round2` equality check (dgka.rs:377–380), and the MAC under a key derived from those same inputs make the argument work, *given* A5's single consistent log. Correctly scoped in §7.4 for m=2.

**C3 (live origin auth) — correct at protocol level, two soft spots.** The `esk_i → i` binding story (σ_i over `(channelID, epoch, author_id, epk, z)`, epoch.rs:188–203) matches the code. But (a) in the *code*, the binding reaches the content verifier through `EpochVerifier::release` (verifier.rs:91–101), which verifies nothing — the verified path (`EpochContext::from_signed_reveals`, epoch.rs:278–313) exists but nothing forces its use; the analysis states this trust boundary for re-key (§7.1) and for `current_epoch` (§7.3) but not for the verifier itself. (b) "came from the party that ran round 3" should read "holder of `esk_i`": `esk_i` lives in memory for a whole epoch, and mid-epoch exfiltration (not member corruption, so not A6) defeats C3. Neither is discussed.

**C4 (repudiation) — correct only under the judge model it quietly chose.** The mechanism description is honest ("its strength is exactly the strength of 'the key is now public'", analysis:99–100). But the claim "no transferable proof survives ... *even given every long-term secret*" (analysis:17–20) is doing all the work. Under that all-secrets model the entire log — including every static-signed governance entry — is simulatable, so C4 is nearly vacuous. Under the realistic accuser-judge (log + published esks + the accuser's own keys, no one else's static keys), see §4 below: pre-publication signatures are datable via the log's own hash chain, and C4 fails for exactly the in-epoch content the protocol exists to protect. The analysis never states its judge model as an assumption or considers the alternative.

**C5 — correct.** Matches dgka.rs:107–138 and epoch.rs:188–203; publication of `esk` touches nothing σ_i covers.

## 2. Assumptions A1–A6

A1–A4 are adequate (nits: A3 mislabels commitment *binding* as a random-oracle property — it needs collision/preimage resistance; A1's DDH is stronger than needed given A3). **A5 is insufficient for the claims it must carry:**

- It does not state that **commits precede reveals in log order** — load-bearing for C1, unenforced in code (see above).
- It does not state **admission filtering**. `recv_reveal` (dgka.rs:220–260) accepts any reveal with a valid static signature; admission is enforced only at the DAG layer (dag.rs:343–346) and only if the driver feeds exclusively DAG-accepted entries to the state machine. Nothing in the deniable module or the analysis says so.
- It never says **who signs the `0x000B` envelope and what it binds**. For COMMIT and CONFIRM rounds the *body* carries no author signature (wire.rs:120–143); attribution and cross-epoch replay defense for those rounds rest entirely on the envelope, which is outside this module and outside this analysis.
- Unstated elsewhere: CSPRNG quality for `x_i`/`esk_i`/`n_i`; the C4 judge model (above).

A6 is fine and §7.2 is honest about its limit.

## 3. Document vs code

Accurate: commitment formula (rounds.rs:22–37), reveal signing input (epoch.rs:188–203), ordering by pubkey bytes (epoch.rs:251), BD combiner (share.rs:191–211 — I checked the n=3 algebra), m=2 ECDH path (share.rs:156–164), K/K_confirm derivations (key.rs:55–102), esk gate on both build and receive (esk_publication.rs:64–79, 165–181), codec arities and the fingerprint check (wire.rs:171–237, 198–202), exact-triple verifier keying (verifier.rs:146–153).

Mismatches and misses:

1. **"Adaptive share choice ... prevented in setup" (analysis:124) — the code does not do this** (dgka.rs:187–196 has no epoch/round ordering state). Worst single doc-vs-code discrepancy.
2. **§7.6 overstates coverage.** "The construction is exercised only against itself" implies everything is at least exercised. **`esk_publication` — the entire deniability mechanism, C4's basis — has zero tests anywhere in the workspace.** No test calls `EskPublication::build`, `PublishedEsk::ingest`, or `ingest_verified` (grep across /opt/vox finds only doc comments). Worse, esk_publication.rs:83–85 says `reconstruct()` is "Used by the forge-after-publication demonstration" — **that demonstration does not exist**. A phantom test is cited inside the normative code.
3. **Re-key cannot compose with the verifier, and neither doc notices.** rekey.rs:176–179 says `verify_rekey`'s fresh `MemberEpk` is "registered in the content verifier — ... picks up the fresh verifiers and retires the old" — but `EpochVerifier::release` (verifier.rs:91–101) **rejects a different epk for an already-released `(channel, epoch, author)` triple**. A same-epoch re-key (the design record's framing, ADR-009-deniability-mode.md:96–106, "K may be retained for the epoch") makes post-rekey content unverifiable for every existing member. The only re-key test sidesteps this by bumping the epoch number (tests.rs:429, 432), i.e., it tests a *different protocol* than the one the design describes. §7.1's blanket "no claim covers re-key" covers the cryptography but hides this interop contradiction.
4. Nits: §2's "X_i ... ignored by verifiers" for m=2 — it is checked (dgka.rs:377–380) and bound (dgka.rs:403–421), merely redundant; §2 references `K_confirm` without defining it (it's in key.rs:74–81 / the ADR impl notes).

## 4. The attack missing from §6

**Timing/ordering evidence against repudiation — the dating attack.** Content entries and the `esk-publication` entry live in the *same per-author hash chain* (entry.rs:225–247, entry_hash at 262–264; feed continuity enforced at dag.rs:377). The publication entry is static-signed by `i`; every content entry before it in `i`'s feed is pinned there by the chain — altering or inserting anything at seq < p collides with SHA-256 all the way into the authentic publication entry. So a judge holding the log (no static keys needed) can establish: *this epk_i signature was created before esk_i was published*, and pre-publication only `i` (or someone `i` gave the key to) could produce it. That is transferable proof of authorship for precisely the in-epoch messages C4 claims are repudiable. Related variant: any member can contemporaneously quote `epk_i`-signed content in an attributable governance entry — the design's own attributable plane (dag.rs:324–331) is the witness infrastructure. There *is* a defense — `i` can fabricate an alternative feed publishing `esk` earlier, since publication entries carry no cryptographic date and cross-feed order is unpinned — but whether a judge finds that plausible is exactly what the analysis must argue, and it doesn't mention any of it. Secondary omissions: the late-commit/rushing attack (§6 affirmatively claims it's prevented — worse than omission), unadmitted injection into the live DGKA, mid-epoch `esk` exfiltration.

## 5. Is §7 honest and complete?

Honest in tone — §5 (deniability is self-granted, non-publishers conspicuous, DoS kills repudiation) is genuinely good, and gaps 1–5 are real. Incomplete in fact: it hides (a) the untested `esk`-publication path and the phantom "forge-after-publication demonstration" behind §7.6's wording; (b) the `EpochVerifier::release` trust boundary; (c) the re-key/verifier composition conflict behind the "no claim covers re-key" blanket; (d) the judge-model choice that C4 rests on. Silence on (d) is the one that matters.

## 6. Safe to enable on the strength of this analysis?

**No.** Four reasons, in order: (1) the analysis's own §8 concedes it is unreviewed self-analysis of a property whose failure is silent, and I found concrete errors in it (§6 false as implemented; C4 model-dependent); (2) the deniability mechanism itself has never executed in a test anywhere in the workspace; (3) C1's central premise is unenforced in code, and every unstated load-bearing assumption (ordering, admission, verifier sourcing, `current_epoch`) lives in the driver layer — which **does not exist**: `DgkaMember` has no caller outside `tests.rs`; (4) ADR-009's own blocker (1) and the module's ship prerequisite (deniable.rs:60–67) say this document does not clear the bar it was written to clear, and the project mantra ("no false deferrals") binds. The core construction is not shown broken — the BD/DGKA work, C2/C5 are right, and the required fixes are enumerable — but this analysis cannot support a shipped enable.

## VERDICT

**REVISE** — fix the named issues first:

1. Enforce (or explicitly assume in A5 and enforce in the driver contract) global commit-before-reveal ordering; correct the C1 sketch and the §6 "adaptive share choice" bullet (dgka.rs:187–196).
2. Analyze the dating/ordering attack on C4 and state the judge model explicitly; rescope C4/§1 accordingly.
3. Test the `esk`-publication path (build/ingest/ingest_verified/forge-after-publication); delete or implement the phantom demonstration reference (esk_publication.rs:83); correct §7.6.
4. Resolve the re-key/`EpochVerifier` composition conflict (verifier.rs:91–101 vs rekey.rs:176–179) and pin the re-key epoch-numbering semantics against the design record.
5. Add the missing §7 trust boundaries: `EpochVerifier::release` is unverified; live-path admission is driver/DAG-only; envelope semantics for COMMIT/CONFIRM rounds.
6. Minor: C1 insider scope, "party that ran round 3" → "holder of esk_i", A3 binding label, §7.5 "helps C4" overstatement.
