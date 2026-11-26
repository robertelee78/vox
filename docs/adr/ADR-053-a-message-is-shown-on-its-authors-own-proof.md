# ADR-053: A Message Is Shown on Its Author's Own Proof

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-23) for v0.4.31 by the decider, in his words of that day on the
  design: "have gpt-6.1-sol review it -- then come to me with product questions if needed.
  Otherwise looks good to me." (ruling 5). That review (`design/proposal-review-sol.md`) accepted
  the design with nine mandatory corrections, C1 to C9, all carried here, with its build order.
  His answers to its product questions are rulings 7 and 8; question 3 is deferred until a
  measurement (ruling 9). This record writes down that acceptance; its text was not itself put to
  him. Nothing in it is built except what is named below as landed, accepted or built:
  implementation, acceptance and delivery are recorded on the source-bound issues, separately
  from decision status. *(Amended 2026-11-23, amendment 1: the head-mismatch ruling of gpt-6.1-sol (MP-7, MP-8a, MP-9; B-10 resolved), and the coordinating session's engineering decisions on the Order and on MP-9's transport, each marked where it applies. Amendment 2: the M0 ruling of gpt-6.1-sol, `design/step3-m0-ruling.md`, given after its review of the step-3 plan answered DO NOT BUILD (`design/step3-plan-review.md`): MP-1 to MP-5, the Terms, MP-13, MP-17, the Order and B-1/B-2, each marked where it applies. Amendment 3: the decider's ruling 10 with the forked-target ruling of gpt-6.1-sol, `design/forked-target/ruling.md` (MP-9a, MP-6, MP-8), and the moving-head ruling of gpt-6.1-sol, `design/moving-head/ruling.md` (MP-7's prefix serving P, MP-8a's head choice H, W not approved, MP-17), and the Order, each marked where it applies.)*
  *(Amended 2026-11-24, amendment 4: the decider's rulings 11 to 13 (the private-step gap stays in v0.4.31 and is named; v0.4.31 is the busy room, and MP-14 and MP-16 move to v0.4.32; the stack of sync fixes is not the fix); the acknowledgement ruling of gpt-6.1-sol, `design/busy-room/ack-ruling.md` (MP-4); the control-closure ruling of gpt-6.1-sol, `design/busy-room/control-closure-ruling.md` (MP-7); the return ruling of the reviewer of #1393, `mp/cut-disappear/ruling-n.md` (MP-11); what has landed (MP-6 and MP-11 in #1393, MP-10's boundaries in #1392, MP-15 in #1391 with ADR-052 RG-13 closed); and ADR-054, which is to replace the fetching machinery this record's Order assumed (MP-9, MP-12, MP-13, the Order). Each is marked where it applies; the text it amends stays as it was, beside the mark. The coordinator's draft of this amendment is `design/amendment-4-draft.md`.)*
- **Date**: 2026-11-23
- **Deciders**: Robert E. Lee
- **Tags**: sync, admission, governance, removal, fork detection, store, retention, compaction,
  KISS, release
- **Amends**: ADR-036 (H-2, H-4, the v2 signature-retention sentence), ADR-052 (RG-0, RG-5,
  RG-13); records against ADR-046 and ADR-047, both already superseded for v0.4.31 by ADR-052,
  which of their lines this decision overtakes. The exact lines are under "What this ADR
  supersedes and amends".
- **Amended by**: ADR-054 (fetching is one pull loop per connection), recorded here as amendment 4;
  and MP-5 and MP-12 by ADR-054's amendment 3 (2026-11-25), marked at each.
- **Related**: ADR-007 (G-29 to G-32), ADR-018, ADR-023, ADR-036, ADR-046, ADR-047, ADR-052
  (RG-1, RG-6, RG-13, RG-15)
- **Source**: in the release's evidence archive `/opt/vox-evidence/v0431/`: the decider's words in
  `exec/deviations.md` (sections "Answers of the owner on 2026-11-23 (night)", "(morning)" and
  "(later)");
  `design/proposal-review-sol.md` (the final review, the decider's gate; it wins wherever the
  sources differ); `design/proposal.md`; `design/m1-security.md` and `design/sync-sol-on-m1.md`
  (the two attacks on the smallest model); `design/sync-opus.md`, `design/sync-glm.md`,
  `design/sync-sol.md` (the three designs); `design/store-opus.md`; `rg-13/checkpoint/report.md`,
  `rg-13/running-growth/report.md`, `rg-13/follows/report.md`; `found-reds/burst-gap/small/`;
  `rg-5/measurements.md`. Code lines are in `/opt/vox-worktrees/sync-land` (main with #1384 and
  the parked sixteen-rule candidate), under `crates/vox-core/src/` unless they start with `docs/`
  or `vendor/`. The citations this record relies on were read again while writing it. Nothing
  was built or run for this ADR.

## What this ADR sets out to do, and the rulings it carries

**The goal.** In a busy room with a slow member and a newcomer, every member's messages are shown
both ways, with less machinery than today and with no loss of security or usability. The busy-room
journey of ADR-052 RG-1 decides it, in all sixteen directions, unchanged.

**The decider's rulings this ADR carries** (quoted words are his):

1. **The release waits for the busy room.** Asked whether v0.4.31 waits until the busy-room
   journey passes completely: "I think that's ideal no?" (2026-11-23, night). Earlier, by the
   question form: "Keep going until the busy room passes, then release everything together"
   (2026-11-22).
2. **A design fix, not more patches.** "also I've been wondering about our approach for a while --
   we keep finding really brittle state machines and making complex patches and timers etc ---
   when it feels like a design fix is more appropriate so we're less complex -- KISS is the goal
   as long as we don't ruin something in the usabiulity or security -- but Vox needs to actually
   work/be stable." (2026-11-23, night.) The coordinating session read this as: no further rules
   are stacked on the sync candidate and it does not land as it is (exec/deviations.md:110, ‘What
   follows (Main)’); this is the coordinator's reading, not a further quotation or separate ruling
   by the decider.
3. **Storage.** "I don't like that we're storing more than we need, storing the wrong way, or
   waiting until next vox start to try to compact .. compaction should ideally happen
   periodically while vox is running to reduct next start lag ... but we should also be smarter
   about what we store and how we store to need compaction to happen less too?" (2026-11-23,
   night.) Earlier, of compaction only at startup: "why are we only doing this at start up? Why
   are we letting files get run away sized while vox is running? Why aren't we better managing
   this so that start up isn't asked for bad choices like this?" (2026-11-22.)
4. **One Vox version per room.** Asked whether the design may assume every member of a room runs
   the same Vox version: "for now, yes." (2026-11-23, morning.)
5. **The design.** "have gpt-6.1-sol review it -- then come to me with product questions if
   needed. Otherwise looks good to me." (2026-11-23, morning.) The review is in; its product
   questions were put to him (rulings 7 to 9, and "The decider's answers" at the end).
6. **Expired signatures.** Asked whether expired messages may drop their signatures, he first
   asked back: "Would dropping signatures reduce what we need to store? What's the reasoning
   behind this ask?" The review's product question 1 is the refined form of that question; his
   answer to it is ruling 7.
7. **After a message's text expires, only what the chain needs stays** (the review's question 1,
   asked with three options). His first answer: "lol -- if the text is gone, wtf cares -- why are
   we still keeping it -- explain that part?" After the explanation (each member's messages form
   a signed chain; a node needs a small fingerprint of every earlier entry to check later messages
   and to catch a rewritten history; more is kept today only because of an old rule, ADR-036:371-373,
   and because backup recovery and paging read the old header's fields) he chose the option "keep
   only what the chain needs, and change recovery and paging so they need nothing more."
   So the storage rule is the leaf-only form (MP-16); the review's C7 and C8 are the conditions
   under which it may be switched on. Rooms set to keep messages for ever keep everything.
8. **A message shown and later proven not acceptable disappears** (the review's question 2): his
   answer, "disappears". It leaves the conversation so the room looks the same to every member;
   it never authorizes a control or a key release; nothing can recall what was already read
   (MP-11).
9. **The creator's signed summary for old busy rooms is not decided and was not asked** (the review's question 3): it is deferred until a newcomer joining a copy of the decider's real rooms
   has been measured after the redesign. It is not built unless measured to be needed; then the decider is asked, because it means trusting the creator's account of the past.
10. **A member that splits its own history must not escape its removal** (2026-11-23, evening, by the question form; ledger 73; `exec/deviations.md`, "Answer of the owner on 2026-11-23 (evening)"). The defect: a member running altered software signs two versions of its own history; after the creator removes it, members who saw the other version never apply the removal, keep releasing keys to it and stop receiving the creator's later posts, in every release since v0.4.6. "Offered: fix it in v0.4.31, the release waiting for it as well; or ship with the first half, name the rest in the notes and fix next."
    "His answer: **fix it in v0.4.31** (his standing rule; the form's value `fix_now`)." Carried by MP-9a, with MP-6 and MP-8 as amended. *(Amended 2026-11-23, amendment 3.)*
11. **The private-step gap stays in v0.4.31 and is named** (2026-11-23, late afternoon, by the question form; ledger 76; `exec/deviations.md`, "Answer of the owner on 2026-11-23 (late afternoon)"). The gap: a removed person running altered software writes a private Session step after being removed and gets it shown to a member who was offline when the removal happened and has not processed it yet; once that member processes the removal, further such steps are refused, but the one already taken stays. The reviewer found no small sound rule (`design/private-unaware/ruling.md`).
    "His answer: **leave it and say so in the release notes** (the form's value `keep_and_name`). This is his exception to "every known defect is fixed in the current release", for this one defect." Carried by MP-10 as amended. *(Added 2026-11-24, amendment 4.)*
12. **v0.4.31 is the busy room; disk-shrinking moves to v0.4.32** (2026-11-24, morning, in chat; `exec/deviations.md:168-183`). On disk space: "this shouldn't be complicated", and then, to the question whether v0.4.31 waits for the disk-shrinking work: "we can do the busy room as v0.4.31, then be better about disk space for v0.4.32". His other words that morning: "still the same 4 open tasks 🙁"; on the fixes that existed only as patches, "get that done"; "but dang -- we just need to actuallly land tasks better"; "we are prone to over engineered messes". The coordinating session's reading (`exec/deviations.md:180`), not a further quotation: MP-14 and MP-16 move to v0.4.32; what is already done for disk space ships in v0.4.31 (#1364, #1354, #1355, and MP-15, #1391); RG-13 closes when #1391 has merged, with MP-14 and MP-16 named on its issue as moved; for v0.4.32 the design is to be the simplest one that works, "to be re-decided then". Carried by MP-14, MP-15 and MP-16 as amended. *(Added 2026-11-24, amendment 4.)*
13. **The stack of sync fixes is not the fix** (2026-11-24, later the same morning; `exec/deviations.md:185-189`). "yeah -- we have made an ever more elaborate set of if then else conditional messes -- we took something that was a bad design, very brittle, and with our "fix" made it worse -- worse design, more brittle" … "instead of fixing the design". The coordinating session's reading (`exec/deviations.md:189`), not a further quotation: the stack is a prototype, "evidence of what the room needs, not what lands"; what lands is "a design fix of the fetching side of sync: one mechanism in place of the rules, fewer states than today, code deleted rather than added". That design is ADR-054; it is to replace the fetching machinery this record's Order assumed (MP-13, the Order); nothing of it has landed. *(Added 2026-11-24, amendment 4.)*

**Earlier rulings that stand:** KISS is the law (ADR-052 ruling 2, RG-0); the release bar is the
three journeys on the shipped assets (ADR-052 RG-15); a feature is proven on the real binary or a
real wire peer and the proof asserts what a person gets (ADR-018); a test whose red cannot say
whether the product or the test is broken does not belong in the repo, and an act that stops in
its own fixture some of the time is not committed (2026-11-22); all machines move to v0.4.31
together (ADR-052, row 18); existing stores are never reset (ADR-047 Q6); a key package's sealed
body is kept and served by members only (row 40); ADR-007's membership rules (strict-past
authority, removal wins, forward-only readmission with a fresh chain, the unseen-body cut,
ADR-007:299-300).

## Context: what a person met

**The busy room has never passed.** On builds 9 to 15 of 2026-11-23 the journey showed 7, 8, 7, 6,
7, **13** and 8 of 16 directions (`rg-5/measurements.md:143-153`). Build 14 reached 13 with sixteen
scheduling rules stacked on main (the candidate adds 1,655 lines and removes 226,
`sync-opus.md:95`). One of those rules, the pull-back hunk, is needed for 13 of 16 (8 without it,
build 15) and turns the smaller act `a_slow_member_delays_only_itself` red (`rg-6/sync-land/
report.md` §7.1): the rules interact. That is why the stack is parked, not landed
(`rg-5/measurements.md:155`).

**Three properties of today's design produced it** (`design/brief-sync.md:68-87`):
1. *Evidence about other members gates each member's messages.* Every entry cites a tip of every
   other author it has seen, and a reader needs a receipt for each cited parent and every cited
   author's control history complete through it before the entry settles
   (`node/channel/governance/sparse.rs:505-550,561-617`; `node/history_stream/admission.rs:875-944`).
   A slow member with a long feed hid everyone's messages from a newcomer.
2. *Work restarts whenever a head moves.* Parent receipts, an entry's own receipts and the control
   closure were re-fetched under dozens of successive heads (52 to 81 heads per stopped position,
   `sync-glm.md:50-51`), until rules pinned them.
3. *Joining costs the room's whole control history per member.* In a busy room nearly every post
   is preceded by an empty control entry (`node/channel/pending_text.rs:939-957`;
   `node/channel/local_history.rs:493-542`). Before the first message of one long-history member a
   newcomer made 1,928 signature verifications, advancing about 1.2 positions a second while that
   feed grew 1.9 a second (`sync-glm.md:51-54`). A reader keeping up needs about 95 exchanges a
   second (derived) and manages about 75 (measured; `sync-glm.md:48-50`).

**A member online through a burst kept only the newest 128 positions**, scattered: 146 to 362 of
1,000 held for good while `vox status` said healthy (`found-reds/burst-gap/small/report.md:9-12`).
The live window floored at the newest 128 and the server refused Live below its newest 128
(`node/history_stream/server.rs:816-823`).

**Disk.** Every message leaves about 23.3 KB for good on its author's node (measured) and about
33 KB on a reader's (derived; about 37 KB with #1384's proof pieces), mostly its 3,373-byte
signature stored three or four times (`rg-13/checkpoint/report.md:28-69`). With ten-second
retention and about five 60,000-byte posts a second, the file stepped from 2 MB to 268 MB in
doublings and never shrank while the daemon ran; clean shutdown gave back about 46 MiB and the
next start nothing (`rg-13/running-growth/report.md:62-70`). On main the store keeps about 26.5 KB
per expired post (`rg-13/follows/report.md:48`).

**What is already landed, accepted or built, and is not planned work here:**
- **#1384, merged** (`9fce87573`): a member keeps and serves the proof pieces owned by a receipt it
  holds, also after a restart (deviation 21). It narrows ADR-052 RG-13's "fetching writes no proof
  rows". Its control-range pieces stay cache-only (`node/history_stream/admission.rs:439-462`).
- **#1385, accepted by its reviewer, merging** (`found-reds/burst-gap/small/report.md`,
  `verdict.md`): a member that has a window for an author keeps owing itself every position above
  its start, and the server no longer refuses Live below its newest 128. Its act
  `a_follower_held_still_through_a_burst_holds_every_post` is red on main (128 of 300) and green on
  the change (300 of 300); by hand, 1,000 of 1,000 from four shells.
- **RG-13 A, built, not committed, proofs in progress** (`rg-13/follows/report.md`, worktree
  `/opt/vox-worktrees/store-follows`): the store file grows by a quarter, trims at ordinary
  commits, and a give-back pass runs after retention prunes and once after Ready; startup
  compaction before Ready is removed. Its crash, pause and mutant acts had not reported when this
  record was written.
- *(Amended 2026-11-24, amendment 4: landed since this record was accepted.)* **#1391, merged**
  2026-11-24 (merge commit `9cbb105b9`, `exec/review-audit.md:62`; its pull request text,
  `rg-13/follows/fix4/pr-body.md`): MP-15, the store file follows what it holds (the bullet above,
  "RG-13 A"). ADR-052 RG-13 is closed as completed with its work phase Release ready
  (`exec/awa/receipt-integrate-1327.json`), on an audit that found it closable at `9cbb105b9`, with
  MP-14 and MP-16 excluded by the decider's ruling, not treated as completed, and its limits listed
  for the issue and the release notes (`rg-13/close/requirement-audit.md:1-3`, "Limits to state on
  the issue and in the release notes"). **#1392, merged**: the reviewer accepted its merge commit
  `24b15f8b7` (`exec/review-audit.md:42`), which reached main as the pull request's merge
  `febb6459e` (`exec/found-reds.md:167` names both); MP-10's boundaries, each proven alone where
  stated under MP-10. **#1393, merged**
  2026-11-24 (merge commit `36c60c821`, `exec/review-audit.md:66`; its pull request text,
  `mp/cut-disappear/fix6/pr-body.md`): MP-6 and MP-11 together. Not landed when amendment 4 is
  written: MP-9, one commit on `36c60c821`, not pushed (`mp/fork/rebase3/report.md:3`); MP-9a, the
  second half of ledger 73, "not built here" (`mp/fork/rebase3/report.md:12`; ruling 10); M0 with
  its narrowed rule 4 (MP-4), built in a landing tree and not committed (`m0/land/report.md:3`);
  and ADR-054.

## Terms

- **Display receipt**, **cut receipt**: withdrawn by amendment 2 (the M0 ruling): no such types
  are built. A message passing MP-1 and MP-2 is a causal source (MP-3); a removal or readmission
  cut reads the message's checked context and own chain, never its `seen` (MP-3, MP-6). The
  accepted definitions stay in the git history. *(Amended 2026-11-23.)*
- **Causal source**: an entry fully validated by today's full validator
  (`ValidatedSparseEntry`, `node/channel/governance/sparse.rs:578-583`), which may be cited by a
  control entry and may carry authority. "Citable" means a causal source.
- **Own prefix**: the author's own entries before the message, authenticated under a signed head
  of that author; its **acknowledged controls** are the coordinates of the control context that
  prefix commits (`log/history.rs:796-819`).
- **Governing set** (the governing whitelist): the creator and every identity a creator
  certificate ever named, including one whose certificate expired or was revoked and one since
  removed (ADR-007 G-29, G-31).
- **Holder**: a member that verified evidence about another author and keeps it.
- **Busy-room journey, slow member, sixteen directions**: as ADR-052 RG-1.

## The decision

**The rule.** A message is shown on its author's own proof: its exact signed bindings, its place in
its author's own signed history, the governing changes its author had acknowledged, and the
reader's key; nothing about other members' chat history. A trust or membership change is applied
only on full proof of what it depends on, kept and served by those who verified it. A message
shown this way is never, by being shown, evidence for a trust or membership change. *(Amended 2026-11-23 by the M0 ruling: a message is a full causal source; a control may cite it only through its exact own-chain parent receipt, and its `seen` hints are never such evidence, MP-3.)*

Each requirement gives the rule, *Why*, and its *Proof*. **Proof form** (ADR-018 and the ruling of
2026-11-22 on tests): each proof is an act or journey on the real `vox` binary, or a real wire peer
where the act is adversarial, asserting what a person gets. Most security acts are green on main
because today's full gate refuses the attack; such an act is a guard: it MUST be green on main,
green on every step's binary (Order), and its named mutant (the weakened check) MUST turn it red.

### Showing a message

- **MP-1. A message is admitted for display on its author's own proof (C1).** A reader MUST
  "Authenticate the exact message/header/body bindings and the author's own preceding prefix; its
  signed context must preserve that prefix's acknowledged controls and name no own present/future
  position. Verify the governing exclusions and exact author/recipient readmission cuts needed for
  this message. A missing fact is pending, not an empty context or current-roster permission."
  The preserved state MUST be the exact *preceding* acknowledged state: a message whose context
  matches the post-context of some older own control is refused if a later own control
  acknowledged more. A message whose context object, prefix or needed cut is missing MUST wait as
  pending, for that author only; it MUST NOT be treated as having no frontier and MUST NOT become a
  store error. While a message waits, its new body MUST stay unrendered with its obligation kept,
  its sender MUST be named as waiting on membership evidence, and every other already-safe message
  stays usable (review §6: "Safety dictates that boundary"). Author eligibility is a membership
  decision, not "the author is currently present" (`node/channel/governance/view.rs:829-872`;
  `node/channel/governance/member_fold.rs:282-343`). Binding form (M0 ruling §7, rule 1): "**The reader MUST** retain current exact committed-head/inclusion/body/context bindings, own predecessor and exact preceding aggregate check, own-control full-source/effect readiness, every context coordinate's full validation and required effects, author/recipient cuts, consent/reset, termination, private classification and all generation/physical-egress fences. Only ordinary v2 Content's `seen` parent receipts, parent closure and domination requirements are removed; controls and legacy admission remain unchanged." What changes against the record as accepted: the message check keeps today's FULL validation of the author's own prefix and of every context coordinate, and effect readiness, not a governing projection; it drops only the proof about the members named in its `seen`. *(Amended 2026-11-23 by the M0 ruling of gpt-6.1-sol, `design/step3-m0-ruling.md`.)*
  - *Why*: today these bindings and own-prefix inheritance are checked
    (`node/channel/governance/sparse.rs:456-468,512-550`), and author eligibility and the
    recipient-body cut consume them (`node/channel/governance/view.rs:829-872,991-1046`). Without
    them a member removed and readmitted gets the messages it signed while removed accepted, and
    any member can plant a made-up coordinate (`m1-security.md` P1-A). The independent review's
    P1-A(b) ("one of its author's own validated control entries") is too weak: A can acknowledge
    removal R at control U, then sign M with a previously valid pre-R context (review §1, §2).
  - *Proof*: real wire peer acts. (a) *Acknowledged-then-regressed context*: A acknowledges a
    removal at its control U, then signs M with its pre-U context; no reader shows M. Mutant:
    accept any older own control's post-context. (b) *Readmission gap, author side*: a member
    removed and readmitted posts while removed with a context naming the creator at an impossibly
    high position; after readmission no reader shows those posts. Mutant: copy an unverified
    coordinate into the frontier. (c) *Missing context*: M's context object is withheld; M's
    author is named as waiting on membership evidence, every other author's messages are shown,
    the store reports no error.

- **MP-2. Governing effects the author acknowledged are applied before its text is newly shown or
  its package used (C2).** A reader MUST, "Before newly displaying text or using a package, apply
  the governing changes exposed by the authenticated own-prefix/context through their required
  coordinates, including transitive relevant controls. Preserve the current local
  withdrawal/removal-generation and physical key-send fences. Never read post-removal room content
  while continuing to release replies/keys under the exposed pre-removal state." This MUST NOT be
  weakened to consulting a last-good display view. As amended (M0 ruling §7, "Amendment to MP-1 and MP-2"): "For ordinary v2 Content, retain today's full author-own-prefix and exact context-coordinate source checks and required effect readiness, omitting only receipts/closure/domination for its non-authority `seen` hints; missing required facts remain pending for the affected sender. Before newly displaying text or using a package, apply all required controls exposed by that authenticated own-prefix/context, not merely a governing projection, preserving current author/recipient cuts, withdrawal/removal-generation and physical key-send fences. An unverified Content hint is not an acknowledgement of its referent's governing state." *(Amended 2026-11-23 by the M0 ruling.)*
  - *Why*: a reader behind on governance (ordinary lag, a returning member, a relay that withholds
    the creator's newest) would otherwise read the room after a removal while still sealing its
    replies to the removed member (`m1-security.md` P1-B; `sync-sol-on-m1.md` §1, "a direct
    counterexample"). Today the received-effect path waits for each signed control's effects and
    checked governance (`node/channel/pending_received.rs:114-148,197-212`); the egress token and
    the transactional fences stay (`node/channel/governance/channel.rs:691-700`;
    `node/channel/pending_text.rs:1172-1182`; `node/channel/own_writer_gate.rs:137-151,196-219`).
  - *Proof*: *the informative-removal race*. The creator removes A at R; A acknowledges R and posts
    M; reader N holds A's sender key and a pre-R view, and a relay serves N every feed except the
    creator's newest. N does not show M, N's status names A as waiting on membership evidence, N
    shows every other member's messages, and N releases no reply and no key to A, until N has
    applied R; after N applies R, M stays unshown (it lies outside R's cut) and N's key has
    rotated. Mutant: show M against N's last-good view.

- **MP-3. A message is a full causal source; its `seen` references are ordering hints only (C3).**
  "Ordinary v2 Content remains a causal source under the existing source publication and stored
  meanings after full exact context/own-prefix/control-source validation and required effects; its
  signed `seen` references are nonblocking ordering hints only, never control ancestry, cut, key,
  Session or required-ancestor evidence. A later control may cite that Content only through its
  exact committed-branch parent receipt and independently authenticated prefix frontier, with
  today's full control closure and domination. No distinct display/cut admission type or display-only stored meaning is introduced by this step; already-valid sources retain their meaning."
  Binding form (M0 ruling §7, rules 2 and 3): "**Every authority, membership, cut, key, private-access and required-ancestor consumer MUST** ignore Content `seen` as proof or independently verify its exact needed fact. In particular `contains_cut` MUST bypass its entire Content `seen` loop, and raw hint-graph ancestry/referenced/display-order state MUST NOT become an authority predicate. Ordering MAY use held hints without fetching or gating on them." "**A Content source MUST** publish and settle through the existing single strong token/source/effect paths only after rule 1; authoring MUST join settled tips' authenticated own-chain prefix frontiers, never their Content hint closures. Controls' direct parent receipts/domination and MP-6's exact target observation MUST remain enforced."
  *(Amended 2026-11-23 by the M0 ruling of gpt-6.1-sol, `design/step3-m0-ruling.md` §7, "Amendment replacing MP-3". It withdraws the accepted text, which made a shown message a separate kind of entry ("A display receipt cannot construct `ValidatedSparseEntry` … A separate cut receipt supplies only the exact eligibility facts it proves"; "The three meanings MUST be distinct tokens and distinct stored meanings"), and amendment 1's note that those types are the first change of Order step 3: no such types are built. The earlier text stays in the git history.)*
  - *Why*: the accepted text's plan for separate display and cut receipts was reviewed DO NOT
    BUILD: a display-only stored state needs a cut-only reader, source-versus-display dispatch in
    observe, replay, refill and live progress, and a migration (`design/step3-plan-review.md`).
    Keeping Content a full source keeps every existing stored meaning. A signed-format leaf's
    frontier is its pre-context, never its `seen`, so an unverified hint cannot reach a later
    control through it (M0 ruling §1, §2, §4); the recipient cut was the one surviving shortcut.
  - *Proof* (M0 ruling §5): (a) *the poisoned hint*: a hostile member signs an otherwise fully valid M with a made-up or wrong-branch `seen`; M is shown; an honest creator then removes another member and the creator's later controls validate, and the creator's context contains no invented hint coordinate. Mutant: join Content hints into source/authoring Frontiers.
    (b) A control citing M validates M's exact own-chain prefix and cannot gain M's hinted other branch.
    (c) *The recipient-cut forgery*, separately at provider send and at recipient render, covering all three old positive alternatives of `contains_cut` (a raw parent hash equal to the cut, a later unforked parent position of its author, a parent's causal containment): a body signed on a valid pre-readmission context, with the readmitted recipient's covering readmission named only in `seen`, is neither served to nor rendered by that recipient. Mutant: restore Content's `seen` cut shortcut; the real binary then discloses a body it withholds. If `Dag::happened_before` is kept as a hint-ancestry API, its boundary guard is added too.

- **MP-4. A writer advances its signed context only for real control and cut changes.** A message
  MUST carry its author's preceding context plus the required governance ancestors (the room cut,
  ADR-007:300); a writer MUST NOT write an artificial control entry before each post merely to
  absorb other authors' tips. A writer MUST still advance its context, by a control entry before
  the message, whenever a genuine control or cut it has applied changes (ADR-036:90-93). Binding form (M0 ruling §7, rule 4): "**Both writer paths MUST** advance before Content for every applied Governance/StepPolicy coordinate and required ancestor absent from the own committed frontier, independently of the sixteen hint slots; own real controls already advance it. They MUST NOT insert a carrier solely to absorb other authors' Content or empty ContextUpdates. Content MUST then sign the exact own aggregate and keep bounded ordering hints." *(Amended 2026-11-23 by the M0 ruling.)*
  *(Amended 2026-11-24, amendment 4, by the acknowledgement ruling of gpt-6.1-sol, `design/busy-room/ack-ruling.md`, which narrows M0 rule 4. Asked after a count showed 186 of about 210 acknowledgement triggers in an eight-member room were other members' consent grants (ack-ruling.md:3; `design/amendment-4-draft.md:21`, from `mp/sync-stack/c15/controls.md`). Nothing was built or run for the ruling. The rule 4 text above stays as written for every other trigger.)* In plain words: before a post, a writer may write a context entry recording the governance changes it has applied, its *acknowledgement*; a reader then resolves those before showing the writer's post (ack-ruling.md:13). The rule, as ruled: "**Both writer paths MUST acknowledge every currently required Governance/StepPolicy change and required ancestor, except another author's validated epoch-0 ConsentGrant. Own controls, all existing prefix coordinates and all reader source/effect checks remain unchanged. Other epochs and unclassified governance variants retain the current conservative trigger.**" (ack-ruling.md:29.) The writer MUST "Filter during that backwards scan, before selecting and breaking—not after selecting the highest position. If the latest entry is an excluded grant, continue searching for an earlier unacknowledged removal, revocation or reset. Otherwise a later grant would mask precisely the change that must be acknowledged." (ack-ruling.md:33.) The same predicate MUST serve the Content trigger and the ContextUpdate construction (ack-ruling.md:35). Everything else still triggers: removal and readmission, admin certificates and revocations, StepPolicy, retention and lifecycle, Presence, rename and anchors (ack-ruling.md:11-23). No reader check changes and no ConsentGrant is skipped from validation; an unavailable required prefix still defers acknowledgement and never silently disappears (ack-ruling.md:45, :53). Soundness rests on *non-interference*: a grant between other members, by A toward X or toward B, cannot change any decision about B's post, since a reader shows B's post by consent toward B and B's recipients use consent toward B; it does not rest on a reader proving what the writer applied, which no rule gives, before or after (ack-ruling.md:20-21, :47-49; `design/step3-m0-ruling.md:33-35`). Built with M0 in a landing tree whose product patch is the narrowed candidate (`m0/land/report.md:7`); not committed when this amendment is written (`m0/land/report.md:3`). Runs there, once each (`m0/land/report.md:16`): the grants act `G-1` GREEN (eight posts with no advance; a revocation and a reset under later grants each advanced); RED, each engaged: `G-newest-only-1` (a filter of the newest row only, on the revocation case), `G-reset-newest-only-1` (the same, on the reset case) and `G-no-governance-1` (no Governance trigger). The lagging-reader arm (the ruling's step 3) is compiled and not run, because the knob it needs is not on main (`m0/land/report.md:23`, :28). The rule against a post whose context goes back behind its acknowledgement, the ruling's third mutant, rests on review: its act was taken out of the proof (`m0/land/report.md:31`).
  - *Why*: today `authored_context` joins every other author's settled tip
    (`node/channel/local_history.rs:493-542`), so in a busy room `append_text` writes a
    `ContextUpdate` before nearly every post (`node/channel/pending_text.rs:939-957`): two signed
    entries per post, 21 % of a heavy author's entries (ADR-046:475). Skipping a genuine advance
    would let an old-rule reader path refuse legitimate messages and would move the removal cut
    (review §3).
  - *Proof*: in the busy-room journey each author's feed grows about one entry per post, read from
    the stores. ADR-007's removed-member act (ADR-007:410) stays green. Mutant: write the
    per-post carrier again (feed grows two per post). Both writer routes (`PendingText::append_text` and `local_history::authored_kind`'s own ContextUpdate branch) and an upgrade's first post: Content signs its unchanged own aggregate after any required real advance and absorbs no other author's empty ContextUpdate (M0 ruling §4, §5). *(Amended 2026-11-23.)*
    *(Amended 2026-11-24, amendment 4: the "Required real-binary act" of the acknowledgement ruling, ack-ruling.md:55-62. It is to establish:)* (1) in a stable room, with many grants by A toward X, A toward B among them, while B keeps posting: no ContextUpdate is generated solely for those grants, and B's recipient set and readability are unchanged; (2) when the creator removes X, then writes a later ConsentGrant on that same creator feed before B posts: B's next post exposes the removal despite the later excluded grant; (3) when lagging N is given B's post and key without the removal evidence: N does not show that post or continue key or reply release to X through the exposed old state, and supplying the evidence applies the removal with its cut and rotation; (4) the masking case repeated with reset and revocation, with acknowledged-then-regressed-context rejection kept. Mutants: filter only the newest row and stop searching; ignore all Governance triggers; permit regression behind B's acknowledged prefix.

- **MP-5. `seen` stays, as nonblocking display hints outside authority.** A message SHOULD name
  recent tips in its signed `seen` field (at most sixteen, `log/entry.rs:65-67`). A reader MUST use
  them only for display order: a hint MUST NOT need a receipt, MUST NOT gate text, MUST NOT be
  fetched for admission, and MUST NOT raise or poison a control frontier. The display clock's
  current behaviour (parents from `seen`, context and own predecessor; claimed time clamped to a
  parent-derived bound) MUST be preserved (`node/channel/entry_store/dag_facts.rs:524-557,603-678`). The field keeps its sixteen-slot bound and canonical projection and order checks; a required governing or cut advance never depends on one of those slots (MP-4), and a seventeenth unknown author is not a gate (M0 ruling §4, rule 4: "keep bounded ordering hints"). *(Amended 2026-11-23 by the M0 ruling.)*
  - *Why*: without fresh parents a message's clock is capped at its own previous entry plus ten
    minutes, so a member who posts after a pause is shown in the past and a reply can sort before
    its question (`m1-security.md` P1-C). "No reordering … unchanged" is true only if this is kept
    (review §1).
  - *Proof*: two members on skewed clocks; one posts after a pause of more than ten minutes and the
    other replies at once; every member shows the question before the reply. A message whose hints
    name an unknown tip is shown at once. Mutant: drop `seen` from messages. A room with more than sixteen authors, unknown hints nonblocking (M0 ruling §5). *(Amended 2026-11-23.)*
  *(Amended 2026-11-25 by ADR-054 amendment 3, PL-26, on the follow-up of the display-order ruling
  of gpt-6.1-sol, `design/adopt/ruling-order.md` "Follow-up: ADR-053 MP-5": "Amended, not left
  standing and not wholly superseded", as its second ruling corrects that follow-up,
  `design/adopt/ruling-order-2.md` §5. The heading and normative paragraph above are replaced by:)*
  "**MP-5. `seen` stays, as nonblocking references outside ordinary Content authority.** A message
  SHOULD name recent published tips in its signed `seen` field, retaining the sixteen-slot bound
  and canonical projection/order checks; for ordinary v2 Content, these hints MUST NOT require
  receipts, gate text, be fetched for admission, or supply authority, membership, cut, key,
  private-access or required-ancestor evidence."
  In place of the follow-up's sentence on the display key, the second ruling's two sentences:
  "At an entry’s first admitted header publication, the node MUST persist `(D, entry_hash)`, where
  `B = min(signed claimed_ms, original local first_seen_ms.saturating_add(600000))` and `D = B` if
  no signed `seen` reference names an entry already held and committed/published in the
  pre-publication snapshot, otherwise `D = max(B, greatest such entry’s fixed display
  time.saturating_add(1))`. The key MUST remain unchanged through later admissions, refill,
  withdrawal/restoration and reopen; absent or receipt-only references contribute nothing and MUST
  NOT be fetched or awaited for placement, and display keys MUST NOT confer authority or replace
  existing causal/effect clocks."
  Its other boundaries are kept: "`seen` remains an input, when held, to the separate existing
  causal-clock computation with its computed-parent-derived cap, never evidence authorizing a
  control frontier. Required governing/cut advances remain independent of ordinary Content's hint
  slots as specified by MP-4, and control entries' checked parent receipts, closure and
  domination—including MP-6's reserved exact target observation—remain unchanged; an unknown
  seventeenth author MUST NOT gate Content."
  There is no absolute ten-minute ceiling on a display key: each link of a chain of named,
  already-published entries adds at most one millisecond (`ruling-order-2.md` §2).
  *Why*, replaced: "Display stability no longer depends on receiving hinted parents; their later
  arrival may update the separate causal clock but cannot move a displayed row."
  *Proof*, replaced: "Use the ruling's newcomer reading/paging through an old busy room during
  catch-up, including unknown hints: safe Content remains readable, no shown pair reverses, and
  history arrival causes no refresh/retry." And, by the second ruling: "On a computer where the
  named question was already published before the answer's first publication, the answer is
  placed after that question, even if the answer's signed clock is an hour behind"; the answer
  must name the question in `seen`. The "ignore `seen` in display placement" mutant returns for
  this conditional proof: it must fail on the staged screens. It does not restore an all-member
  eventual-topological-order claim.
  The former universal skewed-clock question-before-reply requirement stays withdrawn, narrowed to
  the conditional proof above; one identical or causal display order for every member stays
  withdrawn. This does not waive the separate M0/MP-6 security proofs.

- **MP-6. A removal cuts its target at the target's latest tip the remover holds, by a narrow
  branch-aware cut (C4).** "The removal explicitly reserves one of the sixteen signed `seen` slots
  for the target's latest authenticated held tip. Use its exact branch-bound position/hash only in
  the content-membership observation-cut test, including retained exclusionary removals on forks.
  Do not raise general authority Frontiers from display hints." The cut MUST keep (author,
  position, hash and accepted branch), never a bare `max(seq)`; known-fork rejection, inclusion and
  consistency stay enforced. That tip MUST pass the exact receipt and branch checks of a causal
  source; being displayable MUST NOT satisfy them. "Earlier messages stay" means messages in the
  remover's witnessed accepted prefix, not every message that came earlier in wall time. *(Amended 2026-11-23, amendment 3, by the forked-target ruling of gpt-6.1-sol, `design/forked-target/ruling.md` rule 7, for the decider's ruling 10; the cut is by branch, not by position:)* "A removal's witnessed-message exception MUST mean exact authenticated membership in the prefix W named by the remover's signed target reference, intersected with the messages otherwise eligible on this reader; it MUST NOT mean all local messages with sequence at most p, nor automatically the whole local branch or only a guessed shared prefix." "Equal prefix descriptors under the two roots, or independently verified exact ancestry, may establish shared history; absence of that proof is pending for the affected eligibility, not a false ancestry result." Where the reference names a branch other than the one this reader accepted, it is looked up through the retained exact fork-parent witness (MP-9a).
  *(Amended 2026-11-24, amendment 4:)* MP-6 landed together with MP-11 in #1393 (merged 2026-11-24, merge commit `36c60c821`; `exec/review-audit.md:66`). A consequence, by the coordinating session's engineering decision of 2026-11-24 (`exec/deviations.md:193`), which follows the decider's ruling that such messages disappear ("disappears", ruling 8; `exec/deviations.md:127`): a message a member posted just before it was removed, which the member who removed it had not received, is gone from the room for everyone, its author included, when that member is readmitted. The decision was told to him the same day as one he can overrule, and he did not (`exec/deviations.md:193`); his own words on the author's copy are not recorded. The behaviour is as #1393's pull request describes it, from an observation of one run and not an assertion of an act; that text gives the reason: "Nobody can tell such a message from one written after the removal, and a post that only its author still sees would mislead her" (`mp/cut-disappear/fix6/pr-body.md:15-19`). The release notes draft says it (`release/notes-draft.md:82`).
  - *Why*: without per-post control entries, a cut at the target's last control could fall weeks
    back and hide its legitimate earlier messages (ADR-007 G-32; `m1-security.md` P2-D). The
    generic tip picker can discard an author (`node/channel/local_history.rs:493-527`). The message
    test reads the remover's past (`node/channel/governance/member_fold.rs:330-343`); fork ancestry
    cannot be reduced to an integer (`node/channel/governance/facts.rs:698-755`). Raising the
    general Frontiers instead would create branch-source obligations after a creator fork
    (`node/channel/governance/facts.rs:1210-1249`) and would not reach a removal on a fork branch,
    whose frontier comes from its saved context alone (:1421-1485). This replaces the proposal's
    and `sync-opus.md`'s "a control entry's checked `seen` tips also raise its frontier".
  - *Proof*: (a) in a busy room the creator removes a member while it posts: every reader keeps
    its posts up to the reserved tip and refuses its later ones; its partition-concurrent post,
    replayed after reconnection, is refused (ADR-007:410). Mutant: drop the reserved slot.
    (b) *Fork below the cut*: the removed member forks its own feed below the cut and serves a
    different entry at a witnessed position; no reader shows it, and the fork is recorded. Mutant:
    compare positions only. (c) *The forked target*: MP-9a's act and its positions-only cut mutant. *(Amended 2026-11-23, amendment 3.)*

- **MP-7. Control evidence that standing, keys or later controls depend on is kept durably and
  served (C5).** "Before publishing/adopting a control on which standing, keys or future controls
  depend, durably own its complete verification closure, including necessary non-governing
  dependencies, exact chosen roots, contexts, openings and historical links. Another holder can
  independently verify it after restart; a newer announcement never retargets that obligation.
  Reclaim only after its last owner is gone." The governing set MUST include "every
  creator-certified issuer, even if its certificate is expired/revoked or its member removed".
  Non-governing per-sender controls (consent and revocation, presence and reset, key packages,
  termination, Session floors and support) MUST remain authenticated per sender and namespace; they
  are not powers of the governing whitelist, and a sender whose own such controls are missing
  delays only itself. A newcomer's bootstrap MUST close the governing feeds and obtain each
  sender's own relevant control state and packages, with a pending status per sender rather than a
  barrier across all senders.
  The holder MUST persist the entire verified control-serving trace and its complete semantic verification closure under their exact original heads, atomically with the coverage/source
  owners, and retain the signed heads, contexts and verified consistency links those owners
  require across restart. "A provider may reconstruct another exact prefix for serving from that owned authenticated material; doing so neither rebinds the original owner nor creates permanent ownership of every requested prefix. Do not eagerly store every possible head or prefix."
  *(Amended 2026-11-23, amendment 3, by the moving-head ruling §3, which keeps head-mismatch rule 4 with this addition and replaces rule 5's exclusive commit-link condition:)*
  "The holder MUST serve under an exact requested prefix target only from independently authenticated material on its own accepted branch, either using its retained verified links or by reconstructing [1,n] beneath an independently committed source H with |H|>=n and checking equality of the complete requested Descriptor. Identical aligned nodes may be reused; other nodes are reconstructed. The requested head need never have been observed or committed here. The asker independently verifies under its own signed anchor; serving never changes canonical acceptance, source/effect readiness or evidence ownership."
  This makes a holder that skipped head n useful once it has accepted a larger H; it does not let a
  holder at h1 prove a genuinely unavailable suffix to an asker at a larger h2 (moving-head ruling
  §3). *(Rules 4 and 5 first: 2026-11-23 by the head-mismatch ruling of gpt-6.1-sol,
  `design/head-mismatch/ruling.md`; amended the same day by `design/moving-head/ruling.md`.)*
  *Serving any prefix a holder holds: P.* *(Added 2026-11-23, amendment 3, by the moving-head
  ruling of gpt-6.1-sol, `design/moving-head/ruling.md` §2.)*
  1. "An exact-head-dependent request MUST identify the immutable requested head and carry enough
     fixed-size target metadata to resolve it without the provider having stored that head: its
     TreeBinding, tail epoch and complete Descriptor, whose leaves field is n, with canonical
     head-body hashing checked against the requested head ID."
  2. "The holder MUST choose and pin one independently committed, authenticated source head H of
     the same room/scope/author with |H|>=n, reconstruct the exact canonical prefix [1,n] only from
     material authenticated on that source branch, and compare the ENTIRE reconstructed Descriptor
     with the requested one before claiming that target can be served."
  3. "The holder MUST reuse only identical authenticated aligned blocks, reconstruct
     partial/right-edge nodes for the requested size, retain the independently committed
     source/validated-leaf requirements, and return unavailable when any required node, control
     header or context is absent, n exceeds every available source, or the computed prefix
     differs."
  4. "The same resolver MUST cover Header and the head-bound Entry/Page paths needed to finish the
     operation, not only Query::Proof; exact hash binding, body-held status, current membership,
     recipient cut, live/archive bounds, purpose, key-package recipient and physical-send fences
     MUST remain enforced."
  5. "The asker MUST retain its exact signed committed head, requested coordinates/hashes and
     ordinary verifiers, independently verify every response against that head, and keep missing
     or mismatched evidence pending without rollback, root retargeting, invented absence of
     controls or a fork verdict from a relay's bad proof."
  6. "Serving MUST NOT commit/observe the supplied target, publish a source, advance control-ready
     state, insert a synthesized prefix into the canonical acceptance index, or create durable
     proof/head rows merely because a size was requested; generated request-only contexts and
     intermediate ranges MUST stay in charged bounded serving state/cache unless a genuine existing
     owner requires their durable retention."
  7. "Each incoming request MUST retain the existing admitted lane/byte limits, one response
     quantum, cancellation, lifetime and per-slice WorkBudget bounds; root reconstruction and all
     proof kinds MUST share that request's accounting and never reset its lifetime, fetch remote
     evidence or start a hidden archive catch-up to complete the ask."
  The target is the canonical head body/Descriptor plus its existing ID, not a size alone and not a
  retransmitted signature; the holder treats it as an untrusted selector checked by equality with
  its own verified prefix, and no SignedHead signature is fabricated internally (ruling §2). #1387
  persists the response contexts it generates; rule 6 makes such contexts transient unless an
  existing owner needs them. P changes no writer, admission or authority policy.
  *Considered and not approved: W* (a control names, in `seen`, each other author's latest control
  instead of its newest post). Its prefix facts hold under conditions, but control clocks are not
  display-only: the clock clamp reads held `seen`, so W can move a new control behind the posts it
  followed, and the largest authority-row clock signs the board's AdminRoster timestamp, which the
  board uses to ignore an equal or older roster and to authorize a room withdrawal; a back-clamped
  creator revocation could leave a stale roster installed (the ruling's inference, not run;
  `design/moving-head/ruling.md` §1). A later W proposal MUST separately preserve notice ordering
  and strictly fresh signed-roster authorization and prove the paused-writer/admin-revocation case
  on the real board. P covers every wait where a holder owns the requested prefix, so W is not
  needed there. *(Amended 2026-11-23, amendment 3.)*
  *(Amended 2026-11-24, amendment 4, by the control-closure ruling of gpt-6.1-sol, `design/busy-room/control-closure-ruling.md`; nothing was built or run for it.)* What a newcomer must obtain per author before showing its posts: "authenticated no-omission coverage and individually admitted control sources through A’s preceding prefix, with required effects settled—not every ordinary entry’s body" (§1, :11). By signed kind (§1, :15-22): Governance and StepPolicy need their body; Checkpoint, SessionFloor and PrivateSupport need it under today's full validator; a KeyPackage's header can be admitted without its body, its addressed delivery remaining a separate obligation; a ContextUpdate and a Termination have no body; Content, encrypted read records included, is not part of the control enumeration. A Governance entry cannot be skipped from its header, which says only Governance (§2, :34). An existing signed kind MUST NOT be moved out of the control class for old entries: that class sets both the committed control bit and the leaf's post-context, and existing roots keep their original interpretation (§2, :38). "**Dependencies constrain validation/application, not acquisition of provisional bytes.**" (§3, :42): bodies may be fetched ahead and across authors and are validated and applied only when their exact prerequisites permit; one staging record per node and purpose is "a **real invariant of the current staging implementation**, not a security requirement" (:44), so removing the slot lock alone would corrupt ownership, and parallel staging needs independently fenced owners, bounded in aggregate (:51). Its build order (§4, :59-65): first a bounded control-body page over the already authenticated control enumeration, "without fetching intervening Content", with proofs that a holder cannot omit or substitute a control, mix heads or authors, inject a misclassified removal, serve another recipient's sealed package, exceed byte credit, or turn fetched-but-unvalidated bytes into Complete, and that an interruption and restart mid-batch keep the exact unfinished obligations (:59, :61); then independently fenced, byte-accounted staging for several authors, preserving bounded aggregate storage and memory and publication transactions, with proofs that one stalled or oversized author cannot block unrelated authors, cancellation cannot reclaim another request's bytes, and restart cannot admit stale work (:63). The coordinator's draft takes that order "only as far as measurement requires" (`design/amendment-4-draft.md:33`). Fetching is to be ADR-054's; how ADR-054's control-interval request relates to that build order is not decided.
  - *Why*: #1384 keeps inclusion and consistency witnesses but leaves `ControlRange` pieces
    cache-only (`node/history_stream/admission.rs:439-462,558-597`): a locally completed verdict is
    not a transferable proof, and "members hold the governing controls" does not mean they can
    serve their proof under the needed roots (review §2 on P1-B). A since-revoked admin's earlier
    removals still stand, so closing only today's admins lets a newcomer treat a removed member as
    present (`m1-security.md` §4). Consent and reset decide rendering
    (`node/channel/governance/view.rs:169-220`); private readiness needs per-author control coverage
    (`node/channel/private_session/pending_upgrade.rs:2327-2367`). Measured on main `193224043`:
    one control entry written by an author after a holder verified it strands a newcomer joining
    through that holder with the author stopped; the holder declines pieces it holds under the
    earlier head (`mp/control/runs/ctl-base`, RED). *(Amended 2026-11-23, the head-mismatch ruling
    and its question, `design/head-mismatch/question.md`.)* Measured with M0 built (main `b3d7fb75d` with #1387 and the M0 patch, `m0/journey1/`): the busy room shows 0 of 16 directions, against 5 to 7 on main without M0; every reader verifies every author only to the end of its join-era entries. The cause is the builder's reading (`m0/journey1/cause.md`), not yet confirmed: readers ask under their own newest committed head of an author, which in a busy room no holder has committed because every post is a new head, so holders decline and the ask goes to the author. It stays the builder's reading until the per-wait trace (`m0/journey2/`, a run in flight) shows, for each blocked join control, the reader, the citing author/position/kind, the required author/position/hash, the fixed target head and size, the phase, the provider's source head and size and the exact missing item, distinguishing a head-ID refusal from genuinely absent material (moving-head ruling §6). If every provider is behind the asked size, P does not cover that wait. *(Amended 2026-11-23, amendment 3.)*
  - *Proof*: (a) *the stopped author with the holder restarted and a misleading newer head first*
    (extends the act of `rg-6/witness/`, green on v0.4.30, red on `403218281`): "An author stops
    after a holder has verified and durably retained the complete control closure needed by its
    posts, including the consistency evidence linking that closure's exact heads to the newer signed
    head used in the act; the holder restarts, a peer offers that newer head to the newcomer first,
    and the newcomer independently verifies the required governing/dependency evidence from the
    holder alone and shows the holder's posts after joining. If that link or any required newer
    governing fact was never held, only the affected obligation remains pending, with no rollback
    of its anchor and no authority granted from the unlinked alternative." Mutants: the cache-only
    Control trace mutant and the linked-piece-lookup-disabled mutant each turn this linked
    availability arm red. *(Amended 2026-11-23 by the head-mismatch ruling §§5 and 6.)*
    (b) *Revoked admin*: an admin removes a member, then the creator revokes that admin; a newcomer
    joining after both
    treats the member as removed, releases it no key and shows none of its later posts; an act of
    the admin after its revocation has no effect. Mutant: close only current admins. (c)
    *Non-admin controls*: a non-admin revokes its consent toward a member, and a second non-admin's
    consent is withheld; the first takes effect, and only the second sender's messages wait for the
    newcomer. (d) *A newcomer in old long histories*: a copy of a room grown by v0.4.30 or main
    with long governing feeds (the decider's real rooms among them); the newcomer joins with the
    creator and a long-history member stopped, and shows the others' recent posts; its wait is
    measured and recorded, not promised (MP-17). This measurement decides whether ruling 9's
    question is put to the decider. (e) *A holder answers for a prefix it never committed* (moving-head ruling §5): on real daemons or wire peers, N commits A's signed head n; holder H skips that head, later accepts a strictly larger consistent head while keeping the needed prefix material; A stops and H restarts; from H alone N obtains the exact Header, Inclusion, Consistency, Control and the retained authorized body, applies a real join grant or package and reads the citing member's post; n is not a power of two and lies below H's window, with deliberately owned witnesses, and the act asserts H never committed n. Mutant: restore the committed-ID gate at any required serving stage; the operation fails structurally, not merely because Proof alone was fixed. (f) *P guards*: a forked provider or corrupt relay supplies another prefix, and N never renders or applies it while withholding stays pending (mutant: let N retarget its anchor or skip its root check); authenticated clients cycle historical sizes, including missing-piece and n>|H| cases, cancellation and a concurrent honest client: requests stay bounded, no synthetic durable target, proof or context rows accumulate, and useful progress survives (mutants: persist serving-only synthetic state; bypass credit, lifetime or authorization checks). *(Amended 2026-11-23, amendment 3.)*

- **MP-8. What validating a control closes.** The full validator today closes every context
  coordinate and parent prefix of a control, non-admins included
  (`node/channel/governance/sparse.rs:479-550,561-617`), while the proposal's newcomer closes only
  the governing feeds. The review requires this contradiction resolved: "Either retain and transfer
  that entire required closure, or explicitly specify a narrower **effect-specific** control
  projection whose omitted coordinates never enter authority/cuts/authoring. 'Close governing
  feeds' is not itself that validator." The sources do not choose (open question B-1). Until a
  narrower projection is specified, reviewed and recorded as an amendment of this ADR, the first
  alternative binds: a control is applied only after today's full closure, and MP-7 makes that
  closure durable and serveable. Omitted coordinates of any later projection MUST never enter
  authority, cuts or authoring. *(Amended 2026-11-23, amendment 3, by the forked-target ruling §4:)* MP-9a's fork-parent evidence path is a narrow amendment to this rule for a proved forker only: it replaces an impossible committed-branch requirement with equally exact evidence-only proof; it is not a narrower projection and not a global replacement of MP-8a's no-unlinked-authority rule.
  - *Why*: the proposal the decider read says controls keep "full proof of everything it cites, as
    today" (`proposal.md:19`); the first alternative is today's behaviour, so it adds no new
    validator.
  - *Proof*: MP-7 (c) and (d), and MP-6 (a), green with the first alternative.

- **MP-8a. An author's evidence under another signed head grants authority only across a verified
  link.** *(Added 2026-11-23 by the head-mismatch ruling of gpt-6.1-sol, the reviewer who wrote C5
  and C6, `design/head-mismatch/ruling.md` rules 1 to 3; it resolves B-10.)*
  1. "The asker MUST keep its committed anchor and use a different signed head for authority only
     through the existing consistency acceptance gates, without treating a signature, an exact
     cited header hash, or a pending fork comparison as a consistency verdict."
  2. "The asker MUST keep each evidence obligation's exact root, interval and referenced hashes
     fixed, independently verify its complete required closure, and leave an unlinked
     alternative's evidence serving-only and the affected obligation pending until continuity is
     proved."
  3. "The asker MUST use older linked evidence only for the exact historical facts and prefix it
     proves, never as evidence that later controls are absent or that the newer head is
     control-ready, and MUST wait for every newer control coordinate exposed by the operation's
     authenticated dependencies before that operation takes effect."
  No timeout converts a withheld link into either consistency or a fork; other already-safe work
  stays usable. *Head choice: H.* *(Amended 2026-11-23, amendment 3, by the moving-head ruling §4:)* "H MUST be scheduling preference only: before choosing an anchor for new work, prefer an already available, connected holder's advertised committed head that covers the needed coordinates; after selection keep exact obligations fixed. The author's newer signed observations retain ordinary non-starving processing and consistency-gated promotion. Do not wait for a holder advertisement, roll back an existing commitment, retarget captured work, or require holder approval before newer governing coordinates can be processed." It uses existing ownership and fair queues, not a promote-only-when-useful candidate/demotion state machine.
  - *Why*: a holder could otherwise offer an older head h1 to hide an author's later removal or key
    change under the newer h2 the asker already holds, and an author that signed inconsistent h1
    and h2 could have h1's authority imported while MP-9 investigates; an exact cited terminal
    header does not authenticate every earlier control leaf under h2 (ruling §2 (a), (b)). Nothing
    from unlinked evidence is applied, so nothing needs undoing if a fork is later proved (§2 (e)).
    Today, with h2 committed, promoting a smaller offered h1 already asks for consistency from h1
    to h2 under h2 (main `193224043`, `node/history_stream/admission.rs:649-669`; ruling §3); this
    requirement keeps that gate.
  - *Proof*: the adversarial arm of MP-7 (a): give the newcomer a newer head for which the holder
    cannot supply a valid link to its older head, including an unequal fork with a matching overlap
    terminal header but a differing earlier prefix; the affected operation stays pending with no
    unsupported control or key effect while an unrelated safe sender stays readable; then supply
    authenticated contradictory openings and assert durable fork restrictions, never a fork verdict
    from withholding alone. Mutant: bypass continuity for historical control dependencies; this
    arm turns red. *H act* (moving-head ruling §5): a newcomer sees a holder's usable committed head and an author's larger head, shows the intended initial preference with unchanged exact-root work, then obtains and processes a genuine newer removal or key change without waiting for holder endorsement; repeated with only the author available. Mutants: author-first only for the availability arm; an indefinite holder endorsement for the newer-control arm. *(Amended 2026-11-23, amendment 3.)*

- **MP-9. A member's split view is detectable across all authors and unequal sizes (C6).** Nodes
  MUST "Propagate all-author signed head observations through honest holders; retain unequal-size
  competing observations and request authenticated overlapping openings/prefix evidence when
  continuity cannot be established. Extract a contradiction under the signed roots; refusal or a bad
  relay proof is only unverifiable/pending. Preserve known fork/exclusion evidence permanently."
  The queried overlap position MUST fit both heads, and header or opening evidence MUST authenticate
  both sides under their own roots; where heads disagree about an earlier prefix although a
  terminal header matches, prefix or range evidence is compared. Withholding is not a proved fork.
  "MP-9 MUST retain and make discoverable and retrievable the signed unequal-size observations
  whose continuity is unresolved, including the second unlinked head, and MUST propagate verified
  fork evidence once extracted without replacing that observation exchange with fork-proof
  exchange alone." "MP-9 MUST authenticate both sides of an overlap within both heads, beginning
  at m=min(|h1|,|h2|) when nonzero, continue with authenticated prefix/range comparison if
  matching terminal headers do not establish continuity, and classify withheld or invalid relay
  proofs as pending rather than author equivocation." *(Amended 2026-11-23 by the head-mismatch
  ruling, rules 6 and 7.)*
  *Transport.* A recorded fork travels between members as the proof itself (the two signed entries
  at one position), by a `forks` list on the existing Have frame and one added query, and
  unresolved second heads are retrievable by exact head. Today a recorded fork never leaves the
  node that found it: it is restored only from this node's own store (`node/channel.rs:2709-2731`)
  and the Have frame carries no forks (main `193224043`, `node/history_stream.rs:692-708`). One
  version per room is assumed (ruling 4), so these wire additions are allowed; no new signed record
  is added. *(Amended 2026-11-23: the coordinating session's engineering decision,
  `exec/deviations.md` "Engineering decisions on 2026-11-23 while building ADR-053's step 2"; not
  the decider's ruling and not the review's.)*
  *(Amended 2026-11-24, amendment 4:)* Under ADR-054 the signed heads, with unresolved unequal observations, are to travel in each node's Have (ADR-054 PL-2), and the inventory paging and hint queue named in this requirement's *Why* are to be deleted (ADR-054 PL-11); MP-9's rule stands. Whether the `forks` list rides on ADR-054's Have is not decided. MP-9 has not landed when this amendment is written: it is one commit on `36c60c821`, not pushed (`mp/fork/rebase3/report.md:3`).
  - *Why*: today a message citing the forker's other branch is refused, so the room visibly stops;
    under this design messages cite nobody, and the explicit observed-conflict pair is equal-size
    only (`node/channel/entry_store/sparse.rs:2847-2854`; smaller queued hints are collapsed behind
    a larger one, `node/history_stream/hints.rs:367-392`). The inventory already pages every
    author's committed head (`node/channel/sparse_history.rs:1127-1152`;
    `node/history_stream/source.rs:1288-1312`). `m1-security.md` P2-E's operation, as corrected by
    review §2.
  - *Proof*: *unequal forks through holders and a relay*: author F shows a 40-entry history to one
    group and a different 60-entry history to another; the groups never connect directly, only
    through an honest holder and a non-member relay. A member of each group records F's fork, and
    both groups apply the fork restrictions. A relay that withholds or corrupts the opening yields
    pending, never a fork verdict. Mutant: keep only equal-size conflicts. A second unlinked head
    survives a restart of the member that holds it and is retrieved by exact head by a member that
    never met that branch; a fork proof recorded by one member reaches a member that never met the
    second branch. Mutants: exchange fork proofs only, without the unresolved observations (the
    arm before any proof exists turns red); drop the `forks` list (the second arm turns red).
    *(Amended 2026-11-23.)*

- **MP-9a. A member that splits its own history cannot escape its removal (ruling 10).** "A proved
  fork changes parent evidence, not authority." *(Added 2026-11-23, amendment 3, by the
  forked-target ruling of gpt-6.1-sol, `design/forked-target/ruling.md` §1, for the decider's
  ruling 10; question in `question.md` beside it; ledger 73.)* Rule 7 of that ruling is MP-6's cut.
  1. "A reader MUST enable the fork-parent path only for an author T whose attributable,
     room-bound fork proof has been independently verified and durably recorded; a hint,
     equal-size head conflict, failed consistency proof, peer's `frozen` claim or elapsed wait MUST
     NOT enable it."
  2. "For another author's exact cross-author reference `(T,p,hash)`, the reader MUST obtain the
     exact signed header, authenticated inclusion and authenticated prefix through p under one
     retained author-signed head of T, match every binding and the referenced hash, and treat that
     result as fork-parent evidence rather than a committed T head or a canonical T source."
  3. "The fork-parent verifier MUST authenticate and close that branch's complete required
     control/context/parent evidence through p, including no-omission coverage and transitive
     dependencies, and MUST check the citing entry's signed frontier domination against that exact
     branch prefix, not a truncated or locally convenient prefix."
  4. "The reader MUST keep T's alternate-branch inputs evidence-only: they MUST NOT construct a
     canonical `ValidatedSparseEntry` for T, enter T's accepted positions, become an authoring tip,
     make T control-ready, install T's packages/floors/keys, or supply non-exclusion authority
     outside the already verified common authority prefix." "Authenticated exclusionary controls
     encountered in the closure MUST be retained and evaluated through the existing fork-exclusion
     rules, with their required authority/causal evidence; they are neither silently dropped nor
     made effective merely by being signed."
  5. "The reader MUST preserve every coordinate of R's signed context and every independently
     validated dependency, while treating T's rejected-branch coordinates only as exact fork
     dependencies, not as authority-bearing canonical T source positions or an increased general
     authority frontier."
  6. "The reader MUST persist and serve the exact branch witnesses and their verification closure
     with the citing source's evidence ownership, and MUST re-establish the verified-fork predicate
     and exact bindings when consuming/restoring them; missing evidence remains a resumable, named
     pending obligation, not a fake receipt or an author-fault verdict." It uses the existing
     receipt encodings with an evidence-only parent writer; no new signed format, wire message,
     timer or stored receipt shape.
  7. Written into MP-6: the cut is exact authenticated membership in the prefix W the remover's
     reference names, by branch, not by position.
  8. "Once R's own ordinary admission, fork-parent closure and unchanged authorization/effect gates
     pass, the reader MUST apply its valid control and resume R's later entries through the same
     full validator; the cross-author fork-parent rule MUST also cover the context carriers and
     subsequent full-validation entries needed to avoid immediately blocking the feed again."
     Missing genuine dependencies can still delay R; what goes is the impossible committed-branch
     demand, not the need for withheld closure.
  *What a person sees, and which messages stay* (ruling §3): before the proof arrives, the reader
  names the remover as waiting for the exact fork-parent and membership evidence and does not claim
  the removal applied; once the target's fork is recorded, the existing fork warning and freeze stay
  visible whether or not the remover still waits; other already-safe authors stay usable and the
  egress fences hold. After the complete witness arrives and the removal is authorized, the target
  leaves the roster, no new reply or key is released to it, and the remover's later valid controls
  and posts proceed; the target's proof-only material is not shown merely because it was fetched.
  Of the target's already-shown messages, those in `shown ∩ W ∩ otherwise eligible` stay: a reader
  of the remover's branch keeps the eligible messages through the witnessed tip and loses later or
  unwitnessed ones; a reader of the other branch keeps only messages proved also to be in W,
  normally the true shared prefix, and loses its other-branch messages even below that tip (MP-11).
  The recorded `ForkBoundary` is not necessarily the shared-prefix length (mismatched predecessor
  hashes set it to 1), so the cut proves shared ancestry rather than using it as a display cutoff.
  Nothing recalls plaintext or keys already disclosed.
  - *Why*: measured on real binaries (ledger 73; `mp/cut/arm-c.md`; runs `mp/cut/runs/r2/change-c.log`
    and `base-c`, `mp/fork/runs/cand-armc.log`). Carol signs two branches of her own feed of equal
    length; Dave accepted branch B; Alice, holding branch A, removes Carol naming her A tip. On
    main Dave never records the fork (`"equivocations":[]`), never admits the removal, keeps Carol
    as a member and holds every later entry of Alice. With MP-9's comparison built the fork is
    recorded (`frozen=[carol]`), but the removal still never applies and Alice's feed stops at 11:
    the removal's exact parent receipt under the reader's committed branch of the target can never
    be satisfied (`question.md`). The ruling rejects waiving the receipt once frozen and restricting
    the path to exclusions of the forker: an honest remover's preceding context carrier and later
    entries can cite the same branch, so a removal-only exception would not release the remover's
    feed; and "dominate only through the shared prefix" could discard another author's later
    governing coordinate acknowledged on the cited branch (ruling §2).
  - *Proof* (ruling §4): extends `a_target_that_forks_itself_is_removed_once_its_reader_holds_both_branches`
    on retained real binaries: with the equal-length branches and Carol stopped, Dave records the
    fork, admits and applies Alice's removal from Alice's exact branch witnesses, drops Carol from
    the roster, shows Alice's next post, and shows exactly the retained/intersected history above
    (Alice keeps the common base and the witnessed A posts; Dave keeps the common base and loses
    both B posts once the removal and MP-11 apply), also after Dave restarts. A control or context
    carrier citing Carol's other branch before the removal is included, so a removal-only special
    case cannot pass. Mutants: restore the committed-parent-only gate for a proved forker (the
    removal and later-post arm fails structurally although fork recording succeeds); waive the
    exact referenced receipt once frozen (a signed malicious remover's nonexistent `(p,hash)` must
    not apply its control); compare the cut by position (Dave's B-only posts must not survive the A
    cut). Also: a forged frozen claim, a withheld prefix or closure, and a branch frontier exposing
    a separately withheld governing exclusion all stay pending or inert, with no unsupported
    authority or key effect.

- **MP-10. Recipient, package and private-Session boundaries are named and kept one by one.** Each
  is a distinct check today and MUST stay one:
  1. *provider body send*: a holder sends a body to a once-removed recipient only within that
     recipient's exact readmission cut (`node/channel/governance/view.rs:1635-1728`);
  2. *recipient render*: a node that knows its own applied removal renders no newly received old
     body (`node/channel/semantic_projection.rs:294-313`);
  3. *addressed-package open and install*: removed or ineligible authors and pre-readmission
     packages are refused (`node/channel/pending_package.rs:525-562`);
  4. *restored Drive floor* (`node/channel/pending_package.rs:960-1003`);
  5. *current membership-generation commit* (`node/channel/pending_package.rs:1086-1094`).
  Legacy Session carriers MUST NOT be treated as ordinary text because the outer historical
  classification says Content (`node/channel/private_session.rs:898-926,992-1008`). Private access
  keeps its per-author control coverage, authorized floors and uninterrupted generation
  continuity (`node/channel/private_session/pending_upgrade.rs:1270-1338,2327-2367`). A known
  termination keeps blocking later source positions (`node/channel/entry_store/sparse.rs:2132-2141,
  2365-2378`), and the hidden-termination gap MUST be closed using author-local evidence, not
  silently accepted (review §2; open question B-5).
  *(Amended 2026-11-24, amendment 4:)* #1392 landed (the reviewer accepted merge commit `24b15f8b7`, `exec/review-audit.md:42`; it reached main as `febb6459e`; `exec/found-reds.md:167` names both). Proven alone, each by an act that goes red when that one protection alone is switched off (`release/notes-draft.md:76`): a holder never sends a readmitted member a message written outside its readmission; a readmitted member never shows such a message, even when every holder sends it; a member never installs the key of an author it knows was removed. Not proven alone (`design/amendment-4-draft.md:50`): a key package from an author the reader does not yet know was removed; legacy Session carriers ("cannot arise" by reading); boundary 5, item 5 above, the current membership-generation commit, which "holds twice by construction (no act)"; which two checks hold it is not named in that draft. Boundary 4 (the restored Drive floor) is not among those statements and is not recorded by this amendment. The private-floor boundary is proven only for a reader that has applied the removal: the gap of ruling 11 stays in v0.4.31, and the release notes draft names that boundary as not proven alone (`release/notes-draft.md:76`; ledger 76).
  - *Why*: the review's paragraph on point 5 (§1); `sync-sol-on-m1.md` §1, §5. "Signature, place and
    keyring" is not an adequate description of the package path.
  - *Proof*: (a) *readmission gap, recipient side*: a member removed and readmitted receives,
    renders and installs nothing written between its removal and its readmission, through any
    holder; what it rendered before removal stays. Mutant: one per boundary 1 to 5. (b) *Legacy and
    private floors*: a once-removed author's older floors are withheld; its removal-period private
    records are not accepted; a legacy drive generation carried in Content is not shown as text.
    (c) *Hidden termination*: a real wire peer withholds its author's termination and offers a
    later entry; the reader keeps that entry unrendered and non-citable while the required
    author-local evidence is missing, then rejects it when the authenticated termination is
    supplied, including after restart. Mutant: accept later positions without checking the
    author-local termination evidence. This act MUST be green in Order step 2 before lighter
    admission is activated.

- **MP-11. A message shown and later proven not acceptable disappears (ruling 8).** When a removal
  or a fork that a node applies shows that a message it already shows was not acceptable (its
  author outside the removal's cut, MP-6; its entry on a rejected fork branch, MP-9), the message
  MUST disappear from the conversation on that node: from `vox room read`, the terminal app and the
  Mac app, and from every later read, so the room looks the same to every member. Such a message
  MUST NOT authorize a control or a key release, before or after it disappears. Nothing can recall
  what a person already read, and no notice may claim otherwise. This is a change from today: the
  cached reader checks expiry, not membership, and backfill skips cached rows
  (`node/channel/history.rs:544-560`; `node/channel/pending_governance.rs:464-477`); until it is
  built, no record or release note may say that membership or fork replay retracts shown text. It
  applies to the *author's* ineligible messages only: what a once-removed *recipient* rendered
  before its removal stays with it, as today (`node/channel/semantic_projection.rs:294-309`;
  ADR-007:299-300). *(Amended 2026-11-23, the coordinating session's engineering decision: MP-11 lands only together with MP-6, Order step 2.)*
  *(Amended 2026-11-24, amendment 4:)* MP-11 landed with MP-6 in #1393 (merge commit `36c60c821`, `exec/review-audit.md:66`). As #1393's pull request describes it, it retracts by author eligibility: when an eligibility decision says a shown message's author is outside the cut, its rendered row, its place in counts, pages and threads, and its read receipt go in the same transaction; only author eligibility retracts (`mp/cut-disappear/fix6/pr-body.md:32-37`). The sentence above, "until it is built, no record or release note may say that membership or fork replay retracts shown text", is therefore met for membership; the fork arm of the proof below needs MP-9, which has not landed. For a message its remover never held, see MP-6's amendment 4. *The return half* (a removal that took messages away stops holding). The decider's word covers the first half only; the coordinating session decided the return (`design/amendment-4-draft.md:12`), and the reviewer ruled "BUILD N WITH CHANGES" (`mp/cut-disappear/ruling-n.md:5`). A message that comes back **arrives again**: it gets a new arrival, keeps its place in the conversation (its display clock, hash and created time) and every input to its lifetime, and never gets a fresh lifetime; it is news once more to every reader, including one that had it before it went, and that second telling is accepted, described as the message having returned (ruling-n.md:8, :12, :15; pr-body:100-104). The new arrival MUST be allocated through the shared log and cache allocator, with its advanced high-water mark installed in memory, and the cache, the render and filter indexes and the retention locator MUST be rewritten in one transaction, the old cache retired (ruling-n.md:11). Read marks and receipts, reply references and FFI message IDs stay keyed by hash and are kept; a message already read may stay read although it is announced again; existing deduplication is not cleared globally; the revision and publication fences of reads in flight are kept (ruling-n.md:13-14). A reader that continues page by page holds a *position* (a continuation cursor naming an arrival place), not a message hash: a message that came back has a new arrival place, so continuing from its hash could jump past what arrived while it was away (ruling-n.md:10); such a hash is refused in plain words, and the retention fact carries one optional field for this (pr-body:105-113). Draft B's "A thread page is ordered as the room is" is, as built, the thread page the Mac app reads: it is in the room's order, so a reply that came back is in its place; the terminal app's thread view and the agent hook's thread context read by arrival, unchanged (ruling-n.md:9; pr-body:118-120). No per-reader record of what was withheld exists: the request first built for it was rejected in review and deleted (ruling-n.md:15; pr-body:98-99).
  - *Why*: ruling 8; review §5 ("Choose the later-invalidated-row behavior explicitly") and §6
    question 2. Under MP-1 a message whose author had not heard of a removal is shown until the
    reader applies that removal (the unaware-partition window); without this requirement it would
    stay shown on some members and not on others.
  - *Proof*: a hostile-peer act on real binaries. The creator removes A at R; a real wire peer for A
    that never acknowledges R posts M after R; reader N, which has not yet applied R, shows M. N then
    applies R: M is gone from `vox room read`, from the terminal app's view and from the Mac app's
    read, also after a daemon restart, and no control N writes cites M. The same with a fork: F's
    message on the branch N later rejects is gone once N records the fork. Mutant: leave cached
    rows as they are when membership or fork facts change.

### Fetching

- **MP-12. Each member keeps one list of the positions it lacks, and asks until each arrives.**
  This is what #1385 began. A node MUST keep, per author, every position between its floor (a
  newcomer's first window: the newest 128) and the author's accepted head that it does not hold,
  as permanent missing intervals that survive a restart; it MUST ask for each until it holds it or
  it is declared gone by retention. Per-peer response work MUST be finite. A holder's
  `BodyNotHeld` or unavailable answer is holder-local: that holder is not asked again on that
  connection, and the position stays owed from other holders; it MUST NOT be abandoned.
  *(Amended 2026-11-24, amendment 4, by ADR-054:)* "that holder is not asked again on that connection" is to be met by the holder's corrected extent in its answer (ADR-054 PL-7), not by a refusal flag the reader keeps (ADR-054 PL-13; `design/simple-sync/design.md:52,69,72`). The rest of MP-12 stands; its missing intervals are the debt ADR-054's loops are to work from (ADR-054 PL-3).
  *(Amended 2026-11-25 by ADR-054 amendment 3, PL-20 item 2:)* Amendment 3 replaces this
  connection-lifetime promise for body availability: a denied body is not asked again until an
  ordinary Have positively advertises it again. The bound is per positive re-advertisement, not
  per connection (`design/adopt/ruling-body-extents.md:24-25`).
  - *Why*: ledger 66 (Context). The second-lane fix (about 1,100 lines, a marker, a grace period,
    set-aside rules) is not built. The review's step 1. With one version per room (ruling 4) no
    compatibility path for old servers is built.
  - *Proof*: the stopped-follower burst (`a_follower_held_still_through_a_burst_holds_every_post`:
    300 of 300); a far-behind follower while others post
    (`a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back`, and a third member's
    posts shown during the catch-up); 1,000 posts from four shells held 1,000 of 1,000; a follower
    restarted mid-catch-up still holds every post. Mutants: `VOX_MUTANT_LIVE_FLOOR`; forget the
    missing intervals at restart.

### What is deleted

- **MP-13. The machinery this decision makes dead is deleted, not kept beside it.** After step 3
  of the Order is active and its acts are green, each of the following MUST be deleted with its
  acts kept green (line numbers in `sync-land`; `sync-opus.md` §2; `sync-glm.md` §2). *(Amended 2026-11-23 by the M0 ruling: the list is what M0 makes dead: only the cross-author parent-receipt, closure and domination machinery for ordinary v2 Content's `seen`, the artificial per-post carrier, and scheduling machinery independently shown obsolete; the author's own predecessor/prefix receipts and full own-control source/effect readiness are retained; items that only the withdrawn display/source split would have made dead are withdrawn or made optional below.)*
  1. *The per-post tip join for Content*: the join of every other author's settled tip into a
     message's context (`node/channel/local_history.rs:493-542`, for Content only; controls keep
     it). `append_text`'s context-advance path (`node/channel/pending_text.rs:939-957`) stays and
     fires only on real changes (MP-4).
  2. *Cross-author parent receipts for ordinary v2 Content's `seen` only*: remove only those
     references' receipt fetching, preflight, control closure and domination, and helpers exclusively used by that work. MUST retain Content's own predecessor/header/prefix authentication, exact preceding-aggregate check and full own-control source/effect preflight, together with their required receipt/proof machinery. Control kinds and legacy admission retain their existing parent checks (MP-16's C7, M0 rules 1 and 3).
     *(Amended 2026-11-23 by the M0 ruling's author, `design/amendment-2-verdict.md`.)*
  3. *Withdrawn by amendment 2 (the M0 ruling).* The accepted text listed the live window's control
     closure (`node/history_stream/runtime.rs:1048`, `push_control_closure`) as a gate to delete. M0
     keeps the author's own control-source/effect readiness and every coordinate's full validation
     (MP-1, rule 1), so that closure is not dead; only the closure fetched for Content's `seen`
     parents goes, with item 2. *(Amended 2026-11-23.)*
  4. *Node-wide singletons*: the `Live`, `Control` and `Archive` slots (`node/history_demand.rs:55-61`),
     the serve lanes including `try_serve` (`node/history_budget.rs:399`) and the Live refusal
     "live request is outside the bounded newest window" (`node/history_budget.rs:1088-1091`), and
     the server's newest-128 clause (`node/history_stream/server.rs:823`, removed by #1385). What
     stays: one request per peer and room at a time, and one byte cap per node as a memory bound. *(Amended 2026-11-23 by amendment 2: M0 does not by itself make these dead, and existing scheduling limits remain (M0 ruling §6); each MAY be deleted only where its acts show it dead. The newest-128 clause is already gone with #1385.)*
  5. *Content's stored parent and per-post receipts* once MP-14 no longer writes them.
  The following disposition is the coordinating session's reading of ruling 2, not a separate
  ruling by the decider. **The parked candidate** (`rg-5/dep-first/full4.patch`;
  `rg-6/sync-land/report.md` §3) MUST NOT land as a stack: its rules 3.2, 3.3 and 3.6 to 3.17 (the
  share of four, redirect bound and rests, dependency-first, route-stays, wake-on-release,
  pull-back, hunks A to H) are not built. Rules 3.1
  (per-peer turns), 3.4 (the per-room save gate) and 3.5 (the lost-wake fix) each repair a defect of
  their own and MAY land, each as its own change with its own red (RG-0). The second-lane burst fix
  is not built.
  *(Amended 2026-11-24, amendment 4, on the decider's ruling 13; ADR-054:)* For fetching this paragraph is superseded. None of the parked candidate's rules lands in any form, and neither does the coordinating session's later approval of a narrower rule about who can answer (`exec/deviations.md:156`); the machinery those rules schedule (the hint inbox, routed, parked and deferred flows, announcements and their rearm) is to be deleted by ADR-054's first slice (ADR-054 PL-11). Of the rules this paragraph allowed to land, each peer its own turn is kept from the prototype as structural (`exec/deviations.md:189`); rules 3.4 and 3.5 are not named by ADR-054's sources: not decided. Item 4 is not changed by this amendment.
  - *Why*: ruling 2; each deleted rule scheduled demand that the gate of Context property 1
    created. Under M0 the parent gate for Content's `seen` is what goes (M0 ruling §6), so these rules lose their reason; whether that is enough for the busy room is measured by the journey, not proven by the ruling. *(Amended 2026-11-23.)*
  - *Proof*: *two authors on a slow path*: the `two` relay arm of `key_package_proof.rs` (two
    members posting at once at 75 ms a hop) keeps the reader within its newest-end rule;
    `a_slow_member_delays_only_itself` green with no pull-back rule; and the whole busy-room
    journey (MP-18) on the binary with the deletions made.

### Storage

- **MP-14. Stage 1: each signed header is kept once.** A node MUST keep each signed header once, in
  the sparse `Header` object peers are served (`store-opus.md` §1): a pruned v2 log row keeps a
  marker instead of the header; an inclusion receipt refers to the `Header` object instead of
  embedding it; a parent receipt is derived from the inclusion and prefix receipts kept under the
  same key and is not stored. Every existing evidence meaning MUST be preserved: each reader of a
  changed record gives the same answer. Existing stores MUST be converted in place, room by room,
  in bounded transactions, deleting nothing unless the same bytes are held elsewhere and were
  checked in the same transaction; a row whose header differs from its `Header` object is kept and
  logged. The schema marker MUST advance with the first converted row, so an older binary refuses
  the store rather than misreading it.
  *(Amended 2026-11-24, amendment 4, by the decider's ruling 12:)* MP-14 moves to v0.4.32. Stage 1's half-built work is kept as it stands (`rg-13/stage1/handoff.md`); for v0.4.32 the design is to be the simplest one that works, not the six-part plan as written, "to be re-decided then" (`exec/deviations.md:180`).
  - *Why*: ruling 3 ("storing the wrong way"); the four signed copies (`rg-13/checkpoint/report.md`
    §1). Estimated by reading, not measured: author about 15 KB, reader about 16 KB per expired
    message (`store-opus.md:20`). These are targets to measure, not promises.
  - *Proof*: M1 of `store-opus.md` §5 on real binaries: an author and a reader, one room, ten-second
    retention, 2,000 posts of 1 KB; held-bytes delta per post on each node, before and after.
    Conversion of a copy of the measured store and of a v0.4.30 store: held bytes before and after,
    and identical `vox room read --json` output for every room. Mutant: a marker reader that does
    not resolve the marker fails with "indexed log entry missing".

- **MP-15. The store file follows what it holds, and space is given back while the daemon runs.**
  The engine MUST allocate lowest-first, grow the file by a quarter, and trim at ordinary commits;
  a give-back pass runs on the events that free space (after a retention prune that removed rows,
  and once after Ready), with no timer; startup compaction before Ready is removed. Because the
  vendored public compaction refuses live read references (`vendor/redb/src/db.rs:1147-1155`), the
  pass MUST be a safe native implementation, and startup compaction MUST NOT be removed until there
  is evidence on the real binary that reads stay correct during a pass, that acknowledged rows
  survive a crash during a pass, and of how long writes wait during a pass at about 200 MB and
  about 2 GB, warm and cold (review §5). Built, not committed (`rg-13/follows/report.md`); the
  pass runs after the room's save completes and counts held bytes without pages awaiting a durable
  free, for the reasons that report gives.
  *(Amended 2026-11-24, amendment 4:)* landed as #1391, merged 2026-11-24 (merge commit `9cbb105b9`, `exec/review-audit.md:62`; its pull request text, `rg-13/follows/fix4/pr-body.md`). ADR-052 RG-13 is closed as completed with its work phase Release ready (`exec/awa/receipt-integrate-1327.json`), on the audit `rg-13/close/requirement-audit.md` (closable at `9cbb105b9`, with its limits listed). "Built, not committed" above describes it when this record was accepted.
  - *Why*: ruling 3; deviation 17 is superseded by it. The file today steps up and never comes down
    while the daemon runs (Context).
  - *Proof*: the running-growth measurement on main and on the change, same script
    (`rg-13/follows/measure/`): main RED (2,101,248 to 100,642,816 bytes, never down, "give-back
    lines: 0 started"); the change's file returns to at most 1.25 × held after a burst; mutant
    `VOX_TEST_FX28_MUTANT=rg13-no-give-back`. Reads during a held pass (observed once by hand:
    "reads during held pass: ok=20 bad=0", `safety/run3/`), and
    `a_running_node_gives_expired_space_back_and_keeps_acknowledged_rows_after_a_crash` (running when
    this record was written); the longest write wait during a pass at 200 MB and at 2 GB, warm and
    cold.

- **MP-16. Stage 2: after a body expires, only the chain's fingerprint stays (ruling 7; C7 and C8
  are its conditions).** In a room whose retention is not for ever, once a content entry's body
  has expired, a node MUST keep only that entry's leaf, the fingerprint its author's signed history
  commits (entry hash, control bit and frontier, `log/history.rs:796-819`), and the locator rows
  that cursor, order and expiry decisions need; its signed header, its signature, its unsigned
  skeleton and the receipts that name it go. Controls keep their original signed evidence. Rooms
  set to keep messages for ever keep everything. What a node can then no longer show is who sent an
  expired message, when and how long it was; another member may still hold an old copy.
  This form MAY be switched on only under the review's conditions. C7: "Expired ordinary-data
  headers may be retired only when no retained or future authority/cut/recovery/fork/fetch
  obligation needs them, or an explicitly implemented equally strong leaf-backed replacement
  satisfies every such obligation. Expiry alone is not ownership release." C8: "After body expiry,
  retain the canonical evidence and metadata still owned by causal sources, cuts, own
  continuity/recovery, running reads/fetches, retained fork/exclusion witnesses or advertised
  proof service. A content signature/header may be removed only when a specified root/leaf-backed
  representation preserves those consumers' required authenticated facts and proof service;
  controls retain their original signed evidence. Remove superseded heads only after all owners
  are retired or validly rebound, including competing observations. Do not infer expiry or
  ownership release from a newer head alone." So each remaining consumer of the old header MUST
  first get its leaf-backed replacement, each with its own proof, and the leaf-only form is
  switched on only after all of them:
  1. *own-history recovery from a backup*: before deletion, implement an opaque-expired-position
     path that proves expiry and control absence for every skipped ordinary-data position,
     preserves the latest signed continuity/head, epoch/generation, complete control state, exact
     old-boundary consistency and append forest, keeps sequence and ratchet-generation high-water
     marks, recovers every still-live body and key, and never reports a backup current by
     resetting its sequence. Required terminal headers and anchors MUST survive until this
     replacement is demonstrated; today recovery reads each position's header
     (`node/channel/own_history.rs:25-59,1524-1588`);
  2. *paging into an expired stretch*: before deletion, specify and implement the authenticated
     expired/opaque representation and distinguish every authenticated fact from a holder-local
     unavailable or expiry report. Position, entry hash, control bit and frontier MUST be
     authenticated under a signed head; facts not preserved by that representation MUST NOT be
     represented as authenticated. Locator rows MUST support resumable cursor, range, order and
     expiry decisions. Paging MUST never recreate text, spin on a deleted header, mistake it for
     corrupt storage, or erase demand for other holders' copies because one holder lacks a body;
     control and legacy Session carriers MUST NOT be taken for expired plain text. This
     specification and its proof are prerequisites to activation, not deferred by B-4; today the
     server parses the header before any entry response (`node/history_stream/server.rs:731-745`);
  3. *a returning member's consistency link*: before deleting fallback sources, persist enough
     independently verified range/context material and implement a leaf/range index complete for
     every advertised commitment, so even a sparse holder can construct the consistency link from
     the member's retained root to a newer root and all owned head openings after restart. The old
     member's anchor MUST NOT be rolled back and an unprovable link MUST remain pending, never be
     treated as consistent; today reconstruction falls back to a validated header, source head,
     inclusion receipt and signature (`node/channel/proof_range.rs:179-200,219-269`);
  4. *fork evidence*: before deletion, implement a leaf- or descriptor-based inclusion-and-fork
     path with attributable shared-prefix boundaries and exclusion replay. All necessary ranges,
     frontier objects, leaf preimages/bindings and two signed witnesses MUST survive with
     independent authentication under their respective roots; keeping only a newest head is
     insufficient. Bad or withheld proof MUST remain unverifiable/pending, not author
     equivocation. Known fork pairs and exclusion records remain permanently owned. Today the
     inclusion verifier needs a `VerifiedHeader` and the fork verifier two signed entries
     (`log/history.rs:1314-1338,1355-1382`; `log/dag.rs:132-170`), and that proof is lost when
     either header goes;
  5. *a removal's witnessed tip* (MP-6): the cut's exact position and hash proven by leaf and opening
     under the target's signed head;
  6. *a fully checked message cited by a control*: the control's parent receipt proven from the leaf
     under the parent author's signed head; today full admission asks for the exact header and
     receipt (`node/history_stream/admission.rs:875-944`; `log/history.rs:2171-2219`).
  Known fork pairs and exclusion records MUST never be expired away.
  *(Amended 2026-11-24, amendment 4, by the decider's ruling 12:)* MP-16 moves to v0.4.32, with MP-14; its form for v0.4.32 is to be re-decided then (`exec/deviations.md:180`). Until then the signatures stay, as ADR-036:371-373 says.
  - *Why*: ruling 7. The entry hash excludes the signature and a signed head commits the leaf
    (`log/history.rs:796-819`; `log/entry.rs:215-259`), so a kept leaf under a kept head proves an
    expired entry's place and fingerprint; a leaf cannot recover the skeleton's fields
    (`log/entry.rs:153-189`), which is why every consumer that reads them is changed first (review
    §4). The roughly 2 to 4 KB left per expired message is a target to measure and reduce, "a
    measurement target, not a justified universal bound".
  - *Proof*: one real-binary or adversarial real-wire-peer act per consumer, each green before
    deletion or activation. (1) Recover from a backup preceding an expired stretch; assert retained
    continuity/head, epoch/generation, complete controls, exact old-boundary consistency, append
    forest and sequence/ratchet high-water marks, every live body/key recovered, no skipped
    control, no sequence reset or header wait, and the next post accepted by every member. (2) Page
    an expired stretch across restart; assert authenticated facts separately from holder reports,
    resumable cursor/range/order progress, no recreated text, spin or corruption error, no
    control/legacy Session misclassification, and continued demand to another holder that retains
    a copy. (3) Return with an older anchor through a restarted sparse holder; verify the exact
    consistency link and all advertised openings, with no anchor rollback and pending rather than
    success for an unprovable link. (4) Prove unequal signed histories inside an expired stretch
    using retained ranges/frontiers/preimages/bindings and two signed witnesses; replay exclusions
    after restart; retain previously known fork/exclusion evidence through expiry; corrupt or
    withheld proof yields pending, not a fork verdict. (5) Verify the removal's exact witnessed
    position, hash and accepted branch through the leaf-backed cut after expiry and restart,
    rejecting a competing branch. (6) A newcomer fully validates a control citing an expired
    message through the equally strong leaf-backed parent evidence, without promoting a display
    receipt. Then run M1 and M2 of `store-opus.md` §5 for bytes per expired message and growth
    slope. For each consumer, omit its replacement or weaken one of its required authenticated
    facts; that consumer's act MUST turn red.

### Claims and the gate

- **MP-17. What Vox says matches what is proven (C9).** Release notes, status words and records
  MUST distinguish guarantees from unmeasured estimates. Specifically they MUST NOT say "by
  construction", "after one page", "needs about 18" or "sooner" of this design, and MUST NOT say
  "no new protocol"; they say instead: "no new signed live-entry format is required by the kind
  split; validation policy and local store/receipt representations change, and all room members
  upgrade together." No message needs another member's chat history, but its standing, keys and
  cuts still need complete served control evidence; that prerequisite is part of joining, and old
  history may still enlarge it. Ordinary controls also occur for key generations, presence and
  Session support and floors, not only "tens in a room's life" (`log/history.rs:60-97`). A
  creator-summary payload or a new expired-leaf proof representation is an explicit additional
  encoding and verification change, decided on its own. How soon a removal is applied at a busy
  member is an objective to measure, not a claim. Under M0 they also MUST NOT claim (M0 ruling §3, §6): that a message naming a parent in `seen` is an authenticated acknowledgement of what that parent acknowledged (it is not; a malicious author can be shown against an old view, which is the existing unaware-author window, not a new one, and once the removal is applied MP-6 and MP-11 govern); that a healthy member's message never waits on a slow member (it can, where the author's own controls, its inherited context, or a key package or consent grant cite that member); or that the busy room passes (that is measured by the journey, not proven by the ruling). *(Amended 2026-11-23 by the M0 ruling.)* Under P (MP-7) they also MUST NOT claim availability when every holder is behind the asked size: when n>|H| for every holder, P cannot manufacture bytes or evidence, and P is not an unconditional sixteen-direction liveness proof; H can avoid some poor initial anchors but cannot guarantee that a reader is never ahead of every holder (moving-head ruling §4). *(Amended 2026-11-23, amendment 3.)*
  - *Why*: review §5. The busy-room figures of the proposal's §2 are derived, not run.
  - *Proof*: the release notes and `vox status` words read against this list; the newcomer and
    removal waits of MP-7 (d) and MP-2 recorded as measurements.

- **MP-18. The release gate is unchanged.** v0.4.31 is released only when the busy-room journey
  (ADR-052 RG-1) is green in all sixteen directions, with the restart and update journey and the
  install journey, on the assets that ship, run by a verifier that wrote none of the changes
  (ADR-052 RG-15). Nothing in this ADR lowers that bar.
  - *Why*: ruling 1; review §1 ("The sixteen-direction release gate stays unchanged").
  - *Proof*: the three journeys, on the same retained binaries as the acts above.

## Order

The review's order (§3), not the proposal's. Commits MAY subdivide a step; behaviour is activated
only at the stated boundaries. **No binary built at any step may be less safe than today**: until
step 3, today's full admission gate stays active and wins. Same version does not remove captured
in-flight work, old persisted Complete and eligibility rows, historical entries or old and new
internal paths; each step handles them.

1. **Burst repair, with existing security unchanged** (MP-12). #1385 lands; permanent missing
   intervals, finite per-peer response work and holder-local `BodyNotHeld` handling complete it.
   With one version per room (ruling 4) no old-server compatibility state machine is built.
   *The work may pause here.*
2. **The security prerequisites, while today's full validation stays active** (MP-6's reserved tip
   and narrow cut with exact cut proofs, MP-9, MP-7, MP-8 and MP-8a's durable serveable control
   evidence and linked serving, MP-10, MP-11's disappearance of messages later proven not
   acceptable, together with MP-6, and per-sender bootstrap; and the map of every consumer of the
   one validator that MP-3's types will split). The adversarial acts of MP-1, MP-2,
   MP-3, MP-6, MP-7, MP-8a, MP-9, MP-10 (including the hidden-termination act) and MP-11 MUST be
   green here before any admission check is weakened. Every prerequisite named in this step MUST be
   implemented and proven, not merely listed as an open question or left unexercised by these
   acts. Complete control serviceability is not put after step 4's claims.
   *The work may pause here: the old gate still wins.* *(Amended 2026-11-23, amendment 3:)* step 2 also carries MP-9a (the forked target's fork-parent evidence path, with MP-6's branch cut and MP-11, before the reader switch; forked-target ruling §4) and MP-7's prefix serving P, built first as a serving-only change against the old full admission gate, its focused acts proven before any journey improvement is attributed to it (moving-head ruling §4). Their acts join the acts above that MUST be green before any admission check is weakened. #1387 (MP-7's holder side as first ruled: a member serves the membership proof it verified, across its own linked heads) is merged (`29b808afa`); P generalises its serving rule from linked heads to any authenticated prefix the holder holds.
   *(Amended 2026-11-23: the coordinating session's engineering decisions, `exec/deviations.md`
   "Engineering decisions on 2026-11-23 while building ADR-053's step 2"; not the decider's ruling
   and not the review's.)* (a) MP-3's separate display and cut receipt types move from this step
   to the first change of step 3: in this step nothing produces a display receipt (today's full
   check admits everything), so the types would be dead code, and adding them means restructuring
   the one validator four other slices are touching here. They are built together with their
   producer and before the reader policy is switched, so the guard exists before any check is
   weakened; this step delivers the consumer map (`mp/tokens/consumer-map.raw.md`). (b) MP-11
   lands only together with MP-6. Measured on the real binary (`mp/tokens/runs/mp11-change-green.log`):
   today's cut for a removed member falls at its last control entry, which is written before each
   post, so the target's last witnessed posts are outside the cut; MP-11 alone would take them
   from readers that had shown them. In the coordinating session's reading, landing MP-11 in step 2 together with MP-6 means it is already in place when step 3 switches the reader policy on, which is what the head-mismatch ruling's "must accompany that policy" requires; it is the decider's decided behaviour ("disappears") and does not wait for step 3 because it weakens no check. *(Amended 2026-11-23 by the M0 ruling: note (a) is superseded, since no display or cut receipt type is built (MP-3); the consumer map stays as documentation with its policy assumptions corrected (M0 ruling §4). Step 2's prerequisites are otherwise unchanged, and all of them and their acts bind before step 3 (M0 ruling §4, last paragraph).)*
3. **The new writer and reader policy, activated together** (MP-1 to MP-5 as amended by the M0
   ruling). Binding form (M0 ruling §7, rule 5): "**Upgrade and activation MUST** retain old strong row meanings and full-context effects, safely decode/finish or restage captured old verifier work without losing exact obligations, and switch the writer and reader together after G and all Order-step-2 security prerequisites/acts are in place. Head selection MUST remain non-starving scheduling, not a holder veto. MP-6/MP-11 and the unchanged release journey remain mandatory."
   G is the ruling's guard (MP-3's rule 2: `contains_cut` bypasses its entire Content `seen` loop, and hint-graph ancestry is never an authority predicate). No display or cut receipt type is built and no eligibility, source or display data is migrated; captured format-1 verifier checkpoints stay decodable and either finish their stronger checks or restart from a safe phase with exact obligations kept (M0 ruling §4).
   Acts (M0 ruling §5): old format-1 verifier checkpoints and an upgrade's first post; both writer routes; a room with more than sixteen authors; skewed-clock question and reply with unknown hints nonblocking; the `two` relay and slow-member acts; feed growth near one entry per post; and the unchanged sixteen-direction journey.
   Old valid causal sources stay valid, and stale work is fenced at the existing publication and
   generation boundaries. No cluster agreement service and no second permanent protocol is built. Head choice here is MP-8a's H: scheduling preference only, never a holder veto. *(Amended 2026-11-23, amendment 3.)*
   *(Amended 2026-11-23 by the M0 ruling of gpt-6.1-sol, which replaces the accepted step 3 ("its first change being MP-3's distinct display and cut receipt types with their producer … display-only hints; effect-scoped message admission; no promotion of lightweight data to causal Complete. Derived cuts and eligibility are rebuilt or versioned before use"); the earlier text stays in the git history.)*
4. **Delete the obsolete machinery and prove the product** (MP-13; the proofs of MP-1 to MP-12;
   MP-18's busy-room journey in all sixteen directions; MP-7 (d)'s newcomer in a copy of the
   decider's real rooms, measured). A creator summary is not built unless that measurement shows
   it is needed; then the decider is asked (ruling 9), and only on his yes is it added here.
5. **Storage**: stage 1 and its conversion (MP-14), preserving every existing evidence meaning;
   then stage 2 (MP-16): each consumer's leaf-backed replacement with its act first, and the
   leaf-only form switched on only when all six are green. The release journeys are finished on
   the same retained binaries. A safe intermediate slice MAY be kept, but the release does not
   stop short of MP-18.

MP-15 changes no evidence the sync reads and waits for none of steps 1 to 4; it lands when its own
proof is in. MP-17 applies to every step's notes.
*(Amended 2026-11-24, amendment 4, on the decider's rulings 12 and 13:)* Steps 1, 2 and 4 assumed today's fetching machinery; ADR-054 is to replace it with one pull loop per connection, and the parked rules of step 4 (MP-13) do not land. MP-7's prefix serving P, built first in step 2, stays (#1394, merged: `exec/review-audit.md:42`); ADR-054's page experiment served through it unchanged (`design/simple-sync/experiment.md:26`). MP-6 and MP-11 have landed (#1393). Step 5 moves to v0.4.32 (MP-14, MP-16); MP-15 has landed (#1391). MP-18 is unchanged.

## What does not change, and what a person is told

**Unchanged:** only members read: keys go only to trusted members; trust is forward-only and a
readmission starts a fresh chain (ADR-007:299); a removed member's later writes are refused; nobody
can forge or reorder another member's messages (signature, per-author chain, inclusion); retention
removes bodies when they expire; the governance evaluator and today's full check for every control
kind; key rotation; the busy-room gate.

**What a person is told:**
- *The unaware-partition window stays.* A removal that has not reached a sender yet cannot stop
  that sender; no peer-to-peer design can (ADR-007:286-287, :372; `proposal.md:96`). What closes is
  the worse case of reading the post-removal room while still sealing to the removed member (MP-2). Under M0, a message naming another member's post in `seen` is not an authenticated acknowledgement of what that post acknowledged: an author that never put a removal into its own state can be shown against a reader's old view. That is the existing unaware-author window, not a new one; once the reader applies the removal, MP-6 and MP-11 govern (M0 ruling §3). *(Amended 2026-11-23.)*
- *A split view is found when views meet.* Today a third member's message that cites a forker
  forces the comparison before that message is shown; under this design a fork is found when two
  members, or a holder between them, compare that author's heads (MP-9), possibly later than today.
  A refused or bad proof is not reported as a fork.
- *A removal keeps what the remover witnessed.* Posts of the removed member up to the tip the
  remover held stay; posts concurrent with the removal and outside that prefix are not shown
  (MP-6), as today. *A member that splits its own history is still removed* on members who saw its other version: they record its fork, apply the removal from the remover's exact branch evidence and keep only its messages the remover witnessed; until that evidence arrives they name the remover as waiting and do not claim the removal applied (MP-9a; ruling 10). *(Amended 2026-11-23, amendment 3.)*
- *A sender whose membership evidence has not arrived is named as waiting*; the room's other
  messages are shown (MP-1). *A healthy member's message can still wait on a slow member* where the author's own controls, its inherited context, or a key package or consent grant cite that member; whether the busy room passes is measured by the journey, not proven by the ruling (M0 ruling §6). *(Amended 2026-11-23.)*
- *A message later proven not acceptable disappears.* When a removal or a fork reaches a member,
  that member's view drops the messages it shows of the removed author outside the cut, or of the
  rejected branch, so every member ends with the same room; what a person already read stays read
  (MP-11).
- *A message posted just before its author was removed, which the remover had not received, is gone
  for everyone, its author included, when the author is readmitted* (MP-6, MP-11; #1393): the
  coordinating session's engineering decision of 2026-11-24 following ruling 8
  (`exec/deviations.md:193`); the decider's own words on the author's copy are not recorded (MP-6's
  amendment 4). If the removal is overturned, the messages it
  took come back in their place and arrive again (MP-11). *(Amended 2026-11-24, amendment 4.)*
- *A removed member running altered software can have one private Session step taken by a member
  that was offline for the removal*; the release notes draft names it (`release/notes-draft.md:108`;
  ruling 11; MP-10). *(Amended 2026-11-24, amendment 4.)*
- *An expired ordinary message leaves its chain fingerprint on a node that has applied MP-16.*
  Once its conditions are proven and that node retires the header/skeleton, it no longer supplies
  the discarded sender/time/length metadata; another member may retain an old copy. Permanently
  owned fork/exclusion evidence is not expired, and rooms kept for ever keep everything.
  *(Amended 2026-11-24, amendment 4: MP-16 moves to v0.4.32, ruling 12.)*
- *Every computer in a room updates together* (ruling 4); the release notes say so.

## Consequences

- The cross-member gate on each message's `seen` goes, and with it the reason for the sixteen
  scheduling rules; a slow member's evidence is still needed where the author's own controls, its
  inherited context, a key package or a control cite it, which holders serve (MP-7). *(Amended 2026-11-23 by the M0 ruling §6.)*
- Controls are not made cheaper by this ADR: applying one still needs its full closure (MP-8). In
  old rooms the governing feeds carry long histories of per-post control entries written before
  this change; whether a newcomer meets the experience there is measured on a copy of the
  decider's real rooms (MP-7 (d)); a creator summary is not built unless that shows it is needed,
  and then the decider is asked (ruling 9).
- Feeds grow one entry per post instead of two (MP-4); each signed header is stored once (MP-14);
  after expiry only the leaf stays (MP-16), once all six of its consumers have their replacements.
  Recovery from a backup and paging change so that they read no expired header.
  *(Amended 2026-11-24, amendment 4: MP-14 and MP-16 move to v0.4.32, ruling 12; fetching is to
  be ADR-054's, which is to delete the hint inbox and routed flows instead of adding scheduling
  rules; nothing of it has landed.)*
- Shown messages can now disappear after a removal or fork (MP-11): a change of behaviour from
  today, chosen by the decider so the room looks the same to every member.
- The give-back pass runs on the events that free space, not on a clock. The record reads this as
  meeting ruling 3's "periodically while vox is running" through those events.
- No new stored meaning for messages is added (amendment 2 withdrew the display and cut receipts); a
  changed receipt format is added (MP-14), which RG-0 permits because MP-14 cannot be met without it. *(Amended 2026-11-23.)*

## What this ADR supersedes and amends

- **ADR-036:81-86**, "For a new entry, verify a receipt for its own immediately preceding prefix
  and each explicit `seen` parent, using H-3's derived receipt. The entry's signed pre-entry context
  MUST dominate their joined prefix frontiers … Each cited position requires complete control
  verification up to that position": for Content, amended by MP-1 and MP-5. The own-prefix receipt
  and domination stay; `seen` parents of Content need no receipt and are display hints. Control
  kinds keep the sentence as written.
- **ADR-036:90**, "Changed contexts MUST precede content as control records.": stands; MP-4 stops
  the per-post changes that made it fire before nearly every post.
- **ADR-036:219-222**, "at most 128 entries per logical page and 1 MiB of archive wire work per
  request/continuation response, with at most two archive transfers across the daemon and one for
  a node": the page and byte budgets stand; the node-wide transfer slots are replaced by one request
  per peer and room and the byte cap (MP-13 item 4).
- **ADR-036:371-373**, "Retain those signatures even after body retention: a later live entry may
  require an exact receipt for any earlier content parent. Otherwise dropping a content signature
  could make the required parent evidence unavailable.": replaced by MP-16 (ruling 7): after expiry
  a content entry keeps only its leaf, in rooms whose retention is not for ever. Until MP-16's six
  replacements are proven and the form is switched on, signatures stay as that sentence says,
  enforced at `log/entry.rs:595-600`.
- **ADR-036:576-578**, "Every author's control entries from position 1 up to its known size MUST be
  fetched as one set, by control proof, with a bounded share of each peer's exchanges so that no
  author's bodies wait on another author's control backlog": what a message's display waits on is
  MP-1, MP-2 and MP-7; it waits on no other author's control backlog beyond the governing effects
  its own prefix exposes. Whether a reader still closes each author's own control history from
  position 1 before showing that author's messages is open question B-1.
- **ADR-036:185-186**, "Retain the raw signed heads, entries and authenticated openings needed to
  distinguish an author's malformed commitment from a bad relay response.": stands, extended by
  MP-9.
- **ADR-046** (superseded for v0.4.31 by ADR-052; kept as the record): **:1274**, SY-3 "Admitting
  an entry needs only its author's signature and chain", is not adopted in that form; MP-1 is the
  rule. **:497-499**, the fence post ("a governance checkpoint on the room, signed by the
  creator"), is not built unless the measurement of MP-7 (d) shows it is needed and the decider
  then says yes (ruling 9). **:475**, `ContextUpdate` "≈ 21 % of every entry", growing with
  messages: ended for new entries by MP-4.
- **ADR-047** (superseded for v0.4.31 by ADR-052): **:76** and **:1434-1437**, SO-10, compaction
  "runs at daemon start and on `vox node compact`, and nowhere else": replaced by MP-15.
  **:3033**, proof records "nothing: every range is derivable from headers … delete": not for
  control verification closures, which MP-7 keeps. **:3037**, validated headers "keep" for the
  "life of the entry": replaced for expired content by MP-16 (the leaf stays, the header goes).
  **:3039**, inclusion receipts "delete": replaced by MP-14 (kept, pointing at the `Header`
  object, until MP-16 retires them for expired content).
- **ADR-052 RG-0 (:139-144)**, "A change MUST remove a reproduced cause, and MUST be the smallest
  change that removes it. … One requirement carries one reproduced cause": for sync and storage,
  amended by ruling 2: this ADR is one design fix that removes the mechanisms behind several
  reproduced causes (Context properties 1 to 3, ledger 66, disk), in place of one cause per task.
  KISS stands, and so does RG-0's ban on a new registry, protocol, store format, ledger, journal,
  scheduler or framework unless a requirement cannot be met without it.
- **ADR-052 RG-5 (:231-233)**, "If neither passes, nothing is built on sync: the first step the
  timeline shows missing is the next cause, and the decider is told.": neither passed
  (`rg-5/measurements.md:12`); the sync is built by this ADR's Order. RG-6's text (:238-242) stands
  as what a person gets, and its proofs stay; "Whichever method is built" is this one.
- **ADR-052 RG-13 (:363)**, "fetching writes no proof rows (an in-memory cache of at most 8 MiB,
  ADR-044 Q2)": already narrowed by deviation 21 (proof pieces owned by a held receipt are saved,
  #1384); deviation 21's "rebuilt or repaired ranges and control proofs leave nothing behind" is
  further narrowed by MP-7: the verification closure of a control this node published or adopted
  is owned durably. Fetching to serve a request still writes nothing. **RG-13 (:365)**, "a store
  with more than twice the space it uses is compacted at daemon start": replaced by MP-15 (and
  deviation 17 with it). RG-13's "A store grows with what it holds" is met by MP-14 to MP-16.
  *(Amended 2026-11-24, amendment 4: with MP-14 and MP-16 moved to v0.4.32 by ruling 12, RG-13 is
  closed as completed, Release ready (`exec/awa/receipt-integrate-1327.json`), with MP-15 (#1391)
  and the limits its audit lists, `rg-13/close/requirement-audit.md`.)*
- **ADR-052 RG-1 and RG-15** stand unchanged (MP-18).
- **ADR-053's own Order and MP-13**: the fetching machinery they assumed is to be replaced by
  **ADR-054**, which amends this record by reference; nothing of ADR-054 has landed. *(Amended
  2026-11-24, amendment 4.)*

## The decider's answers to the review's product questions

Put to him on 2026-11-23 by the coordinating session.

1. **After a message's text expires, what stays?** DECIDED: only what the chain needs. His first
   answer: "lol -- if the text is gone, wtf cares -- why are we still keeping it -- explain that
   part?"; after the explanation he chose "keep only what the chain needs, and change recovery and
   paging so they need nothing more." For a person: once a message's text has expired and a node
   has retired its header/skeleton under MP-16's proven conditions, that node
   no longer supplies the discarded sender/time/length metadata; another member may retain an old
   copy. The retained signed roots and authenticated evidence preserve fork detection when honest
   views meet. Known fork/exclusion evidence remains permanently owned, and rooms set to keep
   messages for ever keep everything. Carried by MP-16, with C7 and C8 as its conditions.
2. **A post already shown and later proven not acceptable (a removal or a fork)?** DECIDED:
   "disappears". For a person: it leaves the conversation, so the room looks the same to every
   member; it never counts toward a membership decision or a key release; nothing can recall what
   was already read. Carried by MP-11.
3. **May a newcomer in an old busy room rely on the creator's signed summary of past membership
   decisions?** NOT DECIDED and not asked: deferred until a newcomer joining a copy of the
   decider's real rooms has been measured after the redesign (MP-7 (d)). The summary is not built
   unless measured to be needed; then the decider is asked, because it means trusting the
   creator's account of the past.

## Open questions for the builders

- **B-1. The control closure (C5, MP-8).** In the review's words: "Either retain and transfer that
  entire required closure, or explicitly specify a narrower **effect-specific** control projection
  whose omitted coordinates never enter authority/cuts/authoring." The first binds until a
  projection is specified and reviewed. Inside the same question: whether a reader still closes an
  author's own control history from position 1 before showing that author's messages, or only the
  governing effects its prefix exposes plus that author's own per-sender facts (ADR-036:576-578). *(Amended 2026-11-23 by the M0 ruling: still open, and no longer on this release's path. M0 keeps today's full own-prefix and coordinate validation for messages (MP-1), so no narrower projection is needed for v0.4.31.)*
- **B-2. The smallest check of "what the author had acknowledged" for old entries and legacy
  Session carriers** (review §7: "The strongest remaining design obligation is an exact
  effect-scoped control projection for old entries—not a new timer"; `sync-sol-on-m1.md` §7). *(Amended 2026-11-23 by the M0 ruling: still open, and no longer on this release's path, for the same reason as B-1.)*
- **B-3. Old busy rooms.** Whether the governing feeds' old per-post control entries make a
  newcomer's bootstrap, measured on a copy of the decider's real rooms, exceed the required
  experience (MP-7 (d)); only then is question 3 put to him.
- **B-4. Stage 2's authenticated facts.** With the leaf-only form, an expired position's
  authenticated facts are its position, entry hash, control bit and frontier under a signed head;
  everything else about it is this holder's report. The paging answer and the recovery path
  (MP-16 items 1 and 2) are to state exactly which they return as which (review §4).
- **B-5. The hidden-termination gap.** The review would close it "using author-local evidence"; the
  check is not specified (MP-10).
- **B-6. Per-sender bootstrap.** Step 2 names "sender-specific bootstrap" without its shape: how a
  newcomer obtains each sender's own control state and packages with per-sender pending status
  (MP-7).
- **B-7. MP-15's open points** (`rg-13/follows/report.md`): whether the startup-work notice and its
  restart act stay, decided by the measured pause; private Session step expiry has no give-back
  trigger; a move that finds no lower free page grows the file once before it stops.
- **B-8. #1385's limits**: several readers catching up deep each hold one of the 64 node-wide Live
  grants (its verdict's P3-a); a restart with a re-walk jump pending was not run by hand.
- **B-9. Conversion**: 12 of 8,843 pruned log tails differ from their `Header` object, unexplained
  (`store-opus.md:72`); MP-14 keeps them; the cause is to be traced.
- **B-10. Resolved 2026-11-23: evidence under an older signed head.** How a reader uses an
  author's evidence that a holder can serve only under an older signed head of that author, when
  the reader already holds a newer one. Ruled by gpt-6.1-sol (`design/head-mismatch/ruling.md`,
  question in `question.md` beside it): continuity before authority. Written into MP-7 (rules 4
  and 5, and proof (a)), MP-8a (rules 1 to 3) and MP-9 (rules 6 and 7). *(Amended 2026-11-23, amendment 3: rule 5 is replaced in MP-7 by the moving-head ruling §3, and rule 4 gains its addition.)*

## C1 to C9 and the security findings, by requirement

| Source item | Requirement |
|---|---|
| C1 (lightweight admission; own preceding prefix) | MP-1 |
| C2 (acknowledged governing effects; fences) | MP-2 |
| C3 (shown and citable; as amended by the M0 ruling, a message is a full source and its `seen` are hints) | MP-3 |
| C4 (reserved `seen` slot; narrow branch-aware cut) | MP-6 |
| C5 (durable serveable control evidence; governing set) | MP-7 |
| C5 (the "full proof of everything it cites" contradiction) | MP-8, B-1 |
| C5 and C6 (evidence under another signed head; the head-mismatch ruling) | MP-7, MP-8a, MP-9 |
| C6 (all-author, unequal-size fork detection) | MP-9 |
| C6 section, point 8 (`seen` as display hints) | MP-5 |
| C6 section, point 5 (recipient, package, private boundaries) | MP-10 |
| C7 (expired-header dependency statement) | MP-16 |
| C8 (stage-2 rule) | MP-16 |
| C9 (claims and format scope; "sooner") | MP-17 |
| C9 section (later-invalidated rows; decided "disappears") | MP-11 |
| C9 section (online give-back evidence) | MP-15 |
| Review §3 step 1, step 3 writer policy | MP-12, MP-4 |
| Review §4 (stage-2 consumers: recovery, paging, return, fork) | MP-16 |
| Review §6 question 1 (decided: leaf only) | MP-16 |
| Review §6 question 2 (decided: disappears) | MP-11 |
| Review §6 question 3 (deferred to a measurement) | MP-7 (d), B-3 |
| Review §6 (undecidable plaintext held) | MP-1, MP-2 |
| P1-A forged readmission, store errors | MP-1 |
| P1-A poisoned tip | MP-3 |
| P1-A(b), as corrected by C1 | MP-1 |
| P1-B (reader behind on governance) | MP-2, MP-7 |
| P1-C (order) | MP-5 |
| P2-D (removal against concurrent posts; the smaller form) | MP-6 |
| P2-E (fork opening, corrected) | MP-9 |
| P2, newcomer: the governing set; the self-contradiction | MP-7, MP-8 |
| P3: creator-fork edge | MP-6 |
| P3: Session floors; termination | MP-10, B-5 |
| P3: stale consent display; key-package standing checks | MP-7, MP-10 |
| The M0 ruling (`design/step3-m0-ruling.md`; rules 1 to 5, the amendments to MP-1, MP-2 and MP-3, what M0 does not promise) | MP-1, MP-2, MP-3, MP-4, MP-5, MP-13, MP-17, Order step 3, B-1, B-2 |
| The forked-target ruling (`design/forked-target/ruling.md`; rules 1 to 8, the decider's ruling 10, ledger 73) | MP-9a (rules 1 to 6, 8), MP-6 (rule 7), MP-8, Order step 2 |
| The moving-head ruling (`design/moving-head/ruling.md`; P rules 1 to 7, the amendment of head-mismatch rules 4 and 5, H, W not approved) | MP-7, MP-8a, MP-17, Order steps 2 and 3 |
| The acknowledgement ruling (`design/busy-room/ack-ruling.md`; M0 rule 4 narrowed) *(amendment 4)* | MP-4 |
| The control-closure ruling (`design/busy-room/control-closure-ruling.md`) *(amendment 4)* | MP-7 |
| The return ruling on #1393 (`mp/cut-disappear/ruling-n.md`) *(amendment 4)* | MP-11 |
| The decider's rulings 11 to 13 (2026-11-23 and 2026-11-24) *(amendment 4)* | MP-10; MP-14, MP-15, MP-16; MP-13, the Order, ADR-054 |

## Links

- ADR-007 (G-29 to G-32), ADR-018, ADR-036, ADR-046, ADR-047, ADR-052.
- In `/opt/vox-evidence/v0431/`: `exec/deviations.md` (17, 21, and the owner's answers of
  2026-11-22 and 2026-11-23); `design/proposal.md`, `proposal-review-sol.md`, `m1-security.md`,
  `sync-sol-on-m1.md`, `sync-opus.md`, `sync-glm.md`, `sync-sol.md`, `store-opus.md`,
  `brief-sync.md`, `brief-store.md`; `rg-5/measurements.md`; `rg-6/sync-land/report.md`;
  `rg-6/witness/`; `rg-13/checkpoint/report.md`, `rg-13/running-growth/report.md`,
  `rg-13/follows/report.md`; `found-reds/burst-gap/small/report.md` and `verdict.md` (#1385).
- Added by amendment 4: ADR-054; `exec/deviations.md` (the owner's answers of 2026-11-23, late
  afternoon, and 2026-11-24); `design/amendment-4-draft.md`; `design/busy-room/ack-ruling.md`;
  `design/busy-room/control-closure-ruling.md`; `mp/cut-disappear/ruling-n.md` and
  `fix6/pr-body.md` (#1393); `rg-13/follows/fix4/pr-body.md` (#1391);
  `rg-13/close/requirement-audit.md`; `exec/awa/receipt-integrate-1327.json`;
  `exec/review-audit.md`; `exec/found-reds.md`; `m0/land/report.md`; `mp/fork/rebase3/report.md`; `design/simple-sync/`
  (ADR-054's sources); `release/notes-draft.md`.
