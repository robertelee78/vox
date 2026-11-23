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
  from decision status.
- **Date**: 2026-11-23
- **Deciders**: Robert E. Lee
- **Tags**: sync, admission, governance, removal, fork detection, store, retention, compaction,
  KISS, release
- **Amends**: ADR-036 (H-2, H-4, the v2 signature-retention sentence), ADR-052 (RG-0, RG-5,
  RG-13); records against ADR-046 and ADR-047, both already superseded for v0.4.31 by ADR-052,
  which of their lines this decision overtakes. The exact lines are under "What this ADR
  supersedes and amends".
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
9. **The creator's signed summary for old busy rooms is not decided and was not asked** (the
   review's question 3): it is deferred until a newcomer joining a copy of the decider's real rooms
   has been measured after the redesign. It is not built unless measured to be needed; then the
   decider is asked, because it means trusting the creator's account of the past.

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

## Terms

- **Display receipt**: what a node records when a message passes MP-1 and MP-2. It lets the
  message be shown, and nothing else (MP-3).
- **Cut receipt**: the record of the exact eligibility facts a removal or readmission cut needs
  about one message (MP-3, MP-6).
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
shown this way is never, by being shown, evidence for a trust or membership change.

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
  `node/channel/governance/member_fold.rs:282-343`).
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
  weakened to consulting a last-good display view.
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

- **MP-3. Shown is not citable (C3).** "A display receipt cannot construct `ValidatedSparseEntry`,
  set causal/control Complete, raise an authority frontier, advance a control-ready prefix, become
  an authoring settled tip, or install key/Session effects. A separate cut receipt supplies only
  the exact eligibility facts it proves. Full validation is required before promotion to a causal
  source; already-valid old sources retain their stronger status." The three meanings MUST be
  distinct tokens and distinct stored meanings, not one "validated" boolean with a branch around
  its verifier. Old or malformed entries MUST NOT gain authority through the display path; derived
  cuts and eligibility rows written under the old meaning MUST be rebuilt or versioned before the
  new policy uses them.
  - *Why*: publication today requires the stronger token and installs its context and authority
    obligation (`node/channel/entry_store/sparse.rs:2107-2129,2200-2209`); authoring consumes
    settled tips and their prefix frontiers (`node/channel/local_history.rs:493-542`). A message
    shown on lighter checks and then cited by the next honest control writer would launder a
    made-up coordinate into that control: the *poisoned tip* (`m1-security.md` P1-A), after which
    the room can remove nobody.
  - *Proof*: *the poisoned tip*. A real wire peer member signs one message whose context holds a
    made-up coordinate; the creator then removes another member. Every reader applies that removal,
    and the creator's later controls validate. Mutant: let a display receipt become a settled tip.

- **MP-4. A writer advances its signed context only for real control and cut changes.** A message
  MUST carry its author's preceding context plus the required governance ancestors (the room cut,
  ADR-007:300); a writer MUST NOT write an artificial control entry before each post merely to
  absorb other authors' tips. A writer MUST still advance its context, by a control entry before
  the message, whenever a genuine control or cut it has applied changes (ADR-036:90-93).
  - *Why*: today `authored_context` joins every other author's settled tip
    (`node/channel/local_history.rs:493-542`), so in a busy room `append_text` writes a
    `ContextUpdate` before nearly every post (`node/channel/pending_text.rs:939-957`): two signed
    entries per post, 21 % of a heavy author's entries (ADR-046:475). Skipping a genuine advance
    would let an old-rule reader path refuse legitimate messages and would move the removal cut
    (review §3).
  - *Proof*: in the busy-room journey each author's feed grows about one entry per post, read from
    the stores. ADR-007's removed-member act (ADR-007:410) stays green. Mutant: write the
    per-post carrier again (feed grows two per post).

- **MP-5. `seen` stays, as nonblocking display hints outside authority.** A message SHOULD name
  recent tips in its signed `seen` field (at most sixteen, `log/entry.rs:65-67`). A reader MUST use
  them only for display order: a hint MUST NOT need a receipt, MUST NOT gate text, MUST NOT be
  fetched for admission, and MUST NOT raise or poison a control frontier. The display clock's
  current behaviour (parents from `seen`, context and own predecessor; claimed time clamped to a
  parent-derived bound) MUST be preserved (`node/channel/entry_store/dag_facts.rs:524-557,603-678`).
  - *Why*: without fresh parents a message's clock is capped at its own previous entry plus ten
    minutes, so a member who posts after a pause is shown in the past and a reply can sort before
    its question (`m1-security.md` P1-C). "No reordering … unchanged" is true only if this is kept
    (review §1).
  - *Proof*: two members on skewed clocks; one posts after a pause of more than ten minutes and the
    other replies at once; every member shows the question before the reply. A message whose hints
    name an unknown tip is shown at once. Mutant: drop `seen` from messages.

- **MP-6. A removal cuts its target at the target's latest tip the remover holds, by a narrow
  branch-aware cut (C4).** "The removal explicitly reserves one of the sixteen signed `seen` slots
  for the target's latest authenticated held tip. Use its exact branch-bound position/hash only in
  the content-membership observation-cut test, including retained exclusionary removals on forks.
  Do not raise general authority Frontiers from display hints." The cut MUST keep (author,
  position, hash and accepted branch), never a bare `max(seq)`; known-fork rejection, inclusion and
  consistency stay enforced. That tip MUST pass the exact receipt and branch checks of a causal
  source; being displayable MUST NOT satisfy them. "Earlier messages stay" means messages in the
  remover's witnessed accepted prefix, not every message that came earlier in wall time.
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
    compare positions only.

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
  - *Why*: #1384 keeps inclusion and consistency witnesses but leaves `ControlRange` pieces
    cache-only (`node/history_stream/admission.rs:439-462,558-597`): a locally completed verdict is
    not a transferable proof, and "members hold the governing controls" does not mean they can
    serve their proof under the needed roots (review §2 on P1-B). A since-revoked admin's earlier
    removals still stand, so closing only today's admins lets a newcomer treat a removed member as
    present (`m1-security.md` §4). Consent and reset decide rendering
    (`node/channel/governance/view.rs:169-220`); private readiness needs per-author control coverage
    (`node/channel/private_session/pending_upgrade.rs:2327-2367`).
  - *Proof*: (a) *the stopped author with the holder restarted and a misleading newer head first*:
    an author stops; a holder that verified its controls restarts; a peer offers the newcomer a
    newer signed head of that author first; the newcomer verifies the author's governing evidence
    from the holder alone and shows the holder's posts (extends the act of `rg-6/witness/`, green on
    v0.4.30, red on `403218281`). Mutant: keep control-range pieces cache-only. (b) *Revoked admin*:
    an admin removes a member, then the creator revokes that admin; a newcomer joining after both
    treats the member as removed, releases it no key and shows none of its later posts; an act of
    the admin after its revocation has no effect. Mutant: close only current admins. (c)
    *Non-admin controls*: a non-admin revokes its consent toward a member, and a second non-admin's
    consent is withheld; the first takes effect, and only the second sender's messages wait for the
    newcomer. (d) *A newcomer in old long histories*: a copy of a room grown by v0.4.30 or main
    with long governing feeds (the decider's real rooms among them); the newcomer joins with the
    creator and a long-history member stopped, and shows the others' recent posts; its wait is
    measured and recorded, not promised (MP-17). This measurement decides whether ruling 9's
    question is put to the decider.

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
  authority, cuts or authoring.
  - *Why*: the proposal the decider read says controls keep "full proof of everything it cites, as
    today" (`proposal.md:19`); the first alternative is today's behaviour, so it adds no new
    validator.
  - *Proof*: MP-7 (c) and (d), and MP-6 (a), green with the first alternative.

- **MP-9. A member's split view is detectable across all authors and unequal sizes (C6).** Nodes
  MUST "Propagate all-author signed head observations through honest holders; retain unequal-size
  competing observations and request authenticated overlapping openings/prefix evidence when
  continuity cannot be established. Extract a contradiction under the signed roots; refusal or a bad
  relay proof is only unverifiable/pending. Preserve known fork/exclusion evidence permanently."
  The queried overlap position MUST fit both heads, and header or opening evidence MUST authenticate
  both sides under their own roots; where heads disagree about an earlier prefix although a
  terminal header matches, prefix or range evidence is compared. Withholding is not a proved fork.
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
    pending, never a fork verdict. Mutant: keep only equal-size conflicts.

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
  ADR-007:299-300).
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
  acts kept green (line numbers in `sync-land`; `sync-opus.md` §2; `sync-glm.md` §2):
  1. *The per-post tip join for Content*: the join of every other author's settled tip into a
     message's context (`node/channel/local_history.rs:493-542`, for Content only; controls keep
     it). `append_text`'s context-advance path (`node/channel/pending_text.rs:939-957`) stays and
     fires only on real changes (MP-4).
  2. *Parent receipts for Content*: the Content branch of the parent-reference loop of
     `node/history_stream/admission.rs:875-944`, its preflight and the target helpers that only it
     uses. Control kinds keep them (MP-16's C7).
  3. *The control-closure gate before showing*: the live window's control closure
     (`node/history_stream/runtime.rs:1048`, `push_control_closure`, and the `LiveWindow`,
     `LiveRetry`, `LiveAdvance` operations from :2417), `select_/advance_/cover_history_live_window`
     (`node/channel/entry_store/sparse.rs:2678-2800`) as a gate, and per-head closure progress; the
     list of MP-12 replaces the window.
  4. *Node-wide singletons*: the `Live`, `Control` and `Archive` slots (`node/history_demand.rs:55-61`),
     the serve lanes including `try_serve` (`node/history_budget.rs:399`) and the Live refusal
     "live request is outside the bounded newest window" (`node/history_budget.rs:1088-1091`), and
     the server's newest-128 clause (`node/history_stream/server.rs:823`, removed by #1385). What
     stays: one request per peer and room at a time, and one byte cap per node as a memory bound.
  5. *Content's stored parent and per-post receipts* once MP-14 no longer writes them.
  The following disposition is the coordinating session's reading of ruling 2, not a separate
  ruling by the decider. **The parked candidate** (`rg-5/dep-first/full4.patch`;
  `rg-6/sync-land/report.md` §3) MUST NOT land as a stack: its rules 3.2, 3.3 and 3.6 to 3.17 (the
  share of four, redirect bound and rests, dependency-first, route-stays, wake-on-release,
  pull-back, hunks A to H) are not built. Rules 3.1
  (per-peer turns), 3.4 (the per-room save gate) and 3.5 (the lost-wake fix) each repair a defect of
  their own and MAY land, each as its own change with its own red (RG-0). The second-lane burst fix
  is not built.
  - *Why*: ruling 2; each deleted rule scheduled demand that the gate of Context property 1
    created.
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
  member is an objective to measure, not a claim.
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
2. **The security prerequisites, while today's full validation stays active** (MP-3's distinct
   tokens and stored meanings, MP-6's reserved tip and narrow cut with exact cut proofs, MP-9,
   MP-7 and MP-8's durable serveable control evidence, MP-10, MP-11's disappearance of messages
   later proven not acceptable, and per-sender bootstrap). The adversarial acts of MP-1, MP-2,
   MP-3, MP-6, MP-7, MP-9, MP-10 (including the hidden-termination act) and MP-11 MUST be green
   here before any admission check is weakened. Every prerequisite named in this step MUST be
   implemented and proven, not merely listed as an open question or left unexercised by these
   acts. Complete control serviceability is not put after step 4's claims.
   *The work may pause here: the old gate still wins.*
3. **The new writer and reader policy, activated together** (MP-1, MP-2, MP-4, MP-5): no
   artificial per-post carrier; still advance for real controls and cuts; display-only hints;
   effect-scoped message admission; no promotion of lightweight data to causal Complete. Derived
   cuts and eligibility are rebuilt or versioned before use, and stale work is fenced at the
   existing publication and generation boundaries. Old valid causal sources stay valid. No cluster
   agreement service and no second permanent protocol is built for the all-upgraded cohort.
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

## What does not change, and what a person is told

**Unchanged:** only members read: keys go only to trusted members; trust is forward-only and a
readmission starts a fresh chain (ADR-007:299); a removed member's later writes are refused; nobody
can forge or reorder another member's messages (signature, per-author chain, inclusion); retention
removes bodies when they expire; the governance evaluator and today's full check for every control
kind; key rotation; the busy-room gate.

**What a person is told:**
- *The unaware-partition window stays.* A removal that has not reached a sender yet cannot stop
  that sender; no peer-to-peer design can (ADR-007:286-287, :372; `proposal.md:96`). What closes is
  the worse case of reading the post-removal room while still sealing to the removed member (MP-2).
- *A split view is found when views meet.* Today a third member's message that cites a forker
  forces the comparison before that message is shown; under this design a fork is found when two
  members, or a holder between them, compare that author's heads (MP-9), possibly later than today.
  A refused or bad proof is not reported as a fork.
- *A removal keeps what the remover witnessed.* Posts of the removed member up to the tip the
  remover held stay; posts concurrent with the removal and outside that prefix are not shown
  (MP-6), as today.
- *A sender whose membership evidence has not arrived is named as waiting*; the room's other
  messages are shown (MP-1).
- *A message later proven not acceptable disappears.* When a removal or a fork reaches a member,
  that member's view drops the messages it shows of the removed author outside the cut, or of the
  rejected branch, so every member ends with the same room; what a person already read stays read
  (MP-11).
- *An expired ordinary message leaves its chain fingerprint on a node that has applied MP-16.*
  Once its conditions are proven and that node retires the header/skeleton, it no longer supplies
  the discarded sender/time/length metadata; another member may retain an old copy. Permanently
  owned fork/exclusion evidence is not expired, and rooms kept for ever keep everything.
- *Every computer in a room updates together* (ruling 4); the release notes say so.

## Consequences

- The cross-member gate on each message goes, and with it the reason for the sixteen scheduling
  rules; a slow member's evidence is needed only for that member's own messages and for controls
  that cite it, which holders serve (MP-7).
- Controls are not made cheaper by this ADR: applying one still needs its full closure (MP-8). In
  old rooms the governing feeds carry long histories of per-post control entries written before
  this change; whether a newcomer meets the experience there is measured on a copy of the
  decider's real rooms (MP-7 (d)); a creator summary is not built unless that shows it is needed,
  and then the decider is asked (ruling 9).
- Feeds grow one entry per post instead of two (MP-4); each signed header is stored once (MP-14);
  after expiry only the leaf stays (MP-16), once all six of its consumers have their replacements.
  Recovery from a backup and paging change so that they read no expired header.
- Shown messages can now disappear after a removal or fork (MP-11): a change of behaviour from
  today, chosen by the decider so the room looks the same to every member.
- The give-back pass runs on the events that free space, not on a clock. The record reads this as
  meeting ruling 3's "periodically while vox is running" through those events.
- New stored meanings (display, cut and source receipts) and a changed receipt format are added;
  RG-0 permits them because MP-3 and MP-14 cannot be met without them, and this record says why.

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
- **ADR-052 RG-1 and RG-15** stand unchanged (MP-18).

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
  governing effects its prefix exposes plus that author's own per-sender facts (ADR-036:576-578).
- **B-2. The smallest check of "what the author had acknowledged" for old entries and legacy
  Session carriers** (review §7: "The strongest remaining design obligation is an exact
  effect-scoped control projection for old entries—not a new timer"; `sync-sol-on-m1.md` §7).
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
- **B-10. OPEN, ruling pending: evidence under an older signed head.** How a reader uses an
  author's evidence that a holder can serve only under an older signed head of that author, when
  the reader already holds a newer one (MP-7's "a newer announcement never retargets that
  obligation" against MP-9's fork safety). The question is `design/head-mismatch/question.md`;
  the ruling is to appear at `design/head-mismatch/ruling.md` and is to be written into MP-7 and
  MP-9 as an amendment when it does. Until then MP-7 (a) and MP-9 bind as written.

## C1 to C9 and the security findings, by requirement

| Source item | Requirement |
|---|---|
| C1 (lightweight admission; own preceding prefix) | MP-1 |
| C2 (acknowledged governing effects; fences) | MP-2 |
| C3 (shown and citable; display, cut, source receipts) | MP-3 |
| C4 (reserved `seen` slot; narrow branch-aware cut) | MP-6 |
| C5 (durable serveable control evidence; governing set) | MP-7 |
| C5 (the "full proof of everything it cites" contradiction) | MP-8, B-1 |
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

## Links

- ADR-007 (G-29 to G-32), ADR-018, ADR-036, ADR-046, ADR-047, ADR-052.
- In `/opt/vox-evidence/v0431/`: `exec/deviations.md` (17, 21, and the owner's answers of
  2026-11-22 and 2026-11-23); `design/proposal.md`, `proposal-review-sol.md`, `m1-security.md`,
  `sync-sol-on-m1.md`, `sync-opus.md`, `sync-glm.md`, `sync-sol.md`, `store-opus.md`,
  `brief-sync.md`, `brief-store.md`; `rg-5/measurements.md`; `rg-6/sync-land/report.md`;
  `rg-6/witness/`; `rg-13/checkpoint/report.md`, `rg-13/running-growth/report.md`,
  `rg-13/follows/report.md`; `found-reds/burst-gap/small/report.md` and `verdict.md` (#1385).
