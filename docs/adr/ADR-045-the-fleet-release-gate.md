# ADR-045: A Release Is Gated on a Fleet That Matches Real Use

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13) as the design for v0.4.31; its acceptance measurements are owed: E-7 in the VM, E-9 (b) and (c), the corrected B3 run, and ADR-046's acceptance. The design passed review at revision 19 under the decider's ledger row 83 (`adr-045-sol-review-r19`: no P1; its three P2s are owed to task acceptance), under his authorization of 2026-11-13 ("post review can accept them too"); proposed 2026-11-12. Revision 19 (design passed at r18 `1e2bee466`; this revision folds in what the siblings and the decider settled since: ADR-044 r17's J3 and soak gate, every post within 5 s with p50/p99/max and the rest recorded and the v0.4.30 host baseline cited; ADR-051 r5's Terms, FG-2, FG-4, FG-11, FG-17, J11(e)–(g), J7(l), the Mach-O refusal retired; ADR-043 r17's CJ-17 as J9(i), J9(e)'s clause, J6(d′); E-9(a) MEASURED red on Linux and item 94; E-7's corpus wording and VM runner; ADR-047 r14's SO-12 wording; ADR-048's act 12 as J6(j); rows 82–82c, 83, 84, 86; ADR-050 TJ-10-A's count; the acceptance list with final sibling hashes). Revision 18 (the thirteenth review's P2: J5(i)'s arm 4d import brought to ADR-047 SO-12 revision 12: the unflushed suffix is five received entries with the Inventory held, the Session step is a ruled commit asserted apart, act 1-pre with its absence and re-send assertions and the captured-read mutant; frozen reference updated). Revision 17 (the twelfth review's two P2s: FG-5 authorizes and the manifest records SO-12 arm 4d's data-write fault run for the stale-handle rebuild mutant; J1(m4)'s over-limit act has its own mutant, a truncated summary). Revision 16 (the eleventh review's P2: SO-12 arm 4d's six acts named in J5(i) and their fault runs at both positions authorized in FG-5 with manifest and restoration records, no settlement waiter; J8 asserts RS-15's three lines by id; J1's fence-post arms on ADR-046 r10's terms, the 1 MiB limit and adoption as J1(m6); SY-21 re-pinned to r10). Revision 15 (A: FG-15 A-1 cites ADR-046 SY-21 at revision 9 by id and hash, no `Have` condition; B: ledger row 74, "one save, one trip": J5(h) withdrawn, every held-token, settlement and waiter wording removed, J5(i) keeps SO-12's arm 2 and what SO-12 still owns, FG-5's exception keeps RD-7 r14's injected `fsync` fault and drops 4b/4c, J3 records per-save flush time and writer queue depth and cites RD-2's post bound by id with no number). Revision 14 (five corrections of the r13 re-check: FG-15 A-1 owned by ADR-046 SY-21, non-green until qualified; J7(c″)'s errno per recorded profile; J11(a)/(b) silence after a successful install and RD-13 staged apart; FG-5 names arm 4c's fault runs; FG-6 separates the macOS Keychain from B's mandatory Linux keyring acts; J5(i) arm 4b's waiter wording after RD-7 r13). Revision 13 (the correction batch after the design passed at r12: the cross-asks targeting this ADR carried or refused by row; ADR-047 SO-12 arms 4b/4c and ADR-046 SY-27 imported by requirement id; revision pins dropped; FG-4's root-in-the-VM rule per ruling 69 with `Rootful: false` stated truly; the OS build in every receipt; Appendix A's kinds and mutants; J9(b)'s three rows; J3's sync-advance check and mutant runner; FG-12's 2-day departure; J10(d)/TR-14 remnants deleted; the test servers assigned to their owners). Revision 12 (seventh review R1: FG-4's two VM modes, the single-VM qualification restriction now in force and the full fleet pending his authorization of concurrent VMs, with the 8–10 h budget restated under both as UNVERIFIED; R2: SO-11 arm 1d as arm 2's contiguous feature-built continuation). Revision 11 (sixth review F1–F4: no demotion of J5(h); item 88 as J1(o); J1(m)/(n) pinned to SY-27 r5 with its 30 s / 20 % / 10 s and the fence post's additions; the feature-build exception scoped; the acceptance conditions and the host rules of row 66). Revision 10: ADR-047 r6's four J5(i) rows carried; R-13 confirmed (row 59); R-15 and R-16 (the replacement with chunked admission; the newcomer's intent) with J1(m)/(n); the receipts lost in the reboot of 2026-11-13 marked and the receipts rule moved out of `/tmp` with a host-restart rule; VM starts on hold. Revision 9: three corrections to J5(h) from ADR-044's author (mutant one's run, no v0.4.30 baseline red, the image inside the guest) and nothing else; revision 8 closed the contradictions and gaps the task cut (`v0431-tasks-ADR-045`) exposed (E-7/E-9 definitions and placement, J10(d) under ruling 22, sibling fleet acts carried as J1(k)/(l), J5(i), J7(b)/(j), J13's retention act, items 88–90 placed, rootful podman, the Linux baseline, item 59's holder, the bounds' publication order, the suites' budget, the dry run's host, the amendments' timing); revision 7 added J5(h) (ADR-044 r7's RD-7 arm four, the old waiter across recovery, blocking on the fleet by R-13) and nothing else; revision 6 recorded the decider's answers of 2026-11-13
  (ledger rows 27, 31, 32, 37–40, 49, 51, 52; R-11 to R-14; every former open question is
  answered; nothing the fifth review closed is changed); revision 5 after the fourth independent review
  (`adr-045-sol-review-4`, three points: offered load not CPU, overlap scenarios under load,
  pending-on-fault operations through their recovery deadline), and revision 4 after the third
  (`adr-045-sol-review-3`, "needs revision, not redesign": F1–F3, the remainders of N1 and N5,
  the E-1r2 arithmetic, the sign-off gaps) and the decider's rulings of 2026-11-13 (R-8 to
  R-10). Revision 3 answered the second review (`adr-045-sol-review-2`, N1–N12); revision 2
  the first (`adr-045-sol-review`, 21 findings). Every finding of all three is answered in
  "Review record"; requirement ids are stable, a changed one is marked *(changed)* with the
  revision; FG-19 to FG-21 were added in revision 2. This is design acceptance only: nothing in
  it is built, every requirement is written as what is to exist, and implementation, acceptance
  and delivery are recorded on the source-bound issues, separately from decision status. It is
  the design record for fix-list items 57 (a test fleet that matches real use),
  60 (the Mac's 15:04–15:24Z outage), 82 (no capture is armed for item 60), 83 (three
  baselines used an instrumented binary), and for how the fleet reproduces the two failures
  the operator met after the plans were written: items 85/87 (a personal node's sync scheduler
  stops starting rounds while its sibling stays healthy; cause KNOWN since `rca-RcaSchedStall`)
  and 64/86 (an ended room is not deleted and a member cannot leave it; the same state; ADR-049
  reproduced the refused leave on the asset). The decider's words this ADR quotes are recorded
  as rulings. No question is open: "The decider's answers (2026-11-13)" at the end records
  what he chose for each. Two experiments are owed before acceptance (E-7, E-9; "Experiments"),
  and R-13 is confirmed (row 59). Rulings R-15 and R-16 record the sync mechanism and the
  intent J1 is tested against.
- **Date**: 2026-11-12
- **Deciders**: Robert E. Lee
- **Tags**: release gate, proofs, fleet, soak, fault injection, attribution, fidelity, CI
- **Related**: ADR-018 (the quality bar), ADR-034, ADR-038 (FX-19, FX-20); in this release
  ADR-040, ADR-041, ADR-042, ADR-043, ADR-044, ADR-046, ADR-047; ADR-039 (replies, another
  branch).
- **Inputs**: the group-H plan; the consolidated analysis "Why Vox keeps breaking" (§2 F and G,
  §3.7 and §3.8); the root-cause reports RcaWedge, RcaFrozen, RcaSlow, RcaChurn, RcaPreparing,
  RcaKeys, RcaTrust, RcaSessions, RcaStore, RcaAppQuit, RcaLanPath, RcaStoreSize and
  RcaSchedStall (`rca-RcaSchedStall.md`, receipts `/tmp/RcaSchedStall/receipts/`); plan
  A's item 14 measurement; the trial "sync progress"; the prototype `proto-range-sync`; the
  io-repair drill; the draft v0.4.31 QA matrix (its rows are now Appendix A); the reviews
  `adr-045-sol-review`, `adr-045-sol-review-2`, `adr-045-sol-review-3` and
  `adr-045-sol-review-4`; `fleet-experiments.md` (in progress: E-43-1, E-8, E-7 and the
  container stall queued, no results yet); the sibling
  revisions as they stand (ADR-040 … ADR-050, cited by requirement id; `/tmp/Adr049Leave/run.log`) and the cross-ADR ledger
  `adr-cross-changes` (rows 2, 7, 11, 17, 18–20); the operator's evidence under `/private/tmp/vox-rca/`
  (read-only); the tree at tag `v0.4.30` (commit `8d71ab337`); experiments E-1 and E-1r2 of
  this ADR (`/tmp/adr045/runs/`, see "Experiments").

## Owed before acceptance

The sixth review's acceptance conditions, stated as conditions and not softened:

1. **E-7, run in the authorized VM configuration** (the Linux VM, the member at the allocation
   FG-4 names), with its result incorporated: host-only evidence cannot select a fleet
   allocation the VMs cannot reproduce; the queued host run is an investigation under FG-19.
2. **E-9**, all three stagings, with its results incorporated: where J5(a)–(g) and J5(i)
   run, or that J5(i)'s latch-dependent acts stay `CANNOT MEASURE` until another fixture is
   qualified or the decider grants an exception (F1 of the sixth review).
3. **The corrected B3 measurement** (R-15, ledger row 57: range admission as one transaction
   per chunk, the fold not waiting on ContextUpdate, the corrected paging reader, all six
   earlier joiners staged, reads in both directions), and **ADR-046's acceptance** (in its
   thirteenth review as this revision is written; cited here by id only, SY-4, SY-10, SY-11,
   SY-15, SY-21, SY-24, SY-27, SY-28, its text not restated), with SY-27's contract
   incorporated into J1(a), (m) and (n) before the checker is accepted. Every other sibling
   has passed (ADR-040 r13 `a623b3108`, ADR-041 r9 `2921b9568`, ADR-043 r17 `562246a27`,
   ADR-044 r17 `770d7d35e`, ADR-047 r14 `762fe04e1`, ADR-048 r11 `fc8b996a2`, ADR-049 r14
   `5c65adba0`, ADR-050 r11 `ba79a3e3f`, ADR-051 r5 `561e96ef8`), and their ids and hashes in
   FG-8's contract manifest are final.

The design passed at revision 18 (`1e2bee466`; ledger row 83: no design-level finding remains; P2s go to task acceptance); acceptance of the gate waits on the three above. Its tasks enter milestone 35 once revision 19 passes a P1-only review (row 84).

## Context

### What the operator saw

1. **Every defect reached him first.** The 87 items of the v0.4.31 fix list were found on
   2026-11-11 to 2026-11-13. Items 1–56 were found by the operator running v0.4.26–v0.4.30 on
   his four machines, with up to seven agent sessions each, before any proof had shown one of
   them; items 64, 85, 86 and 87 were found by him after the fix plans were written. The rest
   were found by the agents planning the fixes.
2. **Each release was green and broken.** v0.4.26 to v0.4.30 went out in two days. Each fixed a
   symptom without a reproduced cause, and each passed the same gate that had missed the fault
   (consolidated analysis §2 G). The draft fix for the sync stall was later shown not to fix it:
   the trial "sync progress" left the operator-shaped run (B3) at "never within 300 s" on every
   build (`trial-sync-progress.md`, rows B3-base, B3-trial, B3-trial2).
3. **The product said all was well.** Every status surface was green while omp-io was cut off
   for three hours (consolidated analysis §2 E). A gate that reads the product's own verdicts
   could not have seen it either.
4. **His machines were the test bed.** The operator's four machines are the only place the
   product has met its real conditions (§2 F). On 2026-11-12 an agent rolled two of them back
   during his work day; AGENTS.md now forbids changing the Vox version on any of them without
   his explicit go ("The operator's machines").
5. **Three rigs gave wrong answers on 2026-11-12, all on loopback with no load.** RcaKeys
   measured a newcomer "readable in 3.7 s" in every shape it ran (`rca-RcaKeys.md`, rows
   restartD-both, busy1-others-first, big1500-busy1, pair-quiet); on the operator's IO the same
   newcomer read nobody for two hours. RcaFrozen proved "quiet cures the freeze" six times with
   fast servers (`ctl-pause`, `pause60`, `pause120`), and the cure "DOES NOT WORK with a member
   answering in ≥ 1.5 s (`slow1500`) — the operator's case" (`rca-RcaFrozen.md`, "What clears
   it"). The io-repair drill found "fresh node … works with caveat" on loopback and the fresh
   node failed on the real machines (`io-repair-drill.md`, Verdict). Each rig measured the
   product under the condition in which it works. G-8 below is the class.
6. **One outage nobody can explain (item 60).** On 2026-11-12 from 15:04:40Z to 15:24:44Z both
   daemons were Ready and attached, and QUIC handshakes between the Mac and beast timed out in
   both directions: 38 failure lines on the Mac and 36 on beast, among them "could not dial it
   back … direct attempt timed out" and "did not answer within 5 s as nytypetvqtzh" eight times
   (`rca-RcaLanPath.md` L1, R2). In the same seconds the Mac lost the anchor at .203 ("answered
   nothing for 8s" at 15:04:57, 15:08:04, 15:08:28 and twice at 15:19:51) while beast kept its
   connections to the same anchor and to vince's nodes. The relayed path failed too. It began
   28 s after macOS reset its network-privacy and firewall filter policies (`nesessionmanager`,
   15:04:12Z) and ended with the Mac daemon's restart at 15:24:44Z.
7. **A personal node stopped starting rounds while its sibling stayed healthy (items 85, 87).**
   On 2026-11-13, 01:33–02:16Z, robert-work (the Mac's personal node) held three sync slots
   with no round running, every port `queued` with `round_running` null, "no completed sync in
   10 minutes" for four rooms and the person's post "only on this machine", while omp-work on
   the same daemon held zero slots and its rooms' last activity was seconds old
   (`/private/tmp/vox-rca/mac/stall-robert-work-021627Z.json`: `lanes.slots.in_use` 3,
   `per_peer` {ehu3: 2, rotl: 1}, 18 ports, all `round_running: null`; `stall-omp-work-021627Z.json`:
   `in_use` 0, `unhealthy` empty). robert-work held the ended room repo-to-cve (2,334 entries)
   that omp-work no longer listed. Vince's personal node vovando showed the same shape from the
   Mac's side (item 87). A daemon restart cleared it. The cause is now KNOWN and reproduced on
   the release asset (`rca-RcaSchedStall`): a retained sync flow whose local cleanup save failed
   is kept for ever in `retiring` and counts against the node-wide cap `RETAINED_FLOW_LIMIT = 12`
   (`bounded_sync.rs:580`, `:1789-1810`, `:1854-1860`; the waiter at `runtime.rs:1814-1848` wakes
   on a lock, never on store recovery); at 11 such flows every Public start is refused with no
   reason recorded (`:4749-4757`). The operator's snapshot holds exactly 11 retiring flows (10
   in the live room `vox`, one in the ended room). Rig: a node whose data sits on a 64 MiB disk
   image, two fill-and-free cycles (7 then 11 pinned flows); after the second free, every port
   `queued`, no round starts, three rooms stop receiving, the sibling node healthy throughout;
   control without the fill reads every post within 6 s (`/tmp/RcaSchedStall/receipts/`).
8. **An ended room was not deleted, and a member could not leave it (items 64, 86).** The
   creator ended repo-to-cve at 00:50Z; his node kept it with "ended room cleanup stopped:
   history retirement requires recovery", the app listed it with no "ended" marker and raised
   "sync failing … authenticator invalid" against members that had deleted it; on Vince's Mac
   `Leave` failed with "An internal error — a bug in vox, not something you did". The decider:
   "people should be able to leave a room that has already been ended" (ADR-040 NW-7, NW-15).
   Both are the same pinned-flow state: on RcaSchedStall's stalled node `vox room end` looped
   `cleanup stopped … history retirement requires recovery` 170 times in 3 min and `vox room
   leave` answered "an internal error" with no log line; a healthy node ended and left in 20 s.
9. **Two more rig lessons (the prototype `proto-range-sync`, 2026-11-12).** On the v0.4.30 asset
   in the operator-shaped case (B3), every join through the slow member failed at about 37 s
   ("remote admission may have occurred, but its acceptance could not be verified and saved"),
   six earlier joiners and the newcomer alike, so the prototype's B3 had to join through a fast
   member; and the prototype's first baselines paused the `vox daemon` wrapper pid, which pauses
   nothing because the serving process is detached: those runs were discarded. Both bear on
   this ADR: J1(e)'s join through the slow member has a second failure mode on the asset
   (plan A item 8), and FG-6's pid rule names the serving process, never the wrapper.

### The decider's rulings this ADR records

- **R-1. No minimal or partial release.** "minimal continues the shit cascade". v0.4.31 ships
  every item of the fix list, or it does not ship.
- **R-2. Proven before he installs it.** "don't give me more broken shit"; "STRONG QA in the vm"
  (the title of the draft QA matrix, 2026-11-12). v0.4.31 must be thoroughly proven before the
  operator installs it on any of his machines.
- **R-3. The fleet never runs on the operator's machines.** Fix-list item 57: "never on the
  operator's machines". ADR-038 FX-20 ("use the VM stuffs so I'm not losing ability to use my
  macs") authorizes VM staging instead of working-profile staging; it does not say whose
  hardware the VM runs on. Whether a guest and containers on this Mac meet R-3 is the decider's
  call (Q3); until he makes it, this ADR does not claim compliance (FG-4, FG-6).
- **R-4. Reviewers run the journeys themselves.** A review's verdict rests on the reviewer's own
  run, not on the author's receipts. Recorded by Main from the decider on 2026-11-12; the ADR
  amends ADR-018 §10.9 for fleet journeys on that basis, and the amendment falls if the ruling
  is not confirmed at sign-off (Q1).
- **R-5. No fix without a reproduced root cause.** (Consolidated analysis §3.8: "already
  ruled".)
- **R-6. A reproduction that also appears without the trigger is not evidence.**
- **R-7. People can always leave a room.** "this is totally broken people should be able to
  leave a room that has already been ended" (2026-11-12; ADR-040 NW-15). The fleet holds the
  product to it (FG-20).
- **R-8. All machines move together.** 2026-11-13: every machine moves to 0.4.31 together; no
  mixed-version sync support (ledger row 18). J12's mixed-version act and Appendix A's Q5 are
  withdrawn; the one-time update path is J7(c′) and Appendix A's Q1/Q4.
- **R-9. The gate fits 8–10 hours.** 2026-11-13: "that's a lot of wall clock -- can we do
  something more compressed -- like 8-10 hours total?" (ledger row 19). The whole gate for a
  candidate, journeys and soak, is to fit 8–10 h of wall clock; no standing 24 h run. FG-12
  says what a day would have caught and how it is covered instead.
- **R-10. The fleet runs inside VMs.** 2026-11-13, "why not use the vm?" (ledger row 20): the
  fleet runs entirely inside VMs, the macOS guest and the Linux members inside the container
  VM; nothing runs on the host outside a VM except the driver that starts them.
- **R-11. The fleet blocks, reviewers run it, the VMs are on this Mac, open incidents ship
  named, no capture.** 2026-11-13 (ledger row 52), answering this ADR's Q1, Q3 and Q4: the
  fleet journeys block the release as a step of the release gate and reviewers run them
  themselves; the VMs run on this Mac, at most 20 vCPU and 48 GB, with a stop within 30 s;
  v0.4.31 may ship with each unreproduced incident (35, 46, 47, 60, 87 until Vince's files,
  E-b) named as open in the release notes; and no capture on his Mac (he declined it; nothing
  is armed).
- **R-12. The whole gate runs inside the VMs.** 2026-11-13 (ledger rows 31, 32): ADR-044's five
  heavier arms (RD-15's, RD-5's held-flush and Drive arms, RD-8's stalled-read arm, RD-16's
  parked-actor arm) block the release gate once each arm's mutant has been run red; and, to
  "can the tests run in a vm though", the whole release gate, the in-tree suites and those
  five arms included, runs inside the VMs: the macOS guest for Mac arms, the Linux VM for
  Linux arms; the host runs only the driver (FG-1, FG-3).
- **R-13. The in-tree full-disk journey is optional; the fleet's blocks.** 2026-11-13 (ledger
  row 51): ADR-047's in-tree full-disk journey is optional, against the recommendation; the
  fleet journeys block (R-11) and they include J5's full disk and FG-20's stall staging, which
  stay blocking there. Confirmed by him on 2026-11-13 (ledger row 59): only the separate
  in-tree full-disk journey is optional; J5, J5(g) and FG-20's staging block.
- **R-15. The sync mechanism is the replacement, with chunked admission.** 2026-11-13 morning
  (ledger rows 57, 62): range reconciliation (R2) is the requirement, R1 the recorded
  alternative; one admitted range is one store transaction ("yes chunks were the intent");
  nothing else is built on sync until B3 is measured again with the corrected reader. ADR-046
  is being restructured around it and owns the bounds; J1's acts (m) and (n) assert the intent
  with bounds marked "to be published by ADR-046".
- **R-16. The intent a newcomer is tested against.** 2026-11-13 morning (ledger row 63), his
  words: the chunks exist "for the explicit purpose of not making the user have to start from
  message one in the room and read every single message one message at a time in order to get
  caught up because that's crazy they should only have to do the most recent chunk so they can
  immediately start having access to the room and if they want to go back in history they can
  scroll up and just in time start grabbing older chunks". Binding: a newcomer starts from the
  most recent chunk and has access at once; older chunks are fetched just in time when a person
  scrolls up; nothing makes a newcomer walk from message one. J1(m), J1(n).
- **R-14. Joins, catch-up, retention, offline words.** 2026-11-13 (ledger rows 37, 39, 49,
  27), where this ADR's journeys assert them: a join is admitted by one member unless the room
  is near its member cap, and a member that does not answer the seat question within the
  patience never fails a join (J1(e), J6(b), FG-13 outcome 3); 1,000 entries a minute is the
  floor the gate proves, raised to what the chosen design measures, with no artificial rate
  limit on catch-up (J1(g)); Session steps are kept 2 days, not 7 (J4, outcome 5's
  projections); a trusted member's node that cannot be connected to is shown as `offline, last
  seen <dur> ago`, not counted unhealthy, with `waiting for a member` only when wanted entries
  have no other holder (FG-13 outcome 2, FG-15 A-1, J10(a)).
- Standing rulings this ADR fits and does not change: CI runs no proof (the decider,
  2026-10-02, `.github/workflows/ci.yml:77-80`: "I hate gates ... even the tests that test how a
  user would use a product should be done ad hoc on demand as opposed to be part of the normal
  build or CI process"); the 2026-10-01 rulings in AGENTS.md "Tests" (only real use is a test,
  every red names its side, every proof has a mutant, run once, no report-only checks, extend
  before adding, no knobs in the shipped binary); no `sudo`; never run `vox` against a real
  profile; v0.4.x has no prior-release compatibility requirement.

### Root causes at v0.4.30

Citations are to the tree at tag `v0.4.30` (commit `8d71ab337`). Status words: **KNOWN** =
reproduced on the release binary, or read from the tree or the operator's evidence, with where;
**INFERRED** = fits the evidence, not reproduced; **UNKNOWN** = not explained, with the experiment
that settles it. "Release binary" means the published asset; where a report's number came from an
instrumented build it is said.

| # | Root cause | Status and evidence |
|---|---|---|
| G-1 | **CI runs no proof.** The CI job `build-lint` runs `cargo fmt --check`, `cargo build --release --workspace`, four `cargo clippy` runs (three with `--all-targets`; the mutant-sender one at `ci.yml:103` is `-p vox-core` only; the optional-proofs one type-checks the optional proofs) and an unsigned app build (`ci.yml:94-112`). It runs no `cargo test`. ADR-018 §11.1 still says "The gates MUST run once, in CI, on the commit that is published" (`ADR-018-quality-bar-and-product-proof.md:213`); the tree follows the 2026-10-02 ruling, not the ADR. | KNOWN, read from the tree. |
| G-2 | **The only blocking run is `scripts/release-gate.sh`, on one Mac, on loopback.** It is "run on a real Mac, on the commit to be tagged" (`release-gate.sh:2`) and runs fmt, clippy, the debug suite, rustdoc and the release `--ignored` suite (`:52-66`), then checks CI's run (`:68-110`). Its proofs stage two or three `vox` processes on `127.0.0.1`/`[::1]` with empty stores and peers that answer in milliseconds (`crates/vox-tui/tests/support/sync_pair.rs`, `room.rs`, `relay.rs`, `nat.rs`, `port_forward.rs`). The one latency emulator, `PortForward::set_delay` (`port_forward.rs:232-233`), delays guest → host only; it serves V210-122's prompt-connection bounds, never a sync round under load. | KNOWN, read from the tree. |
| G-3 | **The conditions the reproduced items needed are absent from that staging.** The sync, load and store items each needed at least two of: sustained agent load, a peer that answers in seconds or sits 37.5–75 ms away, a multi-GB store, a restart in flight, several computers in one trust group, a late joiner, a trust change (consolidated analysis §2 F); the items about a missing command, a small buffer or a wrong error text need only the one condition their row names. The rigs of 2026-11-12 reproduced each failure only after adding them: relayed at 75 ms per hop alice held 3 of bob's 677 posts, and directly on loopback 542 of 542 (`rca-RcaWedge.md`, runs `r30-relay75-b10x2` and `r30-direct-b10x2`, release asset); the newcomer froze 9 of 9 times only with member traffic and an earlier late joiner, and not in the controls `ctl-pause` and `ctl-no-n-old` (`rca-RcaFrozen.md`, release asset); the daemon slowed (posts 3.5–5.4 s) only with ten sessions stepping (`rca-RcaSlow.md` S1, measured on RcaSlow's instrumented build, not the asset). | KNOWN; RcaWedge and RcaFrozen on the release asset, RcaSlow's timings instrumented. Run directories `/tmp/rca-RcaWedge/`, `/tmp/rca-RcaFrozen/`, `/tmp/rca-RcaSlow/` were lost in the reboot of 2026-11-13 (row 64); the figures stand in the reports; re-run as the fleet baseline. |
| G-4 | **No rule makes an expensive proof run before a tag.** ADR-018 §10.2 puts "Expensive user-facing proofs" behind `optional-proofs`, where they "MUST block nothing: not CI and not the release gate" (`ADR-018…:149-151`); §10.9 says "Nobody SHOULD run locally what CI already runs" (`:186`); the 2026-10-02 ruling took every test out of CI. Together they left no place where a proof of the operator's conditions must run before a tag. §10.12 ("A latency bound MUST hold on a machine doing ordinary work", `:196-198`) was read as "do not require an idle machine", never as "require a loaded one". | KNOWN, read from the ADR and the tree. |
| G-5 | **The draft QA matrix is the right shape and too small.** Its 12 rows run the candidate assets in the guest VM and a Linux container and name every red, but cover only items 1, 2, 13, 39, 40, 43, 46 and the v0.4.27–v0.4.30 regressions. Nothing covers the store (20–25), trust containment (26–32, 36, 38), the slow member (2, 14), the late joiner (3, 7, 8), truth (49–56), a full disk (23, 24) or the Linux buffer (19). Its soak (Q12) is 30 min with two restarts and no trust change, join, leave, full disk or network change. | KNOWN, read from the draft; its rows are Appendix A. |
| G-6 | **The dry run's Linux asset is a stand-in.** `scripts/release-dry-run.sh OUTPUT_DIRECTORY [LINUX_VOX]` (`:7`, the second positional argument, `:26-31`) copies the macOS `vox` under the Linux name unless that argument is given (`:18`), and signs ad hoc with stand-in notarization receipts (`:13-17`). The release builds Linux as `cargo build --release --bin vox` then `strip` on `ubuntu-latest`, packaged as `x86_64-unknown-linux-gnu` (`release.yml:80-97`, strip at `:91`). A gate that ran "the dry run's assets" as they come would run a macOS binary as Linux. | KNOWN, read from the tree. |
| G-7 | **Three baselines used a binary that does not ship (item 83).** RcaFrozen's slow-member rows, the trial "sync progress" and RcaWedge's slow-server rows made the slow member with `vox-0.4.30-rca`, the release plus the knob `VOX_RCA_SERVE_DELAY_MS` (`trial-sync-progress.md`, "Binaries"). RcaWedge's delayed-relay rows (3/677, 4/344, 89 stream failures) and RcaFrozen's fast-server freezes (9/9) are on the asset and stand. A journey that kept the knob would break "no test knobs in the shipped binary" and could not run on the assets. The plan's replacement, a 300 ms-per-second `SIGSTOP` duty cycle, is not a slow responder: an exchange in the other 700 ms finishes at loopback speed, and the whole daemon stops, authors and clients included. | KNOWN, read from the reports; the duty cycle's defect is arithmetic. E-1 (this revision) replaces it with a measured slow path on the release asset. |
| G-8 | **A rig on loopback with no load answers for loopback with no load.** The three wrong answers of 2026-11-12 (Context 5) share one cause: each measured a claim without the condition that produced the failure (a member answering in seconds, a 4-node daemon on a 9.7 GB store, a 150 ms path) and reported the result as the product's. Nothing required a rig to show the condition before its number counted. | KNOWN, read from the three reports and the operator's outcome. FG-19 is the rule. |
| G-9 | **Sampled checks are blind between samples and during faults.** The plan's soak scored nine numbers per quiet 60 s window and exempted misses inside a fault and its heal pause; a restart that prepares for 45 s, a join that takes 50 s, or a post accepted during a fault and never delivered on one member, all pass. | KNOWN, read from the plan (H §3) and revision 1 (FG-13). FG-13 is rewritten around a ledger and continuous outcomes. |
| 60 | **The Mac's outage: cause UNKNOWN.** Locus KNOWN: the Mac (beast's view of everything else stayed fine; only the Mac lost two LAN hosts at once). Excluded by evidence: the macOS application firewall (disabled), a Local Network denial for `vox` (none in the unified log), a stale advertised port (50760 throughout), the accept gate and rate limiter (no refusal lines, and a refusal is not a timeout), an actor stall of 5 s or more (no "busy … nobody could be answered" line). Not excluded: a UDP or per-flow policy drop that ICMP does not see; the daemon not draining its socket (RcaSlow S3 shows a saturated actor with handshakes under 100 ms, which is one counterexample, not a rule). Two readings remain. **(A) the host:** the Mac's Wi-Fi link (en0, an MLO pair on channels 50/79) or its network stack after the 15:04:12Z policy reset dropped the daemon's UDP for seconds at a time. **(B) the process:** the daemon (two tokio workers, `crates/vox-tui/src/daemon.rs:135-138`; two nodes; 9.7 GB of stores; the item-1 wedge active in exactly this span) did not drain its socket for seconds. "did not answer within 5 s as …" (`crates/vox-core/src/transport/identity.rs:781-785`) means the QUIC handshake completed and the listener did not send PROVE within the exchange timeout (`identity.rs:601-640`); the source does not say which task or packet was late. The host counter "2,347 dropped due to full socket buffers since boot" could not be placed in the window. | UNKNOWN. Evidence: the operator's logs under `/private/tmp/vox-rca/mac/` and beast's, read in `rca-RcaLanPath.md` (e). Settled only by the capture of FG-16 at a recurrence, or by FG-15's (B) experiment if it reproduces the shape with its control green. |
| 82 | **No capture is armed for item 60.** The fix list says "watchers armed". `/private/tmp/vox-rca/mac/lan-outage-captures/` exists and is empty, and no process on the Mac matches `outage`, `wedge-`, `capture` or a `vox status` loop. | KNOWN; observed by the plan at 16:25 local and again while writing revision 1. Its arming is the operator's go (Q4). |
| 85/87 | **A node's sync scheduler stops starting rounds because failed cleanups fill a node-wide cap.** A flow whose local retirement save fails stays in `retiring` and `retirement_failed` (`bounded_sync.rs:1854-1860`) and waits for a lock that never comes (`runtime.rs:1814-1848`); `can_retain_new` (`:1789-1810`) counts it against `RETAINED_FLOW_LIMIT = 12` (`:580`); at 11 every Public start is refused silently (`:4749-4757`). Triggers of the same class: a storage error in the room-save phase (the operator's item-31 `key-package attempt unacknowledged`; ENOSPC and redb's latched `Previous I/O error` on the rig), or a retirement worker that stopped (the ended room's flow; cause of that abort UNKNOWN). The three held slots with nothing running are a second, unexplained leak (owner UNKNOWN; ADR-046 SY-24 names slot owners). | KNOWN for robert-work: reproduced on the release asset (`rca-RcaSchedStall`, receipts `/tmp/RcaSchedStall/receipts/exp.log`, `exp2.log`, `A-stalled.json`, `B-sibling-during-stall.json`; controls (i)–(iv)). INFERRED for vovando (item 87) until Vince's status and log are in hand. Owner: ADR-046 SY-24 (ledger rows 11, 14, 17), ADR-042 TR-25, ADR-040 NW-1's `StoreRecovery(room)`. The fleet reproduces it on demand with the same trigger (FG-12's "storage failure, retained" fault; FG-20). |
| 64/86 | **An ended room is kept, and a leave fails: the same pinned flow.** `RoomRetirement::drain` (`bounded_sync.rs:832-843`) returns `history retirement requires recovery` at once when the room has a flow in `retirement_failed`; `begin_own_key_ended_purge` (`actor.rs:21519-21573`) is re-run every tick and gives up (`leave_save.rs:1563-1578`); `vox room leave` takes the same drain and fails as a `Fault` (`leave_save.rs:1467-1488`) with no log line. the E-64b and E-86 runs on the release asset (recorded in `adr-040-revision` and now attributed to ADR-049 LE-2/LE-4): a healthy node ends and leaves an ended room (gone ≤ 70 s with a member unreachable; at once on a healthy room); RcaSchedStall's stalled node loops `cleanup stopped` and refuses the leave. | KNOWN, reproduced on the asset (RcaSchedStall controls (ii)–(iv)). Owner: ADR-049 LE-2, LE-4 (from ADR-040 NW-7, NW-15; `Retire::Deleting` discards the failed flow with the room; it does not touch the cap, which is SY-24's). ADR-049's E-49a on the asset: the leave on a node with flows in `retirement_failed` exits 1 "an internal error", no log line, room still listed; succeeds after a restart. The fleet holds both from the reproduced state (J5(f), J5(g), J6(h), FG-12's fault, FG-20). |

### Why no proof caught it

This item is the absence of a proof. The nearest existing claims are green on v0.4.30 because
their staging is the condition under which the product works: V210-08
`a_post_answers_promptly_while_a_peer_posts_proof.rs` (two members, no steps, a small room);
`a_newcomer_reads_the_whole_history_proof.rs` (a quiet room); `a_long_room_reads_in_linear_time_proof.rs`
(one node, no peers); `update_proof.rs` (a guest with no live rooms);
`the_daemon_and_its_nodes_proof.rs::a_kept_node_and_its_room_come_back_after_a_restart`
(`:552`, a handful of rows). For item 60: no proof runs a daemon on Wi-Fi, under a macOS policy
reset, or with 9.7 GB of stores and two nodes; `a_network_change_is_noticed_and_acted_on_proof.rs`
changes the address, not the link's loss; `a_silent_stream_cannot_stop_a_node_proof.rs` proves a
silent peer does not stop the node, not that the node is not the silent one. For items 85/87: no
proof watches two nodes of one daemon separately for an hour under multi-room traffic.

### Citations checked

Twenty-six file:line citations were read at `v0.4.30` (the reviewer's audit and this revision).
These hold: `ci.yml:77-80`, `:94-107`; `release-gate.sh:2`, `:12-16`, `:52-66`, `:68-110`,
`:112-117`; `release-dry-run.sh:13-18`; `release.yml:80-97`; `port_forward.rs:232-233`;
`transport/identity.rs:601-640` and `:781-785`; `vox-tui/src/daemon.rs:135-138`;
`node/status.rs:384`; `node/actor/bounded_sync.rs:18` and `:4108-4121`;
`node/channel/entry_store/sparse.rs:2590-2605`; `node/actor.rs:327`;
`history_stream/admission.rs:234-237`; `node/channel/attention.rs:382-393`; `node/store.rs:658, 767`;
`the_daemon_and_its_nodes_proof.rs:552`; `daemon_log.rs:44-47, 48-51`;
`vox-tui/src/keychain.rs:18-19, 56-60, 77-90, 94-104` (`VOX_TEST_KEYCHAIN` is read only under
`test-knobs`); `vox-tui/src/host.rs:1564-1600` (the daemon stores a passphrase in the keychain
only when a client asks it to keep a node with that passphrase). Corrected in this revision:

- `ci.yml:75-112` has four clippy runs, three with `--all-targets`; the mutant-sender run
  (`:103`) is `-p vox-core` only.
- `release-dry-run.sh` takes the Linux binary as its second positional argument
  (`:7`, `:26-31`), not an environment variable; FG-2 now writes the invocation. The release
  strips the Linux binary (`release.yml:91`); FG-2's container build does the same.
- ADR-038 FX-19 is at `ADR-038…:245-247` (`:244` is blank). FX-20 (`:248-253`) requires VM
  staging; it does not define the VM's host as non-operator hardware (R-3, Q3).
- `node/actor.rs:324-327`: `ONE_TIME_WAIT_MS` is the one-time-prekey fallback timer, not a
  key-delivery deadline; J2(b) adopts 30 s as a person's budget and says so.
- RcaSlow's S1, S3 and S4 timings came from its instrumented build; G-3 and FG-15 now say so.
- Item 22's index multiplier was resolved by RcaStoreSize §3.i; it is no longer listed as
  inferred in FG-10.
- AGENTS.md:121-125 forbids unauthorized version changes and daemon restarts on the operator's
  machines; it does not define "operator machine" and does not forbid an authorized read-only
  status instrument. The scratch-profile rule (`:99-100`) is separate.
- Fix-list item 71 cites `daemon_log.rs:44-49`; the truncation at open is `:44-47`, and `:48-51`
  deletes an oversized `daemon.log.1`. An ordinary small log never reaches `:44-47` (J7(k)).
- Fix-list item 68 cites `attention.rs:382-393`; of four files of that name the site is
  `crates/vox-core/src/node/channel/attention.rs`.

## Terms

- **Candidate**: the commit proposed for the tag. **Candidate assets**: what `scripts/release-dry-run.sh <dir>
  <linux dist>` builds from it, the second argument being the `dist/` directory
  `scripts/build-linux-release.sh` wrote from the same commit inside the pinned glibc 2.28 image
  (FG-2; ADR-051 LB-2). **Baseline**: the published v0.4.30 assets.
- **Fleet**: the standing computers, stores, load generators and impairments of FG-4, driven
  from one program (the **driver**, `fleet/`).
- **Journey**: one proof that drives the shipped `vox` on the fleet the way a person does and
  asserts what that person sees. J1–J12 are journeys; J13 is the soak.
- **Claim**: one assertion of a journey, with one bound and one kind (FG-9): **R** (a
  root-cause claim: red with its trigger on the baseline, green without it), **F** (a feature
  claim: red on the baseline because the behaviour did not exist, or red under a deliberate
  product mutant). Claims are numbered J1(a), J1(b), ….
- **Staging**: everything a claim needs before it is measured (computers up, rooms joined, load
  attained, a fault applied, a condition shown). **Shown**: a condition the driver has measured
  on the run itself before the claim counts (FG-19).
- **Trigger**: the condition an R claim says the product survives (a slow member, a 75 ms path,
  ten stepping sessions, a full disk). **Control run**: the same journey with its trigger
  removed. **Mutant receipt**: the journey's recorded run on the baseline, red on the claim's
  own assertion.
- **Ledger**: the driver's record of every operation it issued (post, step, join, leave, end,
  trust change, restart, update, fault, heal) with the product's acknowledgment as the product
  printed it (exit status, the position or id it returned, the time), and of every node's
  rendered view and status at 1 Hz (FG-13).
- **Slow member**: two conditions that the plans had folded into one, kept apart since
  revision 3 (N4): a **delayed member** (every exchange with it crosses a path of T or more;
  made by a **slow path**, the member reaching every peer only through a hop the driver delays
  per direction; E-1, E-1r2) and a **busy responder** (a member whose actor and writer are
  saturated so that a served request waits seconds in its queue; plan A item 14: p90 60–84 ms,
  max 12–16 s; made by **real load**, a CPU-limited computer carrying the nursery's largest
  store and ten stepping sessions; E-7). The operator's robert-work was the second; the fleet
  shows which one a run staged and never credits one for the other. Neither is a stopped
  process: a process pause is its own fault (FG-12), and pausing the `vox daemon` wrapper pid
  pauses nothing (Context 9).
- **Room model**: the operator's repo room as staged on the fleet: one room of 4,900 entries at
  start (3,000 seeded posts in stage 1); three heavy authors (M's agent node, B, I's first node)
  posting closed-loop once a second each; ten sessions on M stepping twice a second in all, with
  bodies of about 330 B (the operator's median body; RcaStoreSize §2a: median row 7,924 B, body
  about 330 B); six late joiners (I's other three nodes, V's three); four computers (M, B, I, V)
  in one computer-trust group; `personal` and `agent` nodes on M's one daemon; the anchor A. The
  driver records offered and acknowledged rates, body sizes, queue depth and refusals (FG-4).
- **Soak**: J13, the hours-long run with faults injected. **Nemesis**: the driver's fault
  injector (Jepsen's word). **Fault**: one injected condition. **Heal**: its removal.
  **Recovery interval**: the time after a heal within which the product must have recovered,
  per fault (FG-12's table). **Drain**: the final phase after the last heal in which no fault
  is in flight and every acknowledged operation must be visible everywhere (FG-13).
- **Nursery**: the dated whole-fleet snapshots the corpus grower leaves behind, from which
  multi-GB stores are cloned (FG-7). **Corpus manifest**: the counts and bytes that describe a
  snapshot (FG-7).
- **Receipts directory**: everything one run leaves for a reader (FG-14).
- **Operator machine**: a computer the operator owns and uses: this Mac, beast, vince's, .203,
  .46 (AGENTS.md:119-125). Whether a guest or container on this Mac that holds nothing of his
  is "an operator machine" in the sense of item 57 is Q3; this ADR does not decide it.
- **Red labels** (ADR-018 §10.1): `PRODUCT:` (what the product did, quoted), `PRODUCT (staging):`
  (a product step the claim needed failed first), `CANNOT MEASURE:` (staging not achieved, claim
  not measured) and `APPARATUS:` (the driver proved its own fault; FG-14).

## Requirements

### 1. The gate

- **FG-1. No tag without the fleet, and the whole gate runs in the VMs.** *(changed: finding
  20; r6, R-11, R-12.)* A tag MUST NOT be cut
  unless, on the candidate assets, every journey J1–J12 is green and one J13 soak has completed
  with every blocking outcome (FG-13) inside its bound, its required scenario coverage (FG-12)
  attained and its drain clean. A `CANNOT MEASURE` is not green. There is no partial pass: no
  subset of journeys, no "known red", no tag after a build stage (FG-17's stages are build
  order, not release points).
  - *Why*: item 57; rulings R-1 and R-2; G-1–G-5. Every one of items 1–56 reached the operator
    before any proof.
  - *Changes*: `scripts/release-gate.sh` is to become the driver's entry point on the host and
    to run nothing else there (R-12): it builds the candidate assets, then runs, inside the VMs,
    the in-tree suites (the debug suite, rustdoc and the release `--ignored` suite, with
    ADR-044's five blocking arms among them, on the macOS guest for Mac arms and on the Linux
    VM for Linux arms), checks CI's run, and runs the `fleet` step, `fleet/gate.py --assets
    <dry-run directory>`, which runs J1–J12 serially and then J13. The whole, suites and fleet,
    fits R-9's 8–10 h, stated for both of FG-4's VM modes as UNVERIFIED figures to be measured
    by FG-3's qualification: in mode (b), the full fleet, the in-tree suites and ADR-044's arms
    get at most 1 h 30 min, the guest's half and the Linux VM's half in parallel with each
    other and before the fleet starts (the fleet needs the VMs' CPU; nothing of it overlaps the
    suites), then about 3 h 25 min of journeys and a 5 h soak, about 9 h 55 min in all; in mode
    (a), one VM at a time, the suites' halves run one after the other (up to 3 h) and only the
    single-VM journeys can run, so no green is possible in mode (a) and its figures measure the
    halves and the single-VM journeys only; a suite half that exceeds 1 h 30 min is FG-3's
    qualification red in either mode.
    Where the assets are built: the macOS dry run (`scripts/release-dry-run.sh`, which needs
    Xcode and cargo) runs in the guest, whose image carries Xcode and the repository's toolchain
    (`docs/release/app-proof-vm.md:10-24`); the Linux build runs in the Linux VM; the host runs
    only the driver (R-12). The build time is outside the 8–10 h gate clock, which starts when
    the assets exist. A completed J13 receipt MAY stand in for a new soak only when its manifest matches the
    candidate on every key: the SHA-256 of every binary; the driver's commit; the hash of every
    journey and checker definition (`fleet/journeys/`, `fleet/check.py`); the corpus manifest
    id (FG-7); the workload and impairment manifest (FG-4); the scenario coverage satisfied
    (FG-12); and no `PRODUCT:` red outstanding in it. A receipt made by a weaker or repaired
    checker is not evidence for the repaired gate. The gate's existing note format stays. A
    green run is to read:

    ```
    release-gate: release suite (every blocking proof; each optional one says NOT RUN): ok
    release-gate: fleet ...
    fleet: candidate 4f2c1e0a7 — vox-aarch64-apple-darwin sha256 1a2b…, Vox-0.4.31 app zip sha256 9e8d…, vox-x86_64-unknown-linux-gnu sha256 3c4d…
    fleet: baseline v0.4.30 (mutant receipts recorded 2026-11-18); corpus n-2026-11-19 (manifest id c7…)
    fleet: J1  a late joiner reads a busy room with a slow member ........ PASS  11 min 52 s
    fleet: J2  a relayed pair 75 ms apart keeps up ....................... PASS   7 min 40 s
    …
    fleet: J12 update with live rooms .................................... PASS  17 min 05 s
    fleet: J13 soak, 24 h, 61 faults, coverage 18/18, drain clean ....... PASS
    fleet: receipts ~/vox-fleet/receipts/2026-11-20T0812Z-4f2c1e0a7
    fleet: this green holds for these binaries, corpus c7…, this workload and these paths (FG-19); open incidents: 35, 46, 47, 60, 87, E-b
    release-gate: fleet: ok
    release-gate: GREEN: 4f2c1e0a7… may be tagged
    ```

    and a red, which names the claim, quotes the product and points at the receipts:

    ```
    fleet: J1  a late joiner reads a busy room with a slow member ........ RED
      PRODUCT: J1(a) n-new did not show z1's "hello to n-new" within 30 s of its acknowledgment (shown at +212 s)
      vox room read repo-to-cve --node n-new (+30 s, exit 0) ends: "y1: hello to n-new from y1"
      receipts ~/vox-fleet/receipts/2026-11-20T0812Z-4f2c1e0a7/J1
    release-gate: RED: fleet
    release-gate: not green: do not tag 4f2c1e0a7…
    ```

    The header of `release-gate.sh` is to say what it runs and where: the in-tree suites and
    ADR-044's blocking arms in the guest and the Linux VM, the CI check, and the fleet; its
    sentences "run on a real Mac" (`:2`) and "It runs what CI's build-test runs" (`:6`) go.
    The release notes of every tag are to name the fleet receipts directory of its gate run
    and each open incident R-11 names.
  - *Deleted*: the draft QA matrix file, after its rows are in Appendix A (FG-21). Its rows are
    absorbed: Q1, Q7–Q9 and Q11 into J12; Q2, Q4 and Q6 into J7; Q10 into J8; Q12 into J13;
    Q3 into FG-9; Q5 withdrawn (R-8).
  - *Proof*: the gate itself. With the fleet step absent, a tag is possible today; with it,
    the gate is green only on a full pass. The step's own check is apparatus (ADR-018 §10.10
    says a `CANNOT MEASURE` is not a product mutant): point `fleet/gate.py` at the v0.4.30
    assets; the gate MUST print `RED: fleet` and name J1's first failing claim, which is a
    product red of the baseline. Acceptance FG-1-A: one v0.4.31 tag cut only after a green
    `fleet` step, its receipts directory named in the release notes.

- **FG-2. The candidate is what ships.** *(changed: citation.)* Every journey MUST run the
  candidate assets: the Mac `vox` and app zip that `scripts/release-dry-run.sh` builds, and the
  Linux `dist/` that `scripts/build-linux-release.sh <dist>` writes from the candidate commit by
  running the release's own Linux steps (`scripts/linux-release-steps.sh`: build, strip, the
  glibc-floor precondition, packaging) inside the `quay.io/pypa/manylinux_2_28_x86_64`
  `linux/amd64` container at the digest `release.yml` pins, so the fleet's Linux `vox` needs the
  same glibc the release asset needs; that directory is the dry run's required second argument:
  `scripts/release-dry-run.sh <out> <linux dist>` (ADR-051 LB-2). The manifest records the
  floor line that script printed beside the binary's hash.
  Linux members that carry load MAY run an `aarch64` build of the same commit, because the
  `x86_64` asset runs on this Mac only under emulation (about 1.7 s per CLI call); the asset
  itself MUST carry the install, update and passphrase claims (J7, J11) and ADR-051's install
  arms J11(e), J11(f) and J11(g) on the floor, operator, below-floor and non-glibc images. **The
  Linux baseline**:
  no `aarch64` Linux v0.4.30 asset was published, so the baseline for Linux load members is an
  `aarch64` build of the tag `v0.4.30` (commit `8d71ab337`, `cargo build --release --bin vox`
  in the Linux VM, stripped), recorded in the manifest as `baseline-linux-aarch64 built from
  8d71ab337` with its hash; it carries behaviour claims and their mutant receipts (the code is
  the tag's; only the target differs), never an asset-level claim; the published `x86_64`
  v0.4.30 asset under emulation carries the asset-level baselines (install, update, passphrase)
  and the container stall staging of E-9 (a), and every manifest
  MUST say which binary each computer ran. (Answered by R-11: the load members run an `aarch64` build on this Mac's VMs; no native
  `x86_64` host.) The manifest of every run MUST record the SHA-256 of every binary it ran. A container
  build is not byte-identical to the release runner's; the manifest records both hashes and the
  post-release smoke runs the published asset once. Notarization and Gatekeeper acceptance
  cannot be checked before a tag (the dry run's signature is ad hoc, `release-dry-run.sh:13-17`);
  they stay with `release.yml` and the post-release smoke, and J12's smoke rows say so (Appendix
  A, Q11).
  - *Why*: G-6; a gate that runs something else than what ships proves nothing about it.
  - *Changes*: the dry run has no stand-in mode: it refuses to run without the Linux `dist/`
    (ADR-051 LB-2), so the driver's Mach-O refusal of earlier revisions is retired (the act that
    tested it, the task cut's V431-045-03, is removed, not retargeted: the condition it refused
    cannot arise); the driver still records the SHA-256 of the Linux `vox` it ran.
  - *Proof*: FG-1's run.

- **FG-3. CI stays compile-only; the fleet and the suites are steps of the release gate, run
  in the VMs.** *(changed: r6, R-12.)* CI MUST remain as the decider ruled on 2026-10-02: format
  check, build, clippy (including the optional proofs' type-check) and the unsigned app build.
  It MUST NOT run a journey, start the fleet or gain any check for it. The fleet runs only in
  `scripts/release-gate.sh` (FG-1), in a reviewer's own run (FG-11) and in the corpus grower
  (FG-7); there is no standing run (ruling R-9). The in-tree suites and ADR-044's five blocking
  arms run from the same script inside the VMs (the guest for Mac arms, the Linux VM for Linux
  arms); nothing of the gate runs on the host but the driver. **Stage-1 qualification
  (UNVERIFIED today)**: that the full cargo suite runs in the guest (8 vCPU, 16 GB) and that
  its wall clock, with the Linux VM's half, fits inside the 8–10 h budget with the fleet; its
  red, if the suite cannot run there or exceeds the budget, is `CANNOT MEASURE: the release
  suite in the guest took 4 h 50 (budget leaves 3 h 10 for it)` and stage 1 is not done until
  it is green or the budget is re-asked. The fleet journeys are
  not Rust test files: a journey needs the guest, the containers and the nursery, so a `cargo
  test` that required them would be `CANNOT MEASURE` on every machine but one. They live in the
  repository under `fleet/journeys/` as programs of the driver.
  - *Why*: the 2026-10-02 ruling; G-1, G-4. The gate script already is the one blocking run
    outside CI; this extends it rather than adding a second convention (AGENTS.md "Extend
    before adding").
  - *Changes*: ADR-018 §10.2, §10.9, §10.12 and §11.1 and AGENTS.md "Tests" are amended (see
    "Superseded and amended lines"; the §10.2 amendment names the fleet journeys of this ADR,
    not every proof that meets one condition); `docs/release/optional-proofs.md:18` is to name
    the CI step that exists (`ci.yml:106-107`); `docs/release/fleet.md` is to say how to run
    each journey and where its receipts go.
  - *Proof*: none of its own; FG-1's run shows the step blocks, and `ci.yml` is unchanged.

### 2. The fleet

- **FG-4. The fleet holds the operator's conditions, and shows them.** *(changed: findings 7, 18,
  21; fidelity assessment.)* The fleet MUST consist of these computers, with no `sudo` anywhere.
  Where they run is ruling R-10: entirely inside VMs on this Mac (the macOS guest; every Linux
  member inside the `podman-machine-default` VM); nothing runs on the host outside a VM except
  the driver (`fleet/`), which starts, impairs, samples and stops them from the host. The
  stage-1 loopback rigs (E-1, E-1r2) ran on the host and are investigations, not the fleet;
  stage 1 as built runs its loopback journeys inside the podman VM (one Linux member per
  computer role, the forwarder inside the VM). The resources and hours those VMs may take on
  this Mac are Q3 (answered, R-11). **Host rules** (the decider, 2026-11-13, after he found
  this Mac unusable that morning and allowed VMs "only if you're careful"; ledger row 66):
  `/opt/vox-evidence/v0431/hostguard.sh` MUST print OK before any rig, build or VM start;
  never Lima; every VM start is approved by Main and announced to him; one rig at a time, about
  ten scratch daemons at most; builds `nice -n 10`, 4 jobs; no disk-image experiments on the
  host; a health line every minute to `/opt/vox-evidence/v0431/host-health.log`; and everything
  stops if a VM process crashes. The driver enforces these before it starts anything and stops
  on the crash signal. **Two modes of VM operation** (R1 of the seventh review):
  - **(a) the qualification restriction, in force now**: until the operator authorizes
    concurrent VMs on this Mac, at most one VM runs at a time. What fits one VM and may run in
    this mode: E-9 (a) and (b) in the Linux VM; E-9 (c) in the macOS guest; E-7 in the Linux VM
    configuration (S at `--cpus 1` with its peers as containers in the same VM); the in-tree
    suites' two halves one after the other (the Linux VM's half, then the guest's with
    ADR-044's Mac arms); stage 1's loopback journeys J1 and J2 inside the Linux VM (every
    computer role a container there, the forwarder in the VM); the corpus grower (stage 2's
    containers, M′ for M); every stage-2 journey (J3 on the 0.5 GB store, J4, J5, J6, J11),
    which needs only the Linux VM; and the stage-3 journeys that need only the guest (J8, J12's
    app rows). What does not fit one VM: J7 (M and B at once), J9's cross-computer acts with
    the app, J10's folded guest half, J3 on the ≥ 2 GB snapshot with M as the guest, FG-15's
    (B), and J13. No peer is omitted and no product process runs on the host to work around
    it: an act that needs both VMs waits for mode (b).
  - **(b) the full fleet**: both VMs at once, the guest (8 vCPU, 16 GB) and the Linux VM
    (12 vCPU, 32 GB) within his limit of 20 vCPU and 48 GB, with the cross-VM paths of this
    table. It is **unavailable until he authorizes concurrent operation**, which Main asks of
    him after the single-VM runs of mode (a) have shown the host stays healthy, with
    `/opt/vox-evidence/v0431/host-health.log` as the evidence. FG-1's green requires mode (b).

  | Role | What it is | Why |
  |---|---|---|
  | **M**, the operator's Mac | the tart guest `vox-app-proofs` (macOS, 8 vCPU, 16 GB, 140 GB), a scratch account with its own login keychain: one daemon with `personal` and `agent` nodes, the candidate Vox.app, the login item, the updater | the only place the signed bundle, LaunchServices, the keychain and the app can be driven (`docs/release/app-proof-vm.md`) |
  | **B**, beast | a podman container in the `podman-machine-default` Linux VM (12 vCPU, 32 GB; applehv; every container shares that VM's Linux kernel, not this Mac's). What is true of root there: the machine is **rootless** as podman defines it (`podman machine inspect` shows `Rootful: false`: the host's `podman` client talks to a rootless podman service of the VM's unprivileged `core` user, no `sudo` on the host), and the VM's `core` user holds passwordless `sudo` inside the VM (the Fedora CoreOS image podman ships; `podman machine ssh` lands in it). By the decider's ruling (row 69) the apparatus MAY act as root **inside this disposable test VM only**, to run the installer as a person does and to set the VM's sysctls for the staged cases; never on the host and never on a machine he owns, and nothing on the host runs as root. Mechanism relied on: `podman machine ssh podman-machine-default -- sudo -n <cmd>` for the sysctl arm and for mounting a loop image (E-9 (b)), and `--cap-add NET_ADMIN` on the container for `tc qdisc`, which a rootless service grants inside the container's user namespace (the earlier `lo` check ran so); UNVERIFIED until E-9 runs them, and recorded in the manifest when it does. B: one daemon, one agent node with a passphrase, started with a seccomp profile that adds `add_key` and `request_key` to podman's default (`--security-opt seccomp=fleet/containers/seccomp-keyring.json`; the kernel keyring arm needs the syscalls permitted) so RS-1's kernel keyring works; a second B container under the default profile stages RS-1's refused-keyring text (J7(c″)). RD-12's kernel arm runs as root in the VM itself per ADR-044 and row 69. ADR-051's in-tree Linux arms (its install and update journeys' new claims) compile and run as x86_64 inside an emulated `linux/amd64` container in this VM, `vox` as an ordinary user, by the two invocations ADR-051 LB-6 gives (the install journey in the debug pass; the ignored update journey in the release pass with `VOX_PROOF_NEXT_BINARY`), with the image digest, `uname -m` and each build's wall clock in the receipt; run natively on aarch64 they print CANNOT MEASURE. ADR-041's in-tree proofs that need a real manager run in the guest's `gui/<uid>` domain (RS-5, RS-15) with the guest's real default paths; the container's daemon for J7 is supervised by the driver's own supervisor, which J7(e) names as the manager under test, since a rootless container has no systemd (ADR-041 RS-5's managed/unmanaged contract: the act says which it proves) | Linux restart and passphrase (39), the UDP buffer (19), headless notifications (55, 72), real fsync on ext4/overlay |
  | **I**, IO | a second container: one daemon, four nodes, no passphrases; its data directory on a size-bounded `--tmpfs` for J5 (a capacity fixture, not a slow disk), provisioned by the driver for every journey that needs a short disk on Linux (ADR-049 LE-8, ADR-047's short-disk arms, ADR-041 RS-9's session-store append failure; the guest's counterpart for RS-9 is a small RAM disk, `hdiutil attach -nomount ram://`; whether the tmpfs also serves the latched-failure acts is E-9) | the late joiner among four (3, 8, 9, 10) and a full disk (23, 24) |
  | **S**, the slow member | the container that carries the slow-member role when it is made by real load: `--cpus 1`, the nursery's largest store, ten stepping sessions (stage 2+); in stage 1 the role is y1 behind the slow path (E-1) | item 2, RcaFrozen RC-2: a member that answers, seconds late |
  | **V**, vince's | a third container, three nodes, behind `tc qdisc … netem delay 150ms 20ms loss 1% reorder 5%` | the distant peer the operator always has; v0.4.30 starves at 37.5–75 ms per hop (RcaWedge) |
  | **A**, the anchor | a fourth container running `vox node --listen [::]:4433`, its address pinned in every node's config | the .203 role; restarted by the nemesis |
  | **N**, the driver | the host: `fleet/lib.py`, `fleet/impair.py`, `fleet/nemesis.py`, `fleet/check.py`, `fleet/gate.py`; the only thing outside a VM (R-10); it runs no `vox` on the host | one owner for every process, impairment, ledger and verdict |

  Paths: the guest reaches the containers through podman's published UDP ports on the host;
  containers reach the guest at its vmnet address. Before stage 3 the role M is a container
  **M′** with two nodes (`personal`, `agent`) and the sessions, so stage 2's room model is
  complete without the guest; the keychain, app and login-item claims wait for stage 3 and say
  so. A direct path between containers is impaired
  with `netem` on the container's interface (`NET_ADMIN` inside the container's user namespace under the VM's rootless service; checked by the plan on `lo`, aarch64; UNVERIFIED on `eth0` until E-9). A
  path with the guest at one end is forced through the driver's userspace forwarder
  (`fleet/impair.py`, grown from `udpdelay.py` with E-1's runtime delay switch), so the product
  sees a real address with real delay and loss. The forwarder is to offer `delay` (per
  direction), `jitter`, `loss`, `reorder`, `bandwidth`, `blackhole` (both directions, timed)
  and `slow_close` (stop one client's datagrams), switched over a control socket; its
  zero-loss baseline at 0 ms is measured before every run (`udpdelay_test.py`; non-zero is
  `CANNOT MEASURE`).

  **Path attainment.** A qdisc listed by `tc qdisc show` proves a qdisc exists, not that Vox's
  path crosses it. Before a claim that names a path, the driver MUST show the path: the
  product's own `vox status --json` `peers[].rtt_ms` and path kind (direct or relayed) for the
  pair, and an independent probe of the driver's own (a datagram echo through the same
  forwarder or interface) agreeing with it within 20 %, in both directions. A pair that found a
  faster route than the one staged is `CANNOT MEASURE: V reached B direct at 0.3 ms; the netem
  path was not taken`.

  **Load attainment.** Load is produced at three fidelities: bridge emulation (RcaSlow's
  sessions speaking the OMP bridge protocol) for volume in J1, J3, J4 and J13; the real OMP
  extension under a host shim with no model (`fleet/omp_host.mjs`, from RcaSessions'
  `shim.mjs`) for J7, J12 and for at least one continuously active conversation in J13 (FG-12);
  live-model proofs stay optional and off the gate (ADR-018 §10.3). Every poster and stepper is
  closed-loop per session (the next operation starts when the previous returns), so the
  product's slowness lowers the achieved rate instead of piling up; the driver records, per
  second, offered operations, acknowledged operations, refused operations, the body-size
  distribution and the backlog, and a claim whose row names a rate is measured only while the
  acknowledged rate is within 20 % of the row's figure ("load attained"), else `CANNOT
  MEASURE: acknowledged 0.4 posts/s against 1/s asked`. Per ADR-044's measurement, the earlier
  RcaSlow rig offered about 0.27 acknowledged posts/s, not 2/s; J3's row says "closed-loop per
  session" and records what it attained.

  **Per-node observation.** Every node of every computer is a reader: I's four and V's three
  each have their own `vox room read` cursor and `vox status --json` sample in the ledger. A
  computer is never represented by one of its nodes (items 85/87 were one node of two). The
  anchor is not a room recipient unless it joins.
  - *Why*: G-3, G-8; item 57's list (load, delay, multi-GB stores, late joiners, restarts, trust
    changes, a 24 h soak); items 85/87 (one node of two).
  - *Proof*: each journey's staging check (FG-14): a claim is measured only when the fleet
    shows the condition (path attained, load attained, "sessions installed: 10/10").

- **FG-5. No knob and no instrumented binary in a journey; a slow member is measured.**
  *(changed: findings 1, 14.)* A journey MUST run only the candidate or baseline assets, with no
  `VOX_TEST_*` or `VOX_RCA_*` variable set. Delay, loss, a full disk, restarts and updates MUST
  all come from outside the process. A slow member MUST be one of:
  - **a slow path** (stage 1 and the journeys): the member listens on the other loopback
    family (`[::1]`) and reaches the anchor only through the forwarder's front, so every peer
    reaches it relayed through the one delayed hop; the forwarder delays the member's outbound
    datagrams by T (1,500 ms) and its inbound by 0, so from any asking node every exchange with
    the member takes T, and the member's own requests leave T late. E-1 built it on the release
    asset and reproduced the freeze (see "Experiments"); its control at 0 ms did not.
  - **real load** (stage 2+ and the soak): a container limited to one CPU carrying the nursery's
    largest store and ten stepping sessions.

  Whichever is used, the claim counts only when the driver has **shown** the slowness on the run,
  and it says which condition it showed:
  - **delayed member, shown** = the product's own completed round-trip measurement toward the
    member, `vox status --json` `peers[].rtt_ms` on every asking node, is ≥ T at every sample
    of the staging window (E-1: 1,501 ms on n-new, z1 and n-old1 toward y1, path `relayed`;
    control 1 ms), and the forwarder's per-datagram log (`datagrams.csv`: direction, bytes,
    scheduled delay, actual delay, lateness, error) shows the scheduled delay applied within
    50 ms on p99 of datagrams and no send error. A completed-round figure is derived from the
    ledger as a third witness, slot occupancy toward the member divided by rounds completed
    toward it in the joined window (E-1r2: 289 s / 147 rounds ≈ 2.0 s; the control has too few
    y1-directed occupied samples, three, for a matched figure and none is claimed). Running
    ages (`lanes.bounded.running[].age_ms`) are occupancy diagnostics only; they are never
    compared with T (N3: a request sampled midway through a 1.5 s exchange is about 750 ms old).
  - **busy responder, shown** = the **load applied to it**, never the delay that load used to
    cause (F1: a candidate that attained "median status ≥ 1.5 s" could not also pass FG-13's
    "every status ≤ 1 s"). Attained means the **externally offered workload, the corpus and
    the allocation**, frozen and the same on every binary: the ten sessions installed and
    stepping at RD-14's rate (2 a second in all, one timer 500 ms apart, 2 KB each, every step
    acknowledged within 5 s), its own closed-loop posts acknowledged, the store the manifest's
    snapshot at its recorded size and shape, the container at `--cpus 1` and the memory the
    manifest names, and the product's `rtt_ms` toward it < 50 ms (so the path is not what is
    slow). What the member does with that offer is the product's: its CPU utilization
    (`podman stats`) and its serving delay (`vox status` start-to-exit and the driver's `vox
    room read --limit 1` probe on that member) are recorded as diagnostics, and on the baseline
    they are v0.4.30's figures (E-7 reports their medians, expected seconds and near-full CPU;
    plan A measured the actor wait at max 12–16 s); neither is ever a minimum the candidate
    must reach, because a fixed candidate that does less repeated work (SO-6 removes most of
    the Session refold) consumes less CPU for the same offer and must not be `CANNOT MEASURE`
    for it (fourth review, point 1). The candidate's responsiveness under the same offer is
    judged by J1(e)/(f)'s and J3's own bounds, with no requirement that any old delay or CPU
    figure appears.
  Below the condition claimed is `CANNOT MEASURE: y1's rtt 0.3 s; the delayed member was not
  delayed`, or `CANNOT MEASURE: S's sessions stepped at 0.4/s (asked 2/s); the busy responder
  was not offered its load`. A `SIGSTOP`/`SIGCONT` of a daemon is a **process pause**
  fault (FG-12), a crash-and-scheduling condition; it MUST NOT stand in for either anywhere,
  and the pid it stops is the serving process (`ps` shows `--data-dir <root>` on it), never
  the `vox daemon` wrapper (Context 9). The numbers of RcaFrozen's slow rows, the trial "sync
  progress" and RcaWedge's slow-server rows stand as investigations; they MUST NOT serve as
  mutant receipts. What E-1 is evidence of: the scheduler's sensitivity to a delayed peer
  (item 2's slot half, item 12) on the release asset; it is not evidence about the busy
  responder (items 8, 14 and item 2's responder half), whose fleet claims count only after E-7
  attains the load as defined here on the baseline, records its serving diagnostic and runs
  its control; if the load as defined does not make the baseline red on J1(e)/(f), those
  claims are `CANNOT MEASURE` on the fleet and are held by their owners' proofs (ADR-044
  RD-16, ADR-046 SY-6, SY-10), never credited to the slow path. A claim the fleet cannot stage
  without a knob is not a fleet claim: it stays with its in-tree proof in the release suite,
  built with `test-knobs` (ADR-018 §10.11), and the matrix says so per item. The one scoped
  exception on the fleet: the fault-dependent acts of J5(i) (ADR-047 SO-12's arm 2, the
  external race between admission and commit, staged by the injected `fsync` fault after the
  header on one ruled commit, the same `test-knobs` fault ADR-044 RD-7's arm two uses; SO-12's
  arm 4d, the surviving storage acts of the withdrawn 4b/4c, with their fault runs at **every
  fault position the arm names**: the post-header `fsync` fault at the final `storage.flush()`
  after the primary header write (acts 1, 1-floor); the fault in the reopened store's
  confirming commit (act 2), in redb's repair commit (act 2-repair), in `compact()` (act
  2-compact) and in R2's deletion batch (act 2-reclaim); and the **data-write fault** (act 1-pre: a
  failure at a data-page write of alice's commit, before any header, on a populated root with
  bob's five received entries unflushed), which is the position SO-12's captured-read rebuild
  mutant needs (`vox room read` showing bob's entries from the latched handle's captured result
  while a restart does not) and which neither the post-header nor the recovery-commit fault
  stages, each its own `test-knobs` knob; SO-12's arm 4 with the
  lock hold and arm 5's leaked holder; SO-11's arm 1d as arm 2's contiguous continuation with
  no restart between them; no settlement waiter, token or snapshot comes back with any of
  them) run a `test-knobs` build of the candidate commit
  on the full-disk member for those acts only, whose owners' in-tree forms the decider made
  optional (R-13); the manifest records that build's hash beside the asset's and lists each act
  and each fault run it ran, arm 4d's seven acts (1, 1-pre, 1-floor, 2, 2-repair, 2-compact, 2-reclaim) by name with the fault
  position of each, with the asset's restoration recorded after each (the arm-2 → 1d chain uninterrupted, its restoration
  after 1d); the member is restored to the packaged asset for
  every other act of J5 and for every asset-only claim (J5(a)–(g), SO-11's ordinary arms 1–1c,
  the SO-14 arms, SO-2's sweep), with the restoration recorded; every other computer and every
  other journey run the assets, and the general prohibition stands everywhere else. ADR-044 no
  longer needs a `test-knobs` member on the fleet (RD-7 at revision 14: one save, one trip;
  its arms are in tree).
  - *Why*: item 83 (G-7); ADR-018 §10.11; finding 1 (a duty cycle is not a slow responder); N3,
    N4 (ages are not durations; a delayed path is not a busy actor); F1 (attainment is the
    load, not the symptom). *(changed: r3; r4, F1.)*
  - *Proof*: E-1 and E-1r2 (red with the slow path, green at 0 ms; `rtt_ms` 1,501 against 1;
    see "Experiments"). Apparatus self-check for
    the rule: a journey run with `VOX_RCA_SERVE_DELAY_MS` set MUST stop with `CANNOT MEASURE:
    VOX_RCA_SERVE_DELAY_MS is set; a journey runs the assets with no knob`.

- **FG-6. The fleet touches nothing of the operator's.** *(changed: finding 4.)* The driver MUST
  NOT start, signal, update or read the profile of any `vox` but its own. Every `vox` it starts
  MUST run with `--data-dir` and `--config-dir` (or `VOX_DATA_DIR` and `VOX_CONFIG_DIR`) beneath
  the fleet root, and with `VOX_NODE`, `VOX_SESSION`, `PI_SESSION_ID`, `PI_SESSION_FILE`,
  `VOX_ROOM` and `VOX_OMP_INSTANCE` unset (a blacklist the driver applies to every child). The
  driver MUST signal a pid only after `ps -o command=` shows the fleet root in its command line,
  MUST kill by pid and never by pattern, and MUST end every run with no stray process (ADR-018
  §12.1); for the guest's login-item daemon, whose argv may not carry the root, ownership is
  the guest itself: everything in the guest is the fleet's. It MUST refuse to start when
  `VOX_DATA_DIR` or `VOX_NODE` is set in its own environment: `fleet: refused: VOX_NODE is set
  in this shell; the fleet never runs against a real profile`.

  **The macOS login Keychain** (and nothing else: the Linux kernel keyring is the next
  paragraph). `VOX_TEST_KEYCHAIN` is read only under `test-knobs`
  (`keychain.rs:18-19`); a shipped asset ignores it and uses the account's login keychain. So:
  (i) in any staging outside the guest's scratch account (stage 1's loopback journeys in the
  Linux VM, and the host scratch rigs E-1/E-1r2 that preceded the fleet) no journey MAY ask a
  daemon to keep a node with a passphrase: nodes are created and attached with `--passphrase-file` only, never `vox node
  unlock --keep`, `vox setup`, `vox agent setup` or the app, which are the only callers of the
  store (`host.rs:1564-1600`); the driver counts `security dump-keychain | grep -c us.vox.node`
  on the host before and after every gate run (the host runs only the driver, R-10) and a change is `APPARATUS: the host keychain gained an item;
  stop` (the item is the operator's to remove; the driver never deletes keychain items); today
  the count is 2 (`omp-work`, `robert-work`), read while writing this revision. (ii) Every
  claim about kept nodes, the login keychain, restart with a remembered passphrase or the app
  (J7's Mac half, J8, J12) runs only in the guest's scratch account with its own login keychain
  (stage 3). Item 58's prevention is (i) and (ii), not a knob.

  **The Linux kernel keyring** is not the Keychain and the rule above does not touch it: on B,
  inside the disposable Linux VM, ADR-041 RS-1's acts are mandatory and run with the packaged
  asset: `vox node unlock` with the passphrase from stdin and no file, the credential remembered
  across a daemon restart, an update and a `kill -9` with nobody typing (J7(c)), and the
  refused-keyring case under podman's default profile with its errno (J7(c″)); `vox node lock`
  removes it. The persistent keyring belongs to the VM's unprivileged user and dies with the VM;
  nothing of the operator's is in it.
  - *Why*: ruling R-3 (as far as it can be met before Q3); AGENTS.md "Safety" and "The
    operator's machines"; item 58.
  - *Proof*: the driver's start-up check, run once with `VOX_NODE=omp-work` set: the refusal
    above, exit 2, and no `vox` process started (`ps` before and after); the keychain count
    before and after E-1 (2 and 2). Apparatus self-checks, not product mutants.

- **FG-7. Multi-GB stores come from the product, through a corpus grower.** *(changed: finding
  6; fidelity assessment.)* The operator's stores MUST NOT be fleet stores (they are sealed to
  his vault and bound to his identity; nothing of his identity is ever copied into the fleet).
  A fleet store MUST be grown by the product and cloned per run. The grower, `fleet/grow.py`,
  is an instrument, not a journey and not J13: it runs the room model on the full fleet on the
  baseline assets with V's path impaired (the shape that grows fastest, because it wedges),
  for 6 h, with every known baseline red attributed in its log and ignored for the purpose of
  finishing; it then stops every daemon (so no writable redb file is copied while open), copies
  every computer's data directory (store, vault, config, `.daemon/port`) into one dated
  snapshot of the whole fleet, so node ids, trust and keys stay consistent (the anchor's port is
  pinned so saved configs stay valid), restarts the fleet from the copy once, and writes the
  **corpus manifest**: per node, file bytes, in-use bytes and data bytes (SO-15 on the
  candidate; `redbhist` category bytes on the baseline), entry counts per room, Session record
  counts, ProofRange-like row count, leaf slack, and the id (a hash of the manifest). Clones are
  `cp -c` (APFS clonefile) on the host and a full copy inside containers (about 30 s/GB). A
  snapshot is valid when the restarted baseline fleet is **consistent**: every node opens
  every room it held (however long that takes: the baseline's preparing time is item 18 and is
  recorded in the manifest as `baseline_open_s`, not judged), every computer's trust group
  and every room's membership read the same on every node as before the copy, one post per
  room from each author renders on every member within 120 s of the last room opening, and no
  room reads `[failed:`. Else the grower says `CANNOT MEASURE: snapshot n-… is not consistent
  (room r2c on I: [failed: …])` and the previous snapshot stays current. RD-11's open bound is
  the candidate's claim, measured in J3(d) when the candidate opens the clone, and SO-2's
  first-open sweep is the candidate's too; neither judges the corpus. Until a snapshot of 2 GB or
  more on its heaviest node exists, the multi-GB claims of J3 and J13 MUST report
  `CANNOT MEASURE: no nursery snapshot ≥ 2 GB`, which is never green (FG-1). Until then the
  stores of 2026-11-12 serve the smaller bounds: RcaSlow's `r1/A` (526 MB, 8.6 k entries),
  RcaChurn's `bigA.redb` (302 MB) and the four wedged pairs (46–100 MB). The grower needs only
  stage 2's containers (with M′ for M) and the baseline; it does not need the nemesis or the
  guest. *(changed: r3, N2.)*
  - *Why*: G-3; items 18, 20–22, 25 and 76–80 need a store of the operator's size and shape;
    size alone does not certify shape (502 k ProofRange rows, 46.5 % leaf slack), so the
    manifest carries the shape.
  - *Proof*: J3(f) and J13's store outcome read the manifest before they measure.

### 3. The journeys

- **FG-8. Every fix-list item has a journey, a claim and a bound, or says who holds it.**
  *(changed: findings 8–13, 16; the coverage audit; ledger rows 2, 7, 11.)* Every item of the
  v0.4.31 fix list MUST appear in the journey matrix below, in a journey whose claim would show
  the item to a person, or in the "held elsewhere" row with the proof that holds it (the owner's
  in-tree proof, a spike, or a procedure) and the reason the fleet cannot stage it. A journey's
  bound that another lane's ADR states (ADR-040–ADR-047) MUST be that ADR's bound, frozen here
  with its measurement origin; a bound this ADR proposes for a lane that has not yet stated one
  is marked "proposed" and the lane ADR governs. Each journey runs once per candidate, serially,
  because they share one host. Every sampler, diagnostic and assertion reads ADR-042's
  schema (`entries_behind`, `last_entry`, `coverage`, `headers_through`, `control_current`,
  `reach`, `last_start_refusal`, the TR-2 verdict words with TR-24's coverage forms and TR-25's
  `NOT ASKING` / `NOT HEARD FROM` lines, `last_round_ms` as a diagnostic only); nothing reads
  `last_sync_ms` or `holds_through` on the candidate, and the baseline receipts record their
  v0.4.30 equivalents. Before implementation the driver freezes a **contract manifest**: the
  requirement ids of each sibling ADR whose words and bounds the journeys consume, cited by id
  and never by revision number (ADR-040 NW-1, NW-12; ADR-048 TC-5–TC-9; ADR-049 LE-1–LE-8;
  ADR-050 TJ-10; ADR-041 RS-1–RS-16; ADR-042 TR-1–TR-25 and Appendix D; ADR-043 CJ-1–CJ-16;
  ADR-044 RD-1–RD-16 (RD-7 at revision 14, ledger row 74, "one save, one trip": no fleet act of its own; cited by id from the frozen copy `ADR-044.a9bb34bdb.md`, hash `3010fbe499b1…`, in its fourteenth review and pending); ADR-046 SY-4, SY-10, SY-11,
  SY-15, SY-24, SY-27; ADR-047 SO-2, SO-4, SO-8, SO-10–SO-15), each with the text's hash the
  manifest froze; a sibling's later change of a cited requirement re-opens the rows that
  cite it. Two bounds this ADR consumes are not yet published by their
  owners and are frozen here as "proposed" until they are: SO-4's per-message and per-step
  byte bounds (J4(b), outcome 5) and the slow-member render bounds of J1(a) (ADR-046 SY-2,
  SY-4); the checker refuses to judge a claim whose bound is still "proposed"
  (`CANNOT MEASURE: J4(b)'s bound is not published`). Who publishes and by when: ADR-046
  publishes J1(a)'s bounds in SY-2/SY-4 before J1's first baseline receipt is recorded (stage
  1's third step, "J1 and J2 with their baseline receipts"); ADR-047 publishes SO-4's numbers
  before J4 is built (stage 2's J4 step); a gate run before either is published is not green,
  by this rule, and the task order places the publication ahead of the journey. *(changed: r3, N8; r4.)*
  - *Why*: G-5; ruling R-2; finding 8 (a gate that asserts the old schema fails a correct
    ADR-042).
  - *Proof*: the matrix itself, checked by the reviewer of this ADR against the fix list; the
    gate's report lists every journey and claim.

#### The journey matrix

Times are per run on this Mac with the fleet up, from the rigs' logs and E-1 (B2 shape 9 min
including staging). "v0.4.30" is what the baseline did in the reports; FG-9 requires each
journey to record its own receipt and says which rows are KNOWN on the asset today. Kinds: R =
root-cause claim (trigger and control), F = feature claim (old behaviour or a deliberate mutant).
"Continuous" means measured from the ledger at every sample, not at the end of an act.

| J | What a person does and sees | Items | Claims | v0.4.30 | Time |
|---|---|---|---|---|---|
| **J1** | *A late joiner reads a busy room with a delayed member, and with a busy responder.* Room model (stage 1: trial-sync B2/B3 shape on loopback, K earlier joiners, y1 the delayed member by slow path, FG-5; stage 2: the same with S as the busy responder, E-7); authors closed-loop at 1/s. `vox node create n-new` on V; n-new joins through a fast member's link; every member posts "hello to n-new". A second newcomer n-new2 joins through the slow member. A node outside the group that joined by invite without `trust add` is the negative control for (b). Staging: every group computer holds n-new's trust before the hellos; every computer runs `vox anchor add <fleet anchor>` at staging (ADR-043 CJ-17's cause of E-1's y1 never learning n-new: the computer management held only the serving process's startup `--anchor` list; item E-b is closed by CJ-17, proved by J9(i)); a computer that has not applied the policy within 120 s is `PRODUCT (staging): <computer> has not applied revision <r> after 120 s`. | 1, 2, 3, 4, 5, 7, 8, 12, 14, 49, 52, 88, 89; R-16 | (a) R: SY-27 (a)'s bound: within 30 s of `joined`, every member's post-join hello renders on n-new and n-new's own hello on every member; the slow member's own hello is SY-4's B3 assertion (120 s on the delayed path), a distinct threshold ADR-046 states as such; SY-2's 5 s applies only when the room is staged quiet (owner ADR-046 SY-27, SY-4, SY-2; unmeasured, row 72). (b) R: `vox agent doctor` on n-new says "you trust each other" for every group member ≤ 30 s, and says TR-10's "has not trusted you" words only for the negative-control node (52). (c) R: n-new's `control_current` (TR-1) is true for every member ≤ 30 s, and no round fails `inclusion header is absent` (3, 5; replaces governance-revision equality, which differs 16/17/17 while everything renders, trial B1). (d) R: SY-4's selective holder (the apparatus server, built by ADR-046 SY-4's owner as its proof-host task; it holds the header and withholds one body below the live window while authors advance 200 entries): while withheld, n-new shows the owed row (TR-11); within 60 s of a second holder serving it (the server releases it, or a member that holds it connects), and again after n-new's restart, the exact body text renders; the owed row alone never passes (SY-4) (4). (e) R: n-new2's `vox room join` through the slow member returns ≤ T + 10 s (SY-10; the admitting member admits alone unless the room is near its cap, and an unanswered seat question never fails the join, R-14; every member running: the paused-seat case is act (o) and the first member post renders ≤ 10 s after; the asset's second failure mode, "remote admission may have occurred, but its acceptance could not be verified and saved" at about 37 s (Context 9), is this claim's red (8). With the delayed member this is a delayed-path join; the busy-responder join (plan A item 8's actor wait) counts only in the stage-2 act with S shown busy (FG-5). (f) R, continuous: every earlier running member renders every author's post ≤ 5 s after its acknowledgment (RD-3) (1, 14; 14's actor-queue cause counts only in the stage-2 act; no member is paused in this act). (g) R: a reader staged ≥ 8,000 behind (a nursery clone rolled back, stage 2) catches up at ≥ 1,000 entries a minute under SY-5's conditions (bodies ≤ 1 KiB, one unloaded holder, ≤ 100 ms round trip) from its first exchange until it holds the head, 1,000 being the floor the gate proves and the bound raised to the figure ADR-046's chosen design measures, with no artificial rate limit (R-14), rows 88 and 5,087 named in the ledger render, and its final render equals the ledger (SY-5) (7). (h) F/R: n-new's TR-2 verdict with TR-24's coverage form agrees with the ledger at every sample (49). (i) R: keys readable both ways ≤ 30 s (a person's budget, adopted) (12). (k) F/R, stage 2, ADR-046 SY-15's budget-saturated act (optional in tree, blocking here; its apparatus, the 70 permit-holding test peers, is built by ADR-046 SY-15's owner as that requirement's proof-host task, and the fleet drives it): 70 apparatus peers each hold a permit by answering nothing for 20 s and each advertise a stream of control entries while one real member posts; n-new shows each post within 60 s throughout (owner ADR-046 SY-15). The stage-2 B3-shape act is SY-4's (owner ADR-046 SY-4; its in-tree form optional). (l) F, ADR-046 SY-11's open-node fence (item 89, cause UNKNOWN until E-89; the apparatus member is built by ADR-046 SY-11's owner as its proof-host task): an apparatus member answers `Head(me)` with a genuine signed own head two positions higher; within 1 s `vox status` answers (RD-1) and `vox room post` is refused "behind what a member holds", never blocked; the recovery completes and a post returns 0 within 10 s; a second room on the node is untouched; E-89 (ADR-046's) runs first and its cause is added before any mechanism is changed (89). (m) F, R-16, ADR-046 SY-27 (its newcomer contract, parts 1–3 and measurement slots (a)–(e), is the contract for J1(a) and this act; cited by id): **access** is SY-27's: the newcomer renders every member's posts made from its join on, is read by every member, and can post; (m1) time to access: from n-new's `vox room join` returning (`joined`) to every member's post-join hello rendered on n-new and n-new's own hello rendered on every member, ≤ 30 s (SY-27 (a)); (m2) what n-new fetched before access, by kind, in bytes and requests (SY-27 (b), from `vox status --json`'s bytes-before-access and the ledger's wire counts); (m3) the same join into the same room with its prior history doubled (6,000 seeds against 3,000, the same authors and members): time to access and fetched-before-access each grow by at most 20 % (SY-27 (c)), and the ledger's fetched positions show no walk from message one; a bound of SY-27's still unresolved at run time is `CANNOT MEASURE`, never a looser substitute. (n) F, SY-27 (d), paging back: after access n-new fetches no older chunk until a person pages back (`vox room read --history older`, the app's scroll), each page back fetches one older chunk just in time and the page renders within 10 s; the ledger's fetched positions show no older chunk fetched without a request. What the fence post (row 65, SY-27 part 3) adds: (m4) fetched-before-access does not grow with the room's **membership history** either (the same join after the room has seen twice the grants, removals and policy revisions: ≤ 20 % growth), because a newcomer starts from the creator's signed summary and verifies only what came after, one control chunk (128 control-kind positions) per author whatever the room's age (ADR-046 SY-27 at revision 10, cited by id from the frozen copy `ADR-046.1aa0d5579.md`, hash `1801cdabf5d7…`, in its ninth review and pending: the fence post's summary is **one answer of at most 1 MiB**, the join answer's `Snapshot` or `Snapshot{H}` asked of a connected member, above which the creator publishes no fence post, the room has no current fence post and status says `no fence post: the room's membership summary (<size>) exceeds this release's 1 MiB limit`; J1(m4) stages a room under the limit and, as a second act, a room whose summary exceeds it, asserting that status line and that access still completes from the last fence post or position 1 with the time recorded, never a 30 s claim; that act's own mutant, distinct from the full-walk mutant below (verifying from the start is permitted above the limit, so it cannot discriminate here): the creator publishes a **truncated summary** that fits 1 MiB by dropping members and events, so the room shows a current fence post and no `no fence post` line, and the newcomer's access omits the dropped members' posts and their consent (the ledger shows posts of a dropped member never rendered on n-new and `vox agent doctor` wrong about it); red on this act's no-fence/status assertion and on outcome 1, PRODUCT; a second over-limit mutant, the limit raised so an oversized summary is published, fails the same status assertion and the single-answer transport (the `Snapshot` answer refused as over budget)); (m5) **with a current fence post** from the room's creator, access within SY-27's 30 s, and **adoption** (SY-28, ledger row 76: "like a newcomer"): a member that has fallen more than one control chunk behind the creator's newest fence for some author adopts that fence post as its baseline and is current about as fast as a newcomer, taking the creator's word for the stretch it skipped, and rejects a summary that contradicts anything it already holds; J1(m6) stages an earlier joiner held offline through 300 control-kind positions of membership change and asserts, after its return, access within SY-27's 30 s from reconnection and no walk of the skipped stretch in its fetched positions, and that a summary contradicting a fact it holds (an apparatus creator's forged summary) is refused and the member verifies from its own `control_through` instead; **with the creator away** (its daemon stopped for the whole staging; ledger row 68, ADR-046 Q8 answered): the newcomer's catch-up grows with the entries since the last fence post, so this arm asserts no fixed 30 s: it asserts that access completes, that `vox status` shows the fence post's age, and it records, measured together as SY-27 (e) asks, the fence's age and distance (3,000 and 6,000 entries behind the heads), bytes and requests fetched before access by kind, and the actual time to access, against SY-27's disclosed growth (its 0.78 MB per thousand entries estimate, to be replaced by the measured figure). Every bound of (m) and (n) is pinned to ADR-046 SY-27's contract and stays **unmeasured** until the next prototype cycle: round 2 of the replacement prototype (ledger row 72, macOS 27.2) passed B1 (every hello 2.4 s) and all B3 joins, and failed B3 on one assertion, the newcomer never rendering the slow heavy author (`arm-replace.md`). Mutants: fetch `ControlRange{all}` or bodies from position 1 at join (m3 red: fetched-before-access doubles); prefetch older chunks after access (n red); verify the membership from message one despite a fence post (m4 red). Owner ADR-046 SY-27 (and SY-4, SY-12–SY-14, the anchor). (o) R, SY-10's paused-seat scenario, item 88, a separate act after (a)–(n) with its own control: three or more members, one of them paused (`SIGSTOP` of its serving process, a process-pause fault under FG-12's contract: its samples `unavailable (paused)`, its pending operations judged by heal + R), a newcomer joins through a **running** member: the join returns within SY-10's T + 10 s and is never failed by the paused member's silence (v0.4.30: `SeatNotAgreed` after `SEAT_ANSWER_WITHIN` = 5 s); the paused member is a recipient with the fault's prospective deadline, and after `CONT` every post acknowledged during its pause, the newcomer's hello included, renders on it within R (30 s) and its own view agrees with the ledger; the delayed-path and busy-responder acts, their continuous healthy-reader bounds ((f)) and their controls stay separate from this one. Control: the same with no member paused (the join returns in the same bound either way; the paused run is red on v0.4.30, the control green). Owner ADR-046 SY-10 (88). | B2 shape, E-1 and E-1r2 (release asset, slow path 1.5 s, `rtt_ms` 1,501 toward y1): fast members' hellos 52.5 s and 150.8 s, control-current 134.8 s, join through the slow member 33.8 s, the newcomer's public slot toward y1 in 292 of 295 occupied samples (299 joined-phase samples); control at 0 ms (`rtt_ms` 1): 2.1 s, 2.1 s, 2.1 s, 3.9 s. Not a control for (b): in both runs y1 never learned n-new's trust (E-b). B3 shape: never within 300 s (trial, knob); join via the slow member failed at 37.7 s (proto-range-sync, asset). RcaFrozen `base1`: rows 1 at join+88 s (asset). Busy-responder act: no receipt until E-7. | 12 min stage 1; 20 min stage 2 |
| **J2** | *A relayed pair 75 ms apart keeps up; a mid-latency pair too.* The anchor behind the forwarder at 75 ms per hop; bob runs 10 closed-loop posters for 180 s; a second act at 37.5 ms per hop. | 1, 11, 12, 13, 69 | (a) R, continuous: alice renders each of bob's posts ≤ 5 s after its acknowledgment, and bob alice's (RD-3's bound applied to the relayed pair; ADR-046 governs) (1). (b) R: keys readable both ways ≤ 30 s (12). (c) F: alice's TR-2 verdict with TR-24's coverage and her `last_entry` toward bob (TR-1, advancing with every delivered post the ledger acknowledged) agree with the ledger at every sample; `last_round_ms` is recorded, never asserted (13). (d) R/F: zero rounds end `quic stream: closed before the frame was written` on either act, and every stream the server closes carries a typed answer (SY-21; the untyped text is on J10(b)'s blacklist) (11). (e) F, TR-6 as revised: during J13's anchor-restart fault a member whose rounds fail shows `sync failing: <reason>`, and the first authenticated answer from the peer, an empty one included, clears it; whether the room receives is outcome 1's and TR-4's question, never this line's (69). | 3/677 and 4/344 with 89 stream failures, keys not readable in 180 s (`rca-RcaWedge.md`, asset). | 8 min |
| **J3** | *The author under agent load answers, and comes back after a restart* (ADR-044 RD-14; no new file; J3 is also where ADR-044's five blocking arms, RD-15's, RD-5's held-flush and Drive arms, RD-8's stalled-read arm and RD-16's parked-actor arm, are recorded as run in the guest and the Linux VM before the fleet starts, R-12, each with its mutant run red once; RD-14's per-claim mutants for RD-1, RD-2, RD-3 and RD-11 are run by the reviewer of ADR-044's fix under FG-11, once, on the fix's assets, J3 being the run). RcaSlow L2 shape on the 0.5 GB store (stage 2) and the ≥ 2 GB snapshot (stage 3): RD-14's load, copied: the author hosts 10 named OMP sessions; steps offered open-loop at 2 a second in all (one timer, 500 ms apart, round-robin, 2 KB each), every step acknowledged by the bridge within 5 s or the run is red (`PRODUCT: step <n> acknowledged after <t> s`); posts 200 B, one closed loop per session; three readers never mark read; `vox daemon --restart` at +300 s; the first 60 s after the room opens and the restart-to-open interval are not sampled; nearest-rank percentiles. The run record carries the acknowledged post rate, the step acknowledgement tail, the served wait (SY-20), `growth_per_hour_bytes` with entry and step counts and body-byte totals (ADR-047 SO-15), the host, its kernel and filesystem (ADR-044 RD-14), and, with every 1 Hz sample, the per-save flush time (each ruled commit's `F_FULLFSYNC` or `fdatasync` duration, RD-7 at revision 14: one save, one trip) and the writer queue depth (saves waiting at redb's one writer); the three 5 s clocks (post CLI exit, bridge step acknowledgment, reader visibility) named apart (ADR-044 RD-14). The v0.4.30 baseline these are compared with, measured on the host under RD-14's load on macOS 27.2 (`/opt/vox-evidence/v0431/perf-baseline/REPORT.md`, runs loaded-1-r2 and loaded-2, MEASURED): post p50 1,039–1,055 ms, p99 2,725–2,798 ms, max 5,276–5,768 ms, 2–3 posts over 5 s per 10-min run (the J3 gate's v0.4.30 red); `vox status` p50 81–86 ms, p99 296–369 ms; daemon CPU about 101 % mean, RSS about 140 MiB; reader latency and flushes per second CANNOT MEASURE on the host (row 81: a baseline, no target). | 6, 13, 15, 16, 17, 18, 22, 68, 77, 78, 84 | (a) R: every acknowledged `vox room post` on the author exits within 5 s of its start (the decider, ledger rows 80–81; ADR-044 RD-2, RD-14); the run records post latency p50/p99/max (start to CLI exit), `vox status` latency p50/p99, the daemon's CPU and memory, and flushes per second, for v0.4.30 and the candidate, blocking on none; no speed target is asserted until the decider sets one from these numbers; the bridge's step acknowledgment ≤ 5 s and RD-3's reader visibility ≤ 5 s are separate clocks and separate checks; every failed post is its own red; (b) R: `vox status` start-to-exit ≤ 1 s every sample (RD-1); (c) R, continuous: each reader renders each of A's posts ≤ 5 s after acknowledgment for the whole run, including after the restart from a cold cache, and each reader's `last_entry` toward A (TR-1) advances at least once a minute (RD-3's sync-advance check) (17, 84); (d) R: after the restart the room opens within RD-11's bound with 8,000 own Session rows and 2,000 foreign ones seeded, and A's first served round completes ≤ 10 s after Ready (18); (e) R: `vox room read --history newest` and `--history resume` on a reader staged behind make wire progress within one exchange and complete the requested range (SY-9) (6); (f) SO-15's figures are recorded here and asserted in J4 (22, 77, 78); (g) item 68 is RD-6's in-tree proof; J3 corroborates that an attention event is delivered under load within TR-18's bound. Durability across a crash after acknowledgment (16) is RD-7's in-tree arms (the held `Immediate` commit, the injected `fsync` fault, the Session step); J3 does not claim it, and the fleet has no act for it since row 74. | posts 3.5–5.4 s, status 581 ms max (RcaSlow, instrumented); preparing 110–134 s (RcaChurn, asset) | 35 min |
| **J4** | *The store stays bounded under a wedge, and compaction gives it back.* Fixed workloads on the nursery corpus: W-msg, 1,000 acknowledged posts of 330 B by one author; W-step, 1,000 acknowledged Session steps of 2 KB; each run twice, once with V's path impaired (the wedge) and once with V direct (the matched control); then 30 min of wedge with no new content; then SO-10's trigger on a slack clone (`vox node compact`, or a restart when Q8 = (a)). No forged row: the poison of item 21 is ADR-047 SO-13's review plus spike E-7 of ADR-047. | 20, 21, 22, 25, 76, 79, 80 | (a) F: `vox status` shows per node file length, disk use, in-use, data and packed bytes, the disk's free space and the floor, and per room the data split by category (SO-15) (25). (b) R: data bytes grow per acknowledged message and per step within SO-4's numeric bounds for the chosen body and signature option (imported from SO-4 when the decider picks it; "proposed" until then), the same in the wedge run and its control (22, 78). SO-6's write-cost contract (bounded writes per Session input over its named-session workload, OS bytes measured) is SO-6's own journey; J4 corroborates that the published Session view after W-step equals the fold. (c) R: in the 30 min wedge with zero admitted entries on the wedged reader, its data bytes grow by 0 and its in-use bytes by ≤ 1 MB (SO-1: no proof records) (20). (d) R: SO-10's states, not a per-sample ratio: when in-use exceeds 1.5 × packed or file length 2 × in-use, status says `rewrite due` (or `not rewritten: it needs …`) and after the trigger the rewrite completes, file ≤ 2 × in-use and in-use ≤ 1.5 × packed, every acknowledged row still reads; a running daemon between the threshold and the trigger is not red (79, 80; 76 corroborated, its layout mutant is SO-5's proof). (e) F: after J5's recovery `nodes/<n>/` holds no `store.redb.failed-*`, `.rewrite` or `.tmp`; `vault.cbor`, `fingerprint`, `cursors`, `sessions`, `files`, `decisions`, `shares` are untouched and every acknowledged row reads (SO-9) (21's recovery half). | +4,228 ProofRange rows in 180 s for 4 bodies; 100.7 MB against 75.5 MB (`rca-RcaChurn.md` C1, C2); about 100 KB of ProofRange leaf per admitted entry under a wedge (`rca-StoreSize.md` §3.iii); no SO-15 fields. | 45 min |
| **J5** | *Disk full, and back; the pinned flows.* (Blocking as a fleet journey, J5(g) included, while ADR-047's in-tree full-disk journey is optional by his ruling; R-13, confirmed.) I's data directory on a sized `--tmpfs` in the Linux VM, or a 256 MB APFS image inside the macOS guest (ADR-047 SO-11; `hdiutil` in the guest, no `sudo`; attach failure = APPARATUS; nothing on the host, R-10), as E-9 decides; for (h) the image is inside the guest, as (h)'s "Where" says; the room fills it over at least 5 min of being full (seed time accounted); a member joins through I; a member leaves the room while it cannot save; space is freed. Then RcaSchedStall's recipe on the same node: three rooms, a second fill while the peer posts in all three for 60 s, free; the peer posts once more per room; I ends one room and leaves another. Then ADR-047's image arms (i). | 21 (SO-12's arms), 23, 24, 25, 64, 85, 86 | (a) R: below the floor the room says `cannot save: the disk holding … has N MB free` (SO-11, SR-2 words) and no whole-store rewrite runs at all (23); (b) R: the joiner is told the member's disk is full, not "usually the room passphrase is wrong", and its retry after space returns succeeds (SO-14) (24); (c) R: after space returns the room saves within 10 s (SO-11); (d) F: no `store.redb.failed-*` 60 s after recovery (SO-9); (e) F: `vox status` names the node's disk use and floor (SO-15) (25); (e′) F, ADR-042 TR-12 claim (2): a settlement save refused on the full image names the room and its cause (`cannot save: the disk holding …`) and is never called a join failure; ADR-042 names its mutant, J5 hosts it as the blocking fleet act (rulings 51/59); (f) R: `vox room leave` of the room that cannot save succeeds and deletes it at once (ADR-049 LE-2; the release-asset red route, `leave.rs:60`) (86). (g) R, SY-24: the staging asserts its own precondition before the free, eleven failed cleanups under the latch (`lanes.bounded.retiring` ≥ 11 on v0.4.30, the cap's edge; the ledger records the count), else `CANNOT MEASURE: 7 retiring flows, the cap was not reached`; after the second free, I shows every post made after it in every room within 30 s; `vox status` lists no `NOT ASKING` and no `no completed sync` line (the positive `NOT ASKING … retained_flows_full` rendering is asserted only on the baseline run of this staging and by TR-25's own proof, never on the candidate, F2); `lanes.bounded.retiring` is 0 within 60 s of the recovery (the ledger's diagnostic); then `vox room end` and `vox room leave` each have their room gone from `vox room list` within 60 s (ADR-049 LE-2, LE-4) (85, 64, 86). ADR-049's E-49a on the asset (`/tmp/Adr049Leave/run.log`, RcaSchedStall's staging): with flows in `retirement_failed`, `vox room leave` exits 1 with "an internal error", no log line, the room still listed; after a node restart clears the pinned flows the same leave succeeds (rc 0); a healthy member leaves an ended room at once. Also under (g), SY-24's nine-room act with ADR-047 SO-11's apparatus latch on eight rooms' commits (the ninth room keeps receiving while eight are latched; owner ADR-046 SY-24, apparatus owner ADR-047 SO-11), and SY-26's 17-node staging on the fleet (the anchors initialized for every existing room at the first v0.4.31 open across I's four, V's three and M's two nodes plus eight apparatus nodes; owner ADR-046 SY-26), both blocking here. Mutant for (g): keep counting failed flows in `can_retain_new`, or skip the retry on `StoreRecovered(room)` (SY-24's). (h) withdrawn at revision 15: ADR-044 RD-7's arm four, "the old waiter across recovery", and its held tokens, settlement and waiter verdicts no longer exist (ledger row 74, "one save, one trip"); RD-7's arms are in tree; the id is kept so earlier reviews read. (i) ADR-047's arms on the fleet's images, blocking here while optional in tree (R-13, confirmed; owner ADR-047 SO-2, SO-11, SO-12, SO-14): SO-2's multi-GB start on the nursery's multi-GB fixture on both hosts (the guest and the Linux VM) with wall time and peak disk use recorded in the run record, and its short-disk arms (i)–(iv) on a data root written by the v0.4.30 asset with 20,000 stranded proof rows (about 80 MB, RcaChurn's `relay75` recipe; 500,000 would not fit the image) with 20 MB free, then 2 MB free, and the multi-GB case on the nursery's multi-GB fixture with filler leaving 20 MB, then 2 MB: the first v0.4.31 open sweeps within the floor or says why not; SO-11's arms 1–1d (refused before the OS at 40 MB free with `cannot save: the disk holding …`; status unhealthy; the reclamation floor; 1c is J5(g); 1d: after SO-12's arm 2 leaves the store reopened but under the floor with a pending re-save and a flow in `retirement_failed`, the apparatus frees the filler and does nothing else, no post, no restart: within 10 s `recovered; it can save again`, the re-save's entry in `vox room read`, `lanes.bounded.retiring` 0, a post succeeds; mutant: an event that waits for the save it must follow); SO-12's arms 2–5 (the external race between admission and commit, reopen-in-place, the generation step, the refused reopen and the leaked holder; arm 4's refused reopen is staged by a writable second open or the `test-knobs` lock hold in the close/open gap, never a read-only open, which redb refuses with `Database repair aborted` and so stages nothing; arm 4b and arm 4c withdrawn (row 74: no settlement, no waiter, no token); **arm 4d** (ADR-047 SO-12 at revision 12, cited by id from the frozen copy `ADR-047.09700b194.md`, hash `8c6bb7e3e45b…`, in its tenth review and pending; the post-header position, the pre-header position and the confirming commit; on the `test-knobs` member; no v0.4.30 baseline, `CANNOT MEASURE`: the asset has no fault knobs). The unflushed suffix is received, non-ruled content: after the fixture's last ruled commit, a Session step alice's room admits, which flushes itself and is asserted apart through `vox room session`, bob's five received entries are admitted at `None` in R1 with no Inventory acknowledgment or other ruled commit between (the apparatus holds the Inventory), then `vox room leave R2` is issued while draining. Its acts: act 1: alice's post hits the post-header `fsync` fault → `cannot save: disk`, exit non-zero at once from its own commit, a second post queued behind it refused definitely at once → latch → one reopen → the confirming commit → reclamation (R2's queued deletion) → rooms rebuilt → `StoreRecovered(R1)`; the log orders `recovery: confirmed` → the first reclamation batch → `StoreRecovered`; `vox room read R1` after recovery and after a restart shows bob's five entries (the `None` commits the failed commit's header carried), `vox room session` shows the step, and the read shows alice's post or not, and either way no surface ever reports it saved; act 1-pre (the pre-header position): the same suffix on a populated root with many commits before this daemon's start, the fault at a data-page write of alice's commit → her post fails at once; after recovery `vox room read R1` lacks bob's five entries, bob's holder re-sends them on `Have` (SY-15), after which they show; before and after a restart the read agrees with itself; act 1-floor: the same with the image under the floor after compaction, no `StoreRecovered(R1)` until space returns, the rooms readable with SR-2's line; act 2: the reopened store's confirming commit also faulted → status `could not confirm it: confirming commit`, no `StoreRecovered`, no reclamation batch, the next reopen's commit succeeds; act 2-repair: the fault inside redb's repair commit → `could not confirm it: repair`, the next reopen succeeds; act 2-compact: `compact()` faulted with `No space left on device` while free + ballast meets the 16 MB reservation → rooms readable, the deferral line naming `compacting the store` and `n` = 16 MB, exactly one attempt in 30 s and no reopen, compaction resuming when the apparatus frees `n`; act 2-reclaim: the fault in R2's deletion batch at or above its 3 MB → the line naming `removing room R2` and `n` = 3 MB, the cursor unchanged, no second attempt for 30 s, the deletion resuming to `RoomRowsPurged(R2)` when `n` is freed; mutants SO-12's (`StoreRecovered` from the repair commit before the confirming commit; reclamation before the confirming commit; the recovered row reported saved; only the confirming commit's failure routed to the exit; the deferral dropped; rebuild from the latched handle's captured result instead of the reopened store (act 1-pre's mutant; the stale material is a captured read, never a live handle that would block the drain), the run FG-5 authorizes at the data-write position: the correct binary lacks bob's five entries until the re-send and the read agrees with itself across a restart, the mutant shows bob's entries while a restart does not, PRODUCT); what SO-12 owns beside these, cited by id and pending: after a ruled commit fails with an I/O error redb latches, the one commit in flight was answered `could not be confirmed` by its own caller, a request that attempts `begin_write` while the store is latched or recovering fails definitely before writing anything and its caller gets its definite receipt (`cannot save: disk`); a request still waiting for the writer mutex when recovery takes it, whose first transaction begins on the reopened backing, gets that transaction's own result and is not a replay; the writer is a mutex with no promised order (ADR-047 SO-12 as aligned with ADR-044 RD-7); SO-12 drains, reopens and repairs the same file, makes one `Immediate` commit to confirm the reopened store and raises `StoreRecovered(room)`, settling nobody; a refused open is retried; a failure during repair or the confirming commit is a new latch named in status); arms needing a hold or fault, and arm 1d as arm 2's contiguous continuation with no restart between them, run the `test-knobs` build on this member, the asset restored only after 1d's assertions) and SO-14's image arms (the member's store below the floor before a join: the joiner told the member's disk, the early challenge); each with ADR-047's own assertions and mutants; placement per E-9 (b)/(c), and on the Linux VM's tmpfs only after E-9 (a) has shown it charges blocks, not length, and fails at a data write (SO-2 step 5's sparse-file behaviour); until then the guest's image. | `.failed-1` kept for ever, a rewrite every 64 s (`rca-RcaPreparing.md` P3, asset); (h): withdrawn (row 74). (f) and (g): RcaSchedStall on the asset: 11 retiring flows after two cycles, every port `queued`, B's 24 posts never read, `no completed sync in 10 minutes` for all rooms at 10 min, `end` loops `cleanup stopped` 170×, `leave` "an internal error"; controls: no fill → every post ≤ 6 s; healthy node ends and leaves in 20 s. | 22 min |
| **J6** | *Trust changes stay in their room.* Rig5 and IoDrill shape under 2 posts/s: a computer-trust pass that cannot finish in one room because that room cannot save (I's room on the full image): under ADR-048 TC-5/TC-9 the room's trust debt parks on `StoreRecovery(room)` and no sibling room is marked (J6(a) asserts TC-9-A as ADR-048 states it; the fleet's stand-in for plan D's failure fixture; the left room's reservation red, plan D's `rig26`, is ADR-048's own); then `vox trust add`, `vox node create`, a computer removal and two joins; pending read marks, a key delivery and a settlement staged before a policy move; the creator ends a second room while one member is unreachable, and is restarted mid wind-down. | 9, 26, 27, 31, 32, 36, 38, 64, 65, 66, 67, 93 | (a) R: while the pass is parked in the full room, every other room reads and accepts a post ≤ 10 s, the parked room prints TC-8's words, and `vox room list` shows no `[failed:` row at any later start or policy move (ADR-048 TC-9-A; ADR-049 LE-1 for the left room) (26, 27); (b) R: from a join's acknowledgment, every member renders every author's posts ≤ 10 s under traffic (9); (c) R: the staged read marks, key delivery and settlement are all visible after the revision move within NW-12's bound (32, 38; CJ-14 withdrawn, a node create is one revision move); (d) F: in rooms the removing computer administers, the removed computer's nodes are gone from members and their posts refused ≤ 60 s, no trust offer for them afterwards (CJ-11, durable), and for other rooms the residual-room command is printed (CJ-12) (36); (d′) F, owed extension (ADR-043 CJ-12 (iii′); ADR-047 SO-9): *a computer removal with a room whose store cannot be opened*: on A, node a1 creates R5 with B's node as a member; stop a1 and overwrite its store header as SO-9's corrupt-store arm does; start A: `vox status` prints SO-9's `the store at <path> could not be opened: <redb's words>; it has not been changed` and a1's other rooms are untouched; `vox computer remove <B>` with `y`; green when (1) A's `vox computer status` state line reads `removing <B>: R5 cannot be opened (<redb's words>), so <b1> is not removed from it yet` with `Next here: vox doctor (the removal finishes by itself once the room opens)`, and `--json .removal_work[]` shows R5 `waiting`, the other rooms `done`; (2) after `vox node restore` of a1 from its backup (ADR-038 FX-32), within 10 s `vox room roster R5` lacks b1 and the state line is clean; or, in a second run, after `vox node delete a1`, the R5 entry leaves the record and the state line is clean; baseline: v0.4.30 UNVERIFIED (no removal record exists; the corrupt-store arm is SO-9's); mutant: mark R5 `Done` when its open is refused: (1) shows a clean line while `vox room roster R5` (after restore) still lists b1, red; (e) R: a key request made during the policy move is served after it ≤ 30 s and a real extension turn in that window completes without a conversation restart (NW-3; the "governance is refreshing" refusal's exact tear is NW-11's in-tree proof; in stage 2 the real extension runs against M′ or this claim is `CANNOT MEASURE`, never emulated) (31, 65); (f) R: after the failed pass, the retry edge (space returned) leads to accepted posts ≤ 30 s (NW-3) (67); (g) R: the typed refusal NW-2 names (a held trust debt or a package not acknowledged, staged by NW-2's apparatus; the ledger records the `NotYet` the product printed) causes no store recovery: no `.rewrite`, no `.failed-*`, unrelated work continues; a run in which no typed refusal was recorded is `CANNOT MEASURE` (NW-2) (66); (j) R, ADR-048 TC-4's act 12 (fix-list item 93; rows 82, 82b): a busy member (closed-loop posting at 2/s in a room of the group) keeps posting through a roster change on its computer (a `vox trust remove` and a `vox node create`): no post is refused for the change, every post is acknowledged within outcome 7's bound and renders on every member within RD-3's 5 s, and the control turn lands within its lane bound (at the head of its lane, at most the transaction in flight plus one authored write); mutant: ADR-048's (the policy application waiting for the room to be quiet) → posts refused or acknowledged late, red (93); (h) R: the ended room is listed `[ended: …]` with TR-2's ended verdict, raises no `sync failing` line, and is gone ≤ 70 s (ADR-049 LE-4), also when the ender restarts mid wind-down; the pinned-flow variant is J5(g) (64). | `[failed:` rows for ever (operator IO); io-drill lost rotated authors; revision drops (plan D); E-64b on the asset: `sync failing` at +50 s, gone at +70 s. (a): KNOWN by code, red route unverified on the asset until J6's baseline run (E-8). | 15 min |
| **J7** | *Restart and update need no human.* M and B: 10 registered conversations, the real extension under the host shim (one continuously active); `vox daemon --restart` three times on each (a restart is a race: the repeats are rate smoke, ADR-018 §10.9); `vox update` candidate → candidate on both; then the one-time update 0.4.30 → candidate on B; on B, one `vox update` whose candidate is a copy of the release `vox` with one version-need name rewritten by `fleet/dead_candidate.py` in the guest (ADR-051 LB-6's dead-candidate apparatus, `GLIBC_9.2.5`), served the way this act serves its candidate release; where that source is GitHub only, the act is CANNOT MEASURE, is not counted as asset coverage and never appears as a passed claim, and ADR-051's in-tree arm (e) is the blocking proof. B runs under the keyring-permitting seccomp profile (FG-4); the manifest names it. The operator's beast (ledger row 21): its daemon is no unit's main process (ppid 1, session scope, systemd 259), so J7's B stages both the managed case (the driver's supervisor as manager) and the unmanaged root, which ADR-041 shows `unsupervised` (RS-5). | 28, 29, 30, 39, 40, 41, 42, 43, 44, 47, 71, 81, 91 | (a) R: during each restart window a sibling node's real turn completes ≤ 10 s and every conversation registers and takes its next turn (NW-8, NW-9) (28, 29); (b) R: a turn landing in the refusal window completes without a conversation restart (ADR-050 TJ-10 through ADR-041 RS-7's real-extension journey; acceptance TJ-10-A: twenty held commits through restarts, zero of either text (`uncertain`, the stale-advice line), every message delivered once; the window is staged by the restart, not left to the 60 s cadence) (30); (c) R: candidate-to-candidate, B is Ready with no input after every restart, the update and a `kill -9` of its daemon, its passphrase held in the kernel's persistent keyring (RS-1, RS-2); (c″) F: B under podman's default seccomp profile: `vox node unlock` says the kernel refused, asserting RS-1's refusal line with the errno the recorded profile actually produces (RS-1: `add_key: Operation not permitted`, EPERM, under Docker's default `SCMP_ACT_ERRNO`; `add_key: Function not implemented`, ENOSYS, under podman's current default action; the manifest records which profile ran and the act asserts that profile's errno, never a hard-coded one), and what that costs, and promises no restart (RS-1's refused case); (c′) F: the first update from 0.4.30 prints RS-4's warning and asks the passphrase once (39); (d) R: the extension prints nothing or ADR-041's restart line, never "node … is unavailable … vox node create" (RS-4's exception: an extension loaded before the update may print its old advice once at that one restart, and the ledger records that one line as expected), and the turn in flight completes after reconnect with its context delivered (RS-7) (40); (e) R: the manager stays the daemon's owner: the daemon's own start and stop lines, `ps` at 10 Hz through the window, and no second process ever holds the socket (RS-5) (41); (f) R: a conversation whose OMP process was killed is ended and listed as ended within 150 s (two checks 60 s apart) with exactly one `OMP ended` and one `bye` in the room's history, raises no follow notice, and a conversation whose OMP lives through the same window is never ended (RS-8); the 24 h on-disk removal is RS-8's clock-knob proof, not a fleet claim (42); (g) R: claims made on 0.4.30 are kept as level 1 and stay on the board, retained until the first room transition after the update, and coordination continues once every worker is updated (RS-10) (43); (h) R: a resumed conversation is listed by `vox room sessions` before its first claim (RS-11) (44); (i) F: the driver stops the daemon by pid and the stop line names that sender (RS-6); the original sender of item 47 stays unknown (47); (j) R, RS-5's acts (ADR-041): after `kill -9`, and after a clean external `kill -TERM` with no client request, the login-item daemon in the guest is back ≤ 15 s with a remote read as the verdict and a real turn completes ≤ 60 s after; the operator's shape (a detached daemon serving while the login-item job is registered and not running: the manager takes ownership and no second daemon ever holds the socket); the restarter killed after the stop (the manager still brings the daemon back ≤ 15 s); the restarter killed after `kickstart` and before the stop (one daemon, the manager's, within 15 s) (81); (k) R: a `daemon.log` planted before the restart that is oversized for the candidate (above TR-17's current-file limit, 3 MiB) with a torn last line, 2 MiB of valid lines and a known oldest line: after the restart the oldest line is in the ring and no file was truncated (TR-17) (71). (l) F: the dead-candidate update exits non-zero, prints ADR-051 LB-5's lines, and B's daemon and `vox --version` are unchanged (91). | refusals and poisoned conversations (`rca-RcaTrust.md`, instrumented run s3; E-30 is the asset route, ADR-040); Locked after every Linux restart; the extension's text; a competing daemon; stale registrations (`rca-RcaSessions.md`). | 15 min |
| **J8** | *Start over, and the updater sees the app.* Guest only: the profile is rebuilt by `vox factory-reset --confirm-move-aside <name>` with a daemon running and a leave pending (ADR-041 RS-15 at revision 8, cited by id from the frozen copy `ADR-041.01cad8419.md`, hash `80bb71d61d2e…`; the hand rebuild of the earlier rigs is replaced, no new journey), and J8 asserts RS-15's three lines as the command prints them: `vox: stopped the vox daemon (pid <n>, <manager>)`, `vox: moved <data folder> to <data folder>.reset-<time> (<k> nodes, <size>)`, `vox: this computer now has no nodes and no computer trust; <the manager> serves the new folder`, then `vox status` saying what it left, judged from the folders' identities; the refusal arm (an orphan writer; a wrong or missing confirmation, exit 2, nothing changed) and the confirmation arm stay in RS-15's in-tree proof; `vox update` with the app stopped (`SIGSTOP`) and with a stand-in app that quits 40 s late; leave and rejoin on a node. | 10, 45, 46, 48 | (a) R: the old daemon stops or refuses the new root by name (RS-13); (b) R: the new identity is Ready, no post of the old identity appears in the new profile, and the new profile's posts survive a restart while the old peer returns (RS-14) (45); (c) F: the updater says what it saw ("it was stopped" / "quit on request") and never rolls back a quit that happened (RS-16; item 46's original cause stays UNKNOWN: RcaAppQuit reproduced neither reading in the 26.6.2 guest) (46); (d) R: after leave and rejoin the node's post is accepted ≤ 10 s and renders on a member ≤ 10 s (SY-11) (10); (e) R: a conversation started before the rebuild is refused by name with old and new identity named and never posts as the new node; a newly authorized conversation works (RS-9) (48). | `rca-RcaStore.md`; rejoined posts refused for about 6 min (`io-repair-drill.md`); `rca-RcaAppQuit.md`. | 10 min |
| **J9** | *Pairing and computers* (ADR-043's journeys on the fleet; ledger row 2). `pair` against an unreachable inviter; `vox computer status` through its states; the app's pairing code; `vox room pause` across computers; `vox node create`; a rebuilt computer with the same hostname; a one-sided proposal cancelled; an unconfirmed attempt healed by `pair` again; a close racing an approval; a kill between claim and record; a removal drained across a restart; CJ-17's act as J9(i) (fix-list item 92; E-43-1 was its spike); ADR-043's spikes E33b, E35, E38b (the revision count across a node create) and E-43-1 may run as host scratch runs under FG-4's host rules and are reported, never committed (ADR-018 §10.4); J9(i) inside the VMs is the blocking proof, and E38b's fleet form is J9(e). | 33, 34, 35, 37, 38, 74, 75 | (a) F: `pair` against the unreachable inviter says so within CJ-7's bound and names the next action (33); (b) F: `vox computer status` prints CJ-1's two lines and the next command in every row CJ-1 defines, asserted as CJ-1's rows and never as v0.4.30's `state` names; the three "not yet applied here" rows are each staged: (1) a trust change held behind a room's trust debt (ADR-048 TC-8's words; staged by J6(a)'s full room on this computer), (2) a policy change whose application is parked on NW-1's typed prerequisite (staged by a sibling node still starting, NW-8's window), (3) a locked node (`vox node lock`, `Next here: vox node unlock`) (34); (c) F: the pairing code within 2 s from the CLI (CJ-8) and ≤ 5 s in the app with Retry (CJ-4); item 35's original cause stays UNKNOWN (35); (d) F: `vox room pause` from another computer is accepted or names the node that can pause and its command; posting is not stopped (CJ-15, PA-2) (37); (e) R: during `vox node create` the sibling's 20 of 20 posts land (NW-12); E38b's blocking form (ADR-043 CJ-16): CJ-14's application trace is spike apparatus only; J9(e) asserts the user outcome (no J6(c) loss) and reports the observed binding-derivation changes (38); (f) F: a rebuilt computer of the same hostname is a new computer through preview, approval and status (CJ-9) (74); (g) F: cancel ≤ 2 s, a new invite ≤ 2 s, remote closure ≤ 5 s, a late approval refused (CJ-6, CJ-8) (75); (h) F: the four new ADR-043 journeys with their own bounds (CJ-5, CJ-6, CJ-8, CJ-12), UNVERIFIED on the asset until run; `/tmp/adr043/run-x1`, `run-x2` were receipts for the rollback divergence class and the same-code replay only (receipts lost in the reboot of 2026-11-13; figures recorded in `adr-043-revision`; to be re-run as J9's fleet baseline). (i) *A relay-only computer learns a new node* (ADR-043 CJ-17; fix-list item 92). A and B each `vox node create` then `vox anchor add <fleet anchor>`; A invites, B pairs, A approves; both `vox computer status --json` `.state` = `confirmed`; B's daemon stopped and restarted with `VOX_LISTEN=[::1]:0` and the same anchor (A cannot dial `[::1]`; staging check: b1 not directly connected to a1, else APPARATUS); `vox node create a2` on A. Green when: (a) within 60 s `vox trust list` on b1 lists a2, both `.state` = `confirmed`, `--details` without `problem`; (b) control: B restarted on `127.0.0.1:0` with no anchor configured anywhere; (a) holds and `vox computer status --details` never mentions an anchor. Baseline: red on v0.4.30 as measured (`rca-relay-only`: `R1-base.out:34`, `R3-anchoraddA.out:35`; `E43-relay-*`). Mutant (CJ-17): `set_anchors` dropped from `deliver_manual_anchors` → (a) red with `computer relay: peer unreachable: no anchor configured for this computer pairing` then the causal-deadline text; (b) stays green. | waits out the code; no next command; `already signed` (`adr-043-revision.md`, asset X1/X2); E-1: y1 never learned n-new at 0 ms and at 1.5 s (E-b). | 10 min |
| **J10** | *The product tells the truth under load* (ADR-042's proofs on the fleet, folded into J1–J9, plus staged refusals). The `NOT RECEIVING` staging is ADR-042 TR-4's apparatus server (a connected member that advertises and serves nothing, ADR-018 §9.2; built by ADR-042 TR-4's owner as its proof-host task, the fleet drives it); the silent member is a stopped daemon; a refusing daemon answers a dial for a node it does not hold; the `NOT ASKING` staging is J5(g)'s stalled node; no repair facility ships in v0.4.31 (the decider, 2026-11-13, ledger row 22: item 53 closed "not in 0.4.31, by ruling"); the watchdog and its operator-only restart advice stay (TR-13). | 49, 50, 51, 52, 53, 54, 56, 70, 73 | (a) F/R: with the apparatus server, the room shows `NOT RECEIVING: N entries behind, nothing received for <dur>` within RECEIVE_PATIENCE + 10 s (TR-4) and the one member's line names it (TR-5); with a stopped member, `waiting for a member` (TR-2); with members connected and no inventory for INVENTORY_FRESH, `NOT HEARD FROM` (TR-25); on the baseline's stalled node (J5(g)'s staging on v0.4.30, the pre-SY-24 state) the candidate's status words are what TR-25's own proof asserts, `NOT ASKING: <N> entries wanted …` within ASK_PATIENCE + 10 s with TR-25's own refusal words (under R1 `its sync slots are held by <k> rounds whose cleanup failed`; under R2, the chosen mechanism, no retained flow exists and TR-25 names what it then prints), while its sibling reads `up to date with all <n> members' inventories` (TR-24); that positive rendering is TR-25's proof on its held-demand apparatus (ADR-042 TR-25's stall act, on SY-24's rig with a real sibling), because a candidate with SY-24 correctly never enters the state; on the candidate J10 asserts the absence of `NOT ASKING` and the delivered posts of J5(g) (F2); a brand-new joiner's first status reads `catching up … with 1 of <n> members' inventories`, never `up to date` (TR-24); each asserted as TR-4's, TR-24's and TR-25's exact lines with their `UNHEALTHY` keys (`room-no-inventory:<room>`, `room-not-asking:<room>`) watched in `vox status --json` and TR-1's outcome fields (`entries_behind`, `last_entry`, `coverage`) read beside them; and never any of these while the ledger shows the contrary (J13's truth outcome) (49, 85); (b) F: every text in ADR-042 Appendix D's rewritten messages is induced on its branch by its producer (the list in the journey file follows Appendix D's ownership) and the replacement text appears; a branch not induced is `CANNOT MEASURE`, never a pass (50); (c) F: `vox status` lists every preparing room (TR-8); a daemon older than 10 min that gains its first peer shows no stale "no completed sync" (TR-1's in-memory origin); the keyring line is a fact row and never adjacent to health (TR-9, owner proof's line-index assertion reused) (51); (d) F: no `vox room repair` exists and no surface offers one (ledger row 22; TR-14 and TR-15 withdrawn with ids kept); on J5(g)'s baseline staging the watchdog's 5-second check names the condition and prints TR-13's operator-only restart advice, and on the candidate (where the condition cannot arise) it prints nothing of the kind; the no-rejoin rule holds (`--rejoin` absent, TR-16); item 53 is closed by ruling, not proved (53); (e) F: 48 busy hours of log (19.3 MB of valid lines at 2 × 201,217 B/h, planted by the driver across `log` … `log.7`) survive rotation and a restart with the oldest and newest lines and each repeat's `count`/`last` intact; the ring's eviction past `log.7` is the one deletion (TR-17); mutant: a retention cut at 2 MiB (54); (f) F: a dial answered by a refusing daemon shows `not attached`, never `unreachable` or "Locked"; that address is not dialled again for 60 s, and the reach still asks each connected coordinator for a dial-back at most once per reach, logged at debug (TR-19, TR-20) (56, 73); (g) F: a line repeated across a restart carries first time, last time and count (70). | green while starved; "has not trusted" for a sync cause; no repair verb; evidence lost in hours; "unreachable" for an answered refusal (consolidated analysis row 15; `rca-RcaLanPath.md`); robert-work 01:33–02:16Z (replay (d) of ADR-042). | folded, +10 min |
| **J11** | *Linux install and buffers.* B; the `x86_64` asset under emulation for `install.sh`, the load build for the daemon; RD-12's kernel arm as root in the podman VM's initial namespace (ADR-044; ruling row 69): the driver records the VM's kernel and the value before the run, sets `net.core.rmem_max=212992`, runs the installer, starts the installed daemon, and restores the value after. ADR-051's four install images, each `x86_64` under emulation and pinned by digest: `almalinux:8` (glibc 2.28, the floor), `ubuntu:22.04` (glibc 2.35, the operator's Pop!_OS 22.04), `ubuntu:18.04` (glibc 2.27, below the floor), `alpine:3.20` (musl, no GNU loader); the manifest records each image's C library as read in the run; the installer acts run as an ordinary user, apart from RD-12's kernel arm. | 19, 55, 72, 91 | (a) F: `install.sh` reads back `/proc/sys/net/core/rmem_max` and prints RD-12's success text when it raised the value to 4194304, or its two-command text with the value read when it could not; after a successful install the daemon it starts prints **no** small-buffer line and `vox agent doctor` prints no `network:` warning (the buffer is large; silence is the assertion); (b) F, RD-13, staged apart: the driver lowers `net.core.rmem_max` to 212992 as root in the VM (row 69) after the install, restarts the daemon: it prints the small-buffer line exactly once per start and `vox agent doctor` prints the remedy; then the driver restores the value it recorded before the run (19); (c) F, TR-18's two acts: with `DISPLAY` and `WAYLAND_DISPLAY` unset, an attention event produces the attention line within 10 s and no `notify-send` is executed and no `not available` line; with `DISPLAY=:0` and a `notify-send` stand-in that sleeps 30 s and exits 1, the stand-in runs once, exactly one `desktop notifications are not available here (…)` line is printed per daemon run, and the attention and recovery lines still arrive within 10 s (55, 72); (d) R: the `DISPLAY=:0` act under J13's slow-notifier fault: the attention note and the "recovered" note within TR-18's bound; the event is scored, not exempted (72). (e) F: on `almalinux:8` and on `ubuntu:22.04`, `install.sh` against the candidate `dist/` exits 0 and `~/.local/bin/vox --version` prints the candidate's version (ADR-051 LB-1, LB-2; the v0.4.30 asset on `ubuntu:22.04` is the red baseline: ``version `GLIBC_2.39' not found``); (f) F: on `ubuntu:18.04`, with `getconf` present it exits 1 before any request with ADR-051 LB-4 (i)'s line, and with a failing `getconf` shim it exits 1 after the run check with LB-4 (ii)'s lines and leaves nothing under `~/.local/bin` (LB-3, LB-4); (g) F: on `alpine:3.20` it exits 1 with LB-4's missing-loader sentence naming `/lib64/ld-linux-x86-64.so.2` and leaves nothing under `~/.local/bin` (LB-4). Mutants: (e) the stand-in server serves an incompatible binary (the published v0.4.30 asset) under records written for it; (f) the pre-download check skipped, and `2>/dev/null` restored on the run check; (g) the missing-loader sentence replaced by the generic one. | "raise net.core.rmem_max" at every start; a GDBus error per attention event; notes up to 120 s late (plan G, E2). | 4 min |
| **J12** | *Update with live rooms, and the old regressions.* Appendix A rows Q1 (update with live rooms), Q7 (fresh profile, v0.4.27), Q8 (busy-room board, v0.4.28) and Q9 (burst delivery, v0.4.30), on the room model; Q11's smokes (the guest smoke of the app, the Linux consumer smoke, `check-release-assets.sh`) on the candidate assets without notarization and Gatekeeper (FG-2). Q5 (mixed versions) is withdrawn: all machines move together, no mixed-version sync (ruling R-8). | 40, 43; v0.4.27–v0.4.30 regressions | the rows' pass conditions as written in Appendix A. | as recorded in the v0.4.27–v0.4.30 release posts. | 18 min |
| **J13** | *The soak* (FG-12, FG-13). | 57, 85, 87, 64, 86, and every item above under faults | the blocking outcomes of FG-13 with FG-12's coverage. | the grower's first run (E-5). | 5 h per candidate (ruling R-9; FG-12 "What a day would have caught") |
| **—** | *Held elsewhere.* | 21 (poison), 53 (by ruling), 58, 59, 60, 61, 62, 63, 76 (layout), 82, 83, 90; 16 (durability, all in tree), 30 (journal), 31/65 (refreshing refusal), 42 (24 h deletion), 68, 69, 77 (write cost) | 21: ADR-047 SO-13, review plus ADR-047's spike E-7 (a full disk cannot grow; the other poisons need a knob). 58: FG-6's keychain rule. 59: one holder, ADR-047 SO-2: the first v0.4.31 start deletes every `store.redb.failed-*` (J5(d) and J5(i) prove it on the fleet); on beast that happens when the operator installs v0.4.31, which is his go by AGENTS.md; no separate procedure. 60 and 82: FG-15, FG-16. 61: ADR-039 is written after stabilisation; no proof; its release disposition is Main's to state. 62: `gh run rerun` outside this repository; its receipts are the runs' completion. 63: J6(d) proves the product; the live clean-up on IO is a procedure with his go after v0.4.31 lands; the fleet observes nothing of IO. 76: SO-5's layout mutant proof. 83: FG-5. 16: RD-7's in-tree arms, all of them (row 74 withdrew the fleet act). 30: NW-10 in RS-7's file. 31/65: NW-3 and NW-11's in-tree proofs (a knob holds the refresh). 42's on-disk removal after 24 h: RS-8's clock-knob proof. 68: RD-6. 69: TR-6's apparatus-server proof. 77: SO-6's named-session write-cost journey. 53: closed "not in 0.4.31, by ruling" (row 22), no proof. 90 (the reader pages): FG-13's reader, which every journey and the soak use; no journey of its own. The failed-retirement state of item 64 no longer needs a knob: J5(g) stages it on the asset. | — | — |

Total for J1–J12: about 3 h 25 min per candidate as an estimate (the rows above, 12+8+35+45+22+15+15+10+10+10+4+18 min, plus
staging; not a measured end-to-end receipt), then the soak.

- **FG-9. Every claim has the evidence of its kind.** *(changed: finding 14.)* Three things are
  kept apart:
  - An **R claim** (root cause) MUST be red on the baseline assets with its trigger, on its own
    assertion, labelled `PRODUCT:`, and green on the baseline with the trigger removed (the
    control run). Both runs are recorded once as the claim's receipts. A claim green on the
    baseline with its trigger is not evidence for the item it names; a claim also red in the
    control has another cause, which must be named before the claim counts (rulings R-5, R-6).
  - An **F claim** (feature) MUST be red on the baseline because the behaviour did not exist
    (the field, the verb, the words), or, where the baseline happens to pass, under a
    deliberate product mutant named in the journey file (ADR-018 §10.10). It has no control
    run; changing traffic does not add a command. An R claim's control removes the trigger and
    nothing else: a control that also removes the session or observer the claim needs (the
    real conversation of J7(b), the reader of J1(f)) is not a control.
  - An **apparatus self-check** (a refused asset, an unmet precondition, a killed sampler) is
    not a proof of anything about the product and is never called a mutant.

  The baseline run records every claim's own assertion, not only the first failing one: a
  journey continues past a red claim until its staging is lost. Controls known today: J1,
  E-1's 0 ms run and RcaFrozen's `ctl-pause` and `ctl-no-n-old` (KNOWN green); J2, direct
  loopback, 542/542 (KNOWN green); J3, the same load without the ten sessions (INFERRED green:
  RcaSlow S1 appeared only with them); J4, the direct path with the same workload; J5, the same
  room with space; J6, the same changes with posters stopped; J7, restarts with no conversation
  registered; J8, a rebuild with the daemon stopped; J9(e), no node create. J13's first 30 min
  without faults is a baseline of the load alone, not a control for faults: a red there is a
  product red of the load (items 1–3 on v0.4.30), and a red after a fault is attributed to the
  fault only if the same claim held in the no-fault prefix.
  - *Why*: rulings R-5 and R-6; ADR-018 §7 ("a green gate is not evidence"), §10.10; the draft
    matrix's Q3 ("Baseline discriminates … else Q2 is not evidence"), generalised.
  - *Changes*: each journey file is to list, per claim, its kind, its trigger, its control or
    mutant, and the paths of its receipts; the gate refuses a journey whose receipts are
    missing: `CANNOT MEASURE: J4(c) has no recorded control run`.
  - *Proof*: recording the receipts is the proof; a reviewer reads them (FG-11).

- **FG-10. No fix without a reproduced root cause.** A product change for an item MUST land only
  after the item has been reproduced on the baseline with its trigger, and not reproduced
  without it, by a journey of this matrix, by the item's in-tree proof, or by a reproduction rig
  run on the baseline asset with its control (E-1 is one). For an item whose cause is UNKNOWN
  (items 11's IO instance, 35, 46, 47, 60, 87, E-b; item 85 is KNOWN since RcaSchedStall), only two kinds of change MAY land before
  that: a change that makes the cause observable (a typed close reason, a stop line naming the
  sender, the capture of FG-16, ADR-042's outcome fields); and a change whose own defect is
  KNOWN (true status, recovery after the condition ends, a leave that always succeeds). A change
  justified only by an inferred cause MUST NOT land. A shared symptom reproduced once does not
  reproduce every cause attributed to it: the receipt names which cause it showed.
  - *Why*: ruling R-5; G-1's v0.4.26–v0.4.30, each "fixing a symptom without a reproduced cause"
    (consolidated analysis §2 G).
  - *Changes*: each fix's pull request names the journey, proof or rig that reproduced its
    item, the mutant receipt and the control.
  - *Proof*: the reviewer's own run (FG-11).

- **FG-11. Reviewers run the journeys themselves; which journey, by stage.** *(changed: finding
  6; standing-rule consistency; r6: R-11 answers Q1.)* A reviewer of a fix MUST build the
  fix's commit into assets (`scripts/build-linux-release.sh <dist>` in the Linux VM, then
  `scripts/release-dry-run.sh <out> <dist>` in the guest; ADR-051 LB-2) and run, himself,
  the journeys whose claims the fix's item is mapped to, and MUST read each claim's receipts.
  The author's receipts are not the review's evidence. The run is the review's one run
  (AGENTS.md "Run a proof once"); a matching receipt (FG-1's key) is reused, not repeated; the
  candidate's full run at the gate is not a repeat of it but the gate's own. What a reviewer
  runs depends on what exists:

  | Fleet stage (FG-17) | A fix mapped to | The reviewer runs |
  |---|---|---|
  | before stage 1 | anything | the owner's in-tree proof and the item's reproduction rig on the fix's assets with its control; the fix is accepted "pending its journey" and the item stays open on the milestone until the journey has run green on it |
  | stage 1 | J1, J2 | that journey on loopback |
  | stage 2 | J3 (0.5 GB), J4, J5, J6, J11 | that journey on the containers |
  | stage 3 | J7, J8, J9, J10, J12, J3 (≥ 2 GB) | that journey with the guest |
  | stage 4 | J13 only | the fault scenario the item names (FG-12's table), as a bounded act, never the whole soak; the whole soak runs once per candidate at the gate |

  A reviewer runs one journey as:

  ```
  $ fleet/gate.py --assets ~/vox-fleet/assets/pr-1234-7c1d2b --journey J2
  fleet: J2  a relayed pair 75 ms apart keeps up ....................... PASS   7 min 40 s
    J2(a) act 75 ms: every post rendered ≤ 5 s (max 2.8 s, 677 posts)
    J2(a) act 37.5 ms: max 1.9 s (344 posts)
    J2(b) keys readable both ways at 1.4 s (bound 30 s)
    …
  fleet: receipts ~/vox-fleet/receipts/2026-11-18T1402Z-7c1d2b/J2
  ```
  - *Why*: ruling R-4; ADR-018 §12.4 ("A green obtained by retrying a red MUST NOT be accepted as
    evidence") and the five releases each approved on the author's green.
  - *Changes*: ADR-018 §10.9's "A verifier MUST NOT re-run the fixer's greens" and AGENTS.md's
    matching line are amended for fleet journeys (see "Superseded and amended lines"); ADR-018
    §10.13's reuse rule is what FG-1's receipt key implements.

### 4. The soak

- **FG-12. The soak runs the room model under a fixed schedule of the operator's faults, then
  random ones.** *(changed: findings 7, 15; ledger row 11.)* J13 MUST run the room model on the
  full fleet from the current nursery snapshot, the candidate on every computer (the one-time
  update from 0.4.30 is J7(c′), not a soak act; no mixed-version act, ruling R-8), with three
  closed-loop authors, ten stepping sessions, two announcing sessions (about 100 a minute), at
  least one real OMP conversation under the host shim taking a turn every 60 s throughout
  (so items 30, 40 and 44 are observed where the extension runs), and every node of every
  computer reading at 1 Hz. Faults are applied in Antithesis's order: none for the first
  30 min, then the faults a member must survive, then those the room must survive.

  **Schedule.** The schedule is fixed first and random after. The fixed part MUST apply every
  fault of the table once per target class, and every overlapping scenario S-1 to S-5 once; the
  gate reports coverage as `n/n`. After each fault's heal the driver MUST wait out that fault's
  recovery interval R and measure it fully (FG-13) before the next fault starts; the next fault
  starts 60–180 s after R ends, chosen from a seed recorded in the manifest. The random part
  draws faults, targets and durations from the same table under the same rule for the rest of
  the run. Every fault and heal is written to `faults.jsonl` with its time, target, arguments
  and attainment (the path shown, the disk full, the process stopped). The driver can replay a
  run's schedule from that file; replay reproduces the schedule, not the kernel's or QUIC's
  timing, and is help toward a reproduction, not one.

  | Fault | How | Heal | R (recovery interval) |
  |---|---|---|---|
  | daemon restart | `vox daemon --restart` on one computer (the operator did 9 on the Mac and 6 on beast in two hours) | — | RD-11's open bound + 30 s |
  | update | binary swap and restart as `vox update` does, candidate → candidate, once per soak | — | as restart |
  | trust change | `vox node create` on a computer; a computer removed and paired again; `vox trust add` of a late joiner by hand | pair again | 60 s |
  | join and leave | a late joiner joins under traffic (one of the six in turn); a member leaves and rejoins | — | 60 s |
  | room end | the creator ends a room while one member is unreachable (E-64b's shape); a member leaves an ended room; a member that never learned the end leaves it | the member returns | 70 s (NW-7), at once (NW-15) |
  | full disk | I's image filled to 100 % for 2 min | space freed | 10 s (SO-11) |
  | storage failure, retained (SY-24's trigger, RcaSchedStall's recipe) | I's small disk image (RcaSchedStall used a 64 MiB HFS+ image on macOS; in the fleet a loop image inside the podman VM or the host-side APFS image, whichever reproduces redb's latched save failure, settled in stage 2) filled while the three heavy authors keep posting in every room I holds for 60 s, freed, filled again for 60 s, freed; traffic continues in every room throughout | the second free | 30 s (every post made after the free renders on I; `NOT ASKING` never printed after the free + ASK_PATIENCE); then I ends one room and leaves another: gone ≤ 60 s (NW-7, NW-15) |
  | slow peer | S's sessions doubled for 5 min (busy responder), or a member's hop delayed 1.5 s for 5 min (delayed member); the ledger says which | sessions halved; delay 0 | 120 s |
  | network change | the guest's forwarder front moved to a new port (an address change); V's netem raised to 300 ms and 5 % loss for 3 min; one member blackholed toward all peers for 20 s (the 15:04Z shape, FG-15 A-2) | restore | 60 s |
  | swizzle-clog | a random subset's paths stopped one by one over 10 s, restored in random order (FoundationDB) | — | 60 s |
  | anchor restart | A restarted (the real one restarted at 15:19:44Z) | — | 60 s |
  | process pause | `kill -STOP` of one daemon's serving process (never the `vox daemon` wrapper, Context 9) for 12 s (a crash-and-scheduling condition, not a slow member) | `kill -CONT` | 30 s |
  | slow notifier | B's `notify-send` stand-in sleeps 100 s (J11(d)); scored, not exempted | restore | TR-18's bound |

  **Fault contract.** Every fault row states what the product is expected to do on its target
  during the attained fault, and the checker scores that, never the healthy expectation (N1):
  a paused daemon's nodes answer nothing (every `vox status` and `vox room read` sample on them
  during the attained pause is recorded as `unavailable (paused)` and is neither outcome 7's
  red nor FG-14's expired wait; from `CONT` the first answer of each within R is the claim); a
  paused author's pending operations are a contract too: a `vox room post` or step issued to a
  node before a fault begins on it and not yet returned is **pending-on-fault**: its latency
  bound (outcome 7's 1 s, RD-14's 5 s step acknowledgment) is replaced by the fault's recovery
  deadline, heal + R, recorded beside the original; it must return by then with an
  acknowledgment or a truthful refusal (any other outcome is a red); a bound that had already
  expired before the fault began keeps its red; an acknowledgment that arrives, during or after
  the fault, is ledgered like any other and creates its delivery obligations under outcome 1
  (with the fault's prospective deadline toward the fault's targets); the driver issues no new
  operation to a paused node (an acknowledgment that arrives during a pause is impossible and
  is recorded if seen); a node on a full disk
  refuses posts with SO-11's words (a refused post with that text is a truthful refusal, scored
  by outcome 8's words and not as a failed post; any other failure is a red); a removed node's
  post is refused by name (CJ-12); a blackholed member's status says silence (TR-3); a delayed
  member's `rtt_ms` is ≥ T. What is never exempted: an acknowledged post's delivery to an
  eligible member by its deadline as outcome 1 fixes it, the recovery clock from the heal, and
  the words. **Fault onset** (F3; fourth review, point 2): a fault's row says which of two
  onsets it uses, and the schedule records which it used. **Under load** (the default; every
  fault of the table in the random part, and the overlapping scenarios S-1 to S-5, whose point
  is the fault landing on a saturated writer, a pending trust change, a mid-join or a wedge):
  traffic keeps running; at the fault's first instant every obligation toward a target that is
  still unexpired gets the fault's deadline (heal + R) prospectively, recorded as a second
  deadline beside the original with the fault's id; an obligation already expired keeps its
  red; operations in flight to the target at that instant become pending-on-fault (above).
  **Quiescent** (only where the apparatus needs a quiet edge to read a clock, never because
  the product may require one, which it may not (the decider, row 82: "quiet room -- lol";
  no Vox operation waits for, reserves or requires a room, flow or member to fall quiet, and
  posts are never refused while a control change applies): the fixed part's first application
  of each fault, so that its R is measured from a clean edge; and the grower's snapshot, which
  copies closed stores. The room-end and leave faults run under load like every other (ADR-049's
  clocks hold with concurrent writes on the ender; a leave or end that waited for quiet would
  be a red of row 82): the driver issues no new operation toward the fault's targets for 10 s
  and the fault starts only when every open obligation toward them is delivered (a red that
  expired in that window stands); the prospective rule then applies to any obligation that
  remains. A fault that needs load and gets a drain, or the reverse, is `CANNOT MEASURE:
  S-1 ran quiescent; the writer was not saturated`. In S-1 the ten sessions keep stepping
  through the restart, their steps pending-on-fault and their acknowledgments ledgered with
  the delivery obligations they create (outcome 1). *(changed: r4, F3, N1; r5.)*

  **Overlapping scenarios** (the states the operator's machines were in; each is one fixed act):
  S-1, a restart of M while a trust change is pending on it and its writer is saturated (ten
  sessions stepping); S-2, a late join through I while I's disk is full; S-3, the update while
  V's path is at 300 ms (the wedge active); S-4, the storage-failure fault on M′'s or M's
  personal node (two fill-and-free cycles on its image) while its agent node on the same daemon
  carries the sessions and the other rooms stay busy; after the second free the personal node
  must receive in every room within 30 s while the agent node never stopped, then the personal
  node ends one room and leaves another (items 85/87's and 64/86's reproduced state, with the
  sibling healthy as on 2026-11-13; this replaces revision 2's guess of a healthy end plus a
  restart, which does not stage the pinned flow: a restart clears it); S-5, the 20 s blackhole
  of M while a late joiner is mid-join.

  **Length (ruling R-9).** The whole gate for a candidate fits 8–10 hours of wall clock: the
  journeys (about 3 h 20 min, FG-8) and a soak of 5 h with the fixed schedule complete (every
  fault once per target class, S-1 to S-5, each with its R measured; about 2 h 10 min of
  faults at the table's durations and separations, run twice with different seeds in the
  random part) and the drain. There is no standing 24 h run. **What a day would have caught
  that this does not, and how it is covered instead**: (i) slow growth of the store (item 80's
  4 GiB steps, SO-10's thresholds reached only after many hours): outcome 5 measures the
  growth *rate* per acknowledged message and step over the fixed intervals and the run record
  projects it to 24 h and 7 days against SO-15's figures (with Session steps kept 2 days, R-14) (`growth_per_hour_bytes`, ADR-047's
  ask); the thresholds themselves are reached in J4 on a nursery clone that already carries
  the slack; (ii) timers at their defaults (RS-8's 24 h deletion, ADR-049's 2-day hidden copy and departure
  record (ledger row 58), TR-17's 48 h of log, the 12 h keyring re-get of RS-1, SO-8's 2-day step retention):
  each default is the owner's in-tree proof with a clock step in a `test-knobs` build (ADR-018
  §10.11), never in the fleet; J10(e) plants TR-17's volume; and where the mechanism has a
  person's setting, the soak exercises the mechanism at a short setting on the assets: J13's
  retention act, one apparatus room with `vox room retention --steps 60s` (SO-8, a product
  setting, not a knob), asserts that steps older than the setting leave `vox room session` and
  `steps_bytes` falls while openings and ends remain, within 2 min of expiry; the 2-day default
  itself stays the owner's clock-step proof; (iii) a stall whose onset needs 43 min of ordinary traffic
  (item 85): its trigger is now staged directly (FG-12's storage-failure fault), so the time
  is not needed; (iv) a fault that recurs only every few hours (item 60): FG-16's capture, not
  the fleet. A soak twice as long found nothing in the plan that the schedule does not stage
  on purpose, and a 24 h standing run on another commit was never the candidate's evidence.
  - *Why*: item 57 ("24 h soak"); G-5 (the draft's 30 min soak had none of these faults);
    consolidated analysis §3.7; items 85/87 and 64/86 (S-4; `rca-RcaSchedStall`); finding 15
    (a random schedule promises nothing); N1 (a mandatory pause must not be a guaranteed red).
    *(changed: r3, N1, N11.)*

- **FG-13. The blocking outcomes are measured continuously from a ledger, every node, every
  second; nothing is blind.** *(changed: findings 2, 11; soak assessment; ledger row 11; r3:
  N1, N5, N9, TR-24/TR-25.)* The
  driver keeps the ledger (Terms) and `fleet/check.py` judges the run from it. Each outcome
  below blocks the release; each is a person's outcome, and each names the diagnostic the
  receipt keeps beside it (never asserted on its own).

  1. **Delivery.** Every acknowledged post is rendered, with its exact text, by every eligible
     member within D of its acknowledgment: D = 10 s when no fault is in flight toward that
     member at the acknowledgment; when one is, D = the fault's heal + its R; when a fault
     begins toward the member after the acknowledgment and before the deadline, the fault's
     deadline applies prospectively (the fault contract's onset rule), and a deadline that had
     already passed is a red the fault does not erase. (D is the soak's wedge detector; the
     shaped acts J1(f), J2(a), J3(c) assert RD-3's 5 s, a different claim.) **Eligibility is
     fixed at acknowledgment**: the ledger records, for each acknowledged post, the set of
     recipients (every node that holds the room instance at that moment, its join acknowledged)
     and each recipient's deadline; a deadline is changed afterwards only by the onset rule,
     and only forward. An obligation is
     **closed** without delivery only by an authorized event on that recipient before its
     deadline: its own acknowledged leave (NW-15), the room's end learned by it (NW-7), or its
     removal acknowledged (CJ-12); a deadline already missed is a red that no later leave, end
     or removal erases. Nothing else is exempt from eventual delivery: at the end of the run the
     driver heals everything, waits the longest R, and runs the **drain** over every
     acknowledged post whose obligation is still open: each MUST be rendered on each of its
     recipients, and every node's `vox status` MUST say `up to date with all <n> members'
     inventories` (TR-24) for every room it still holds; a deleted room is not demanded and no
     membership is recreated to obtain a green. One missing post, on one node, is `PRODUCT:`.
     Private Session steps are ledgered (offered, acknowledged) and their access and durability
     are SO-4's and RD-7's owner claims; the soak asserts their public effect (the step's
     Session view renders where consent allows) and nothing beyond it. Diagnostics kept:
     `entries_behind`, `last_entry`, `coverage`, `last_round_ms`, served and fetched counts.
  2. **Truth.** At every sample, every node's TR-2 verdict with TR-24's coverage agrees with the
     ledger: `up to date` only with at least one source and while outcome 1 holds for it;
     `catching up` only while something arrived within RECEIVE_PATIENCE; `NOT RECEIVING` only
     while a connected member advertises what it lacks and nothing arrived for RECEIVE_PATIENCE;
     `waiting for a member` only while no connected member holds what it lacks (a member that cannot be connected to is `offline, last seen <dur> ago` on its own line and is not unhealthy, R-14); `NOT HEARD FROM`
     only while members are connected and none has sent an inventory for INVENTORY_FRESH;
     `NOT ASKING` only while the node has wanted entries, a connected holder and no request
     started for ASK_PATIENCE, and then within ASK_PATIENCE + 10 s of that state (TR-2, TR-4,
     TR-5, TR-24, TR-25); `no inventory yet` only on a node that has had no source since it
     opened the room. A verdict contradicted by the ledger at any sample is `PRODUCT:`; so is
     "no completed sync in 10 minutes" on a node that received within the last 10 min.
  3. **Recovery clocks.** Each fault's recovery is timed from its own event, not from a window:
     a restart from the `--restart` command to the room open (RD-11) and to the first served
     round (≤ 10 s after Ready); a join from its command to its acknowledgment (SY-10) and to
     its first render on every member (≤ 10 s); a rejoined node's first post accepted ≤ 10 s
     (SY-11); a full disk's return to saving ≤ 10 s (SO-11); an ended room gone ≤ 70 s (NW-7);
     a leave at once (NW-15); a network heal to every peer back within its own path's budget
     (FG-15). A clock that overruns is `PRODUCT:`, whatever fault caused it; the fault is the
     staging.
  4. **Every node.** Outcomes 1–3 are measured per node, on all of M's two, I's four and V's
     three, so a node whose scheduler stops starting rounds while its sibling runs (items
     85/87) is red within D of the first post it misses, and outcome 2 is red when its
     `NOT ASKING` line is late or absent. Every room of the model has its own canary: each
     author posts in each room it holds at least once a minute, so a quiet room cannot hide
     behind a busy one; the checker's own self-check asserts that every node and every room of
     the manifest appear in every minute of the ledger, else `APPARATUS: node I-3 missing from
     the ledger from +1,200 s`. Diagnostics kept at each red: `lanes` (`slots.in_use`,
     `per_peer`, `retiring`), every port's `queued`, `round_running`, `start_age_ms`,
     `last_start_refusal`, the daemon log's last 200 lines.
  5. **Store.** Per node, over each fixed-workload interval the driver marks (1,000 acknowledged
     messages; 1,000 steps), data bytes grow within SO-4's numeric bounds for the chosen option
     (imported when chosen), and during an interval with no acknowledged content on a node its
     data bytes do not grow (SO-1); no `.failed-*`, no surviving `.rewrite` (SO-9); SO-10 is
     scored by its states: when in-use exceeds 1.5 × packed or file length 2 × in-use the status
     says `rewrite due` (or `not rewritten: …` with its reason), and after SO-10's trigger (a
     restart in the schedule, or `vox node compact`) the ratios hold and every acknowledged row
     reads; a daemon between the threshold and the trigger is not red. Growth is read from
     SO-15's fields (file length, disk use, in-use, data, packed).
  6. **Agents.** The real conversation's turn every 60 s completes with its context delivered
     and its post rendered everywhere (outcome 1), across every restart, update and trust
     fault, with no conversation restart; every announced session is listed by `vox room
     sessions` ≤ 60 s; no second daemon ever holds a socket (J7(e)'s method). Diagnostics:
     `omp-uncertain` markers, the extension's prints.
  7. **Daemon health as a person feels it.** `vox status` answers ≤ 1 s at every sample on
     every node (RD-1), including under the slow-peer fault, except on the target of an
     attained process pause during the pause (fault contract; the first answer within R from
     `CONT` is the claim); every acknowledged `vox room post` on an author exits within 5 s of
     its start (rows 80–81; RD-2's soak gate), with post latency p50/p99/max, status latency
     p50/p99, CPU, memory and flushes per second recorded per hour and blocking nothing, except
     a post or step that was
     pending-on-fault, which is judged by its recovery deadline (fault contract) and keeps any
     red that had expired before the fault; a post refused with the fault contract's words on
     the fault's target is a truthful refusal, any other failed post is its own red.
     Diagnostics kept, not asserted: CPU per daemon, `Recv-Q`, "busy N ms" lines.
  8. **Words.** No log line matching ADR-042 Appendix D's rewritten messages; every refusal in a log
     names its prerequisite (NW-1, NW-4).
  9. **Logs.** The daemon log at the end holds the run's first hour and every repeat's first
     and last time (TR-17's 48 h is J10(e)'s planted claim; the soak's own volume is what it
     is).

  A sample the driver could not take is never silently skipped: a `vox status` or `vox room
  read` that exceeds its bound is outcome 7's `PRODUCT:` red with FG-14's evidence, except a
  sample on a node under an attained process pause, which the fault contract records as
  `unavailable (paused)` (N1); a sample the driver itself failed to issue is `APPARATUS:` and
  the run is not green. The reader pages: `vox room read` prints its newest 200 rows and its
  "older messages not shown" footer on stderr, so every read in the ledger follows the footer
  until the row it seeks is found or the room's start is reached, and records the pages it
  read; a reader that did not page cannot say "never rendered" (the earlier rigs' counts on the
  busy case are unreliable for that reason, and are not receipts of the fleet). *(r4.)* A run that ends
  early is not a result; it is repeated, and any `PRODUCT:` red it recorded stands.
  - *Why*: G-9; consolidated analysis §3.7; items 49 and 54 make outcomes 2 and 9 measurable;
    item 25 gives outcome 5 its figures; items 85/87 need outcome 4.
  - *Proof*: J13 on the baseline (the grower's first run, E-5, with the checker run over it)
    is the mutant receipt: outcomes 1, 2, 3 and 5 at least MUST go red on v0.4.30 (W1 wedge,
    "last sync 0s ago" while starved, preparing 110–134 s, ProofRange growth). Acceptance
    FG-13-A: one candidate soak with every outcome in bound and the drain clean, its receipts
    named in the release notes.

### 5. Attribution

- **FG-14. Every red is attributed, by the driver, by a total rule; a product timeout is a
  product red.** *(changed: finding 3.)* ADR-018 §10.1's labels are applied mechanically:
  - Before a claim, the driver checks its staging and writes `CANNOT MEASURE:` if any
    precondition it owns is unmet: the forwarder's loss at 0 ms is not zero; the path is not
    shown (FG-4); the load is not attained; the slow member is not slow (FG-5); the snapshot
    is smaller than the manifest says; a container or the guest does not answer the driver's
    own probe (a non-`vox` command: `podman exec <c> true`, `ssh guest true`) within 5 s.
  - A product step a person would take that fails during staging (a poster's own `vox room
    post` exits non-zero; a session registration the product refused, quoted) is `PRODUCT
    (staging):` and is a product defect (ADR-018 §12.2). "sessions installed: 7/10" is
    `PRODUCT (staging):` when the product refused three, `APPARATUS:` when the shim did not
    start three.
  - **Any wait on the product that expires is `PRODUCT:`** unless the driver proves its own
    fault **on that operation's path in that interval**: the operation was issued through a
    transport whose own probe (a non-`vox` command on the same channel: `podman exec <c> true`,
    `ssh guest true`) failed or exceeded 5 s inside the operation's launch-to-deadline interval
    (so the command may never have been delivered or its result never returned); or the
    operation's product path crosses an emulator whose own log shows it late or erroring in that
    interval (a V forwarder fault is nothing to a command run on M). A failed probe elsewhere,
    an unrelated emulator's lateness or a host under load prove nothing about this operation. A
    `vox status`, `vox room read` or `vox room post` that was launched and exceeded its bound is
    recorded as `PRODUCT:` with the argv, the start and the deadline, the partial output, the
    process table and the daemon's last 200 log lines, even when no JSON came back; the two
    exceptions are a node under an attained process pause, whose samples the fault contract
    records as `unavailable (paused)`, and an operation that was pending-on-fault, whose wait
    is judged by its recovery deadline with any earlier expiry kept (FG-12). Where the
    product evidence and an apparatus fault on the same path cannot be told apart, the record is
    `PRODUCT?/APPARATUS?` with both bodies of evidence, it is not green, and the run is repeated
    for that claim without erasing the record. The driver never discards a run because of it.
  - The driver's own faults are `APPARATUS:` only with the evidence that proves them: a sampler
    thread's traceback, a pid it does not own, a file it could not write, a probe that failed on
    the operation's path. An `APPARATUS:` fault after a `PRODUCT:` red does not erase the red;
    it makes the claims not yet measured `CANNOT MEASURE`, and the run is repeated for them.
    *(changed: r3, N6.)*
  - A `PRODUCT:` red quotes the product: the `vox` command, its exit status and its output, or
    the `vox status --json` field and the sample time; and it names the position in the fault
    timeline (`+1,812 s, 90 s after the heal of netem 300 ms on V`).
  - No wall clock decides a wedge (ADR-018 §6): "not shown within 30 s" is a product claim only
    because it is a bound a person feels. The driver keeps sampling after the bound, so the
    receipt shows whether the product was late (and by how much) or never did it.
  - A red the driver cannot attribute is a defect of the journey; the claim is marked `CANNOT
    MEASURE` until the rule covers it, never deleted from the matrix, and the gate is not green
    while it stands (ADR-018 §10.1).
  - Every run leaves a receipts directory: `manifest.json` (assets and their SHA-256, which
    binary each computer ran, host roles, the driver's commit, the journey and checker hashes,
    the corpus manifest id, the workload and impairment manifest, the seed, and the OS build of
    the host and of each VM the run used: this Mac is macOS 27.3 (26C5035r) since 2026-11-13
    12:39 PST and every earlier figure in this ADR was measured on 27.2, ledger rows 70 and 72), `ledger.jsonl`,
    `faults.jsonl`, `samples.jsonl` (1 Hz, every node), every daemon's log, the status JSONs
    at each red, the `ps` table, and one `verdict.txt` per journey whose first line is `PASS`,
    `RED` or `CANNOT MEASURE`. Receipts live outside the repository and **outside `/tmp` and
    `/private/tmp`**, under `~/vox-fleet/receipts/<UTC time>-<candidate>/` (a directory that
    survives a reboot; the reboot of 2026-11-13 07:23 PST cleared both temporary trees and every
    rig receipt in them, ledger row 64). The driver writes the ledger and samples as it goes
    (append, flush per second), so a run cut by a host restart leaves its receipts; on its next
    start it finds the unfinished run's manifest and records `APPARATUS: host restarted at
    <time> during J13 (+5,120 s); run void` in that run's `verdict.txt`, never a pass and never a
    silent restart of the run; the `PRODUCT:` reds recorded before the cut stand.
  - *Why*: AGENTS.md "If I cannot tell the difference between a broken product and a broken
    test, it's not a valid test"; ADR-018 §10.1, §12.2; finding 3 (a hang laundered into a
    retry).
  - *Proof*: one deliberate fault per label, run once when stage 1 lands: the forwarder started
    with 1 % loss at 0 ms (`CANNOT MEASURE`), a sampler thread killed (`APPARATUS`, with its
    traceback), a poster given a room it is not in (`PRODUCT (staging)`), the baseline
    (`PRODUCT`), a daemon's serving process stopped with `SIGSTOP` outside any scheduled fault
    under a `vox status` sample (`PRODUCT: vox status … exceeded 1 s`, with the process table
    showing the stopped state), and the same stop with V's forwarder made late at the same
    moment (still `PRODUCT:`: the forwarder is not on M's status path). Each MUST print its
    label and its evidence. Apparatus self-checks.

### 6. Item 60

- **FG-15. The fleet holds the product to recovery and truth under both readings of item 60,
  with per-path budgets.** *(changed: findings 17, 18.)* The guest has a virtual network card,
  not Wi-Fi, and the host cannot shape the guest's path without `sudo`, so the fleet provokes
  each reading on its own:
  - **A-1, the link drops toward every peer at once (the 15:04Z shape).** Every path of M runs
    through the forwarder; the nemesis blackholes all of M's fronts (B's, I's and the anchor's
    together) for 16 s, then applies 30 % loss for 60 s, then clears. V keeps its netem.
    Claims: during the fault, M's `vox status` says each peer is `offline, last seen <dur>
    ago` (R-14, TR-3), never `up to date` with `last_received` advancing; within 30 s of the heal every
    peer is back on its own path within its own budget (B, I, A direct, rtt < 50 ms; V on its
    impaired path, rtt < 400 ms) and the first completed round follows ≤ 30 s later; no
    "unreachable" verdict is logged for a peer that answered within the fault's dial windows;
    the network-change path is driven by the link's return, not only by an address change (owner ADR-046 SY-21, ledger row 71, unchanged at revision 10, cited by id from the frozen copy `ADR-046.1aa0d5579.md`, hash `1801cdabf5d7…`, in its ninth review and pending: the connection predicate `net.manager().existing(peer)` is `Some` with `close_reason()` `None`; the event `NetEvent::Connected { peer }` (`actor.rs:3419`, handled at `:12273`), SY-21's `PeerConnected(peer)`, raised when a new authenticated connection is filed, with no `Have`-answer condition; it clears that peer's port backoff and runs a pass (SY-15 rule 6) whether or not the local address changed, where v0.4.30 clears backoff only at the interface- or address-change site (`network.rs:1753-1760`, the `NetworkChanged` handler); SY-21's own proof is this act, and its mutant clears backoff only on an address change; until that contract is incorporated here and qualified by a run, this clause is `CANNOT MEASURE`, which is not green).
    **A-2** is the 20 s blackhole in J13's table. The mutant receipt is A-1 run on the
    baseline; RcaLanPath's 12 s `SIGSTOP` probe is the process-pause fault's receipt, not this
    one.
  - **(B) the daemon does not drain its socket.** A container peer dials M every 2 s while M
    carries two nodes on the ≥ 2 GB snapshot, ten stepping sessions and J2's wedge (the state
    of 2026-11-12). Claims (the person's outcomes): the peer's dial is answered (ASK→PROVE) in
    < 1 s and no "did not answer within 5 s" appears at the peer outside an injected fault;
    outcome 1 holds for M's nodes. Diagnostics kept beside them, never asserted alone: the
    receive queue of M's socket (`netstat -anv -p udp`), per-thread CPU, "answered nothing for
    8s" lines. The control is the same without the sessions and the wedge.
  - **(A′) the macOS policy reset.** In the guest, with the daemon connected to two container
    peers, the driver's operator turns Vox's Local Network permission off and on in System
    Settings and launches an app that raises a Local Network prompt, and watches for silence to
    both peers within 30 s.

  What settles item 60: (B) red on the baseline with its control green confirms reading (B)
  for that shape and no other; (A′) reproduced twice names a trigger; neither reproduces Wi-Fi,
  MLO roaming or macOS 27.2's policy environment, which only the capture of FG-16 can see
  (FG-19). Under FG-10 no product change specific to item 60's cause lands until one of these,
  or the capture, has reproduced it; the claims under A-1, A-2 and (B) are KNOWN defects of
  status and recovery (items 49, 56 and ADR-044's work off the runtime) and land with those.
  Whether v0.4.31 may tag with item 60 still unexplained is Q4.
  - *Why*: item 60; rulings R-5, R-6.
  - *Proof*: A-2 is in J13; A-1 and (B) run in stage 3 as acts of J10 and J3; (B)'s baseline
    run with its control is E-2.

- **FG-16. A read-only capture is written and handed to the operator; he declined to run it,
  and nothing is armed.** *(changed: finding 17; r6, R-11.)* The decider declined a capture on
  his Mac (2026-11-13); this requirement stays as the design of the instrument, written and
  checked on the fleet's guest, so that it exists if he ever asks for it. Until then nothing is
  armed and a recurrence of item 60 settles nothing, which the release notes say (R-11). The
  capture of item 60 at its next recurrence MUST be a script the
  operator starts himself on his Mac (`watch-outage.py`, `nohup … &` in a terminal). It writes
  only under `/private/tmp/vox-rca/mac/lan-outage-captures/`, signals no process, runs no
  `vox` verb but `status`, and MUST keep collecting when `vox status` hangs: every command it
  runs is bounded at 5 s and its result or timeout is a row; the ring never waits on the
  previous sample. Bounds: ring 3 h, one burst at a time, bursts ≤ 5 MB each, the directory ≤
  200 MB in all (oldest burst deleted first). It is his to start because it runs `vox status`
  against his real daemon, which AGENTS.md forbids an agent to do.
  - **Ring**, always on, 1 Hz, one file per hour (`ring-<hour>.jsonl`): `vox status --json`
    for `omp-work` and `robert-work` (each peer's rtt, each running exchange's step and age,
    the lanes' running ages, each room's `last_received`); `netstat -s -p udp` (the "full
    socket buffers" and "dropped due to no socket" counters); `netstat -anv -p udp` for the
    daemon's socket (its receive and send queues); `ps -M` of the daemon summarised to
    per-thread CPU and the count of threads running; one `ping -c1 -W 200` each to .202 and
    .203.
  - **Trigger**, any of: a peer's rtt missing for two samples after being present; an exchange
    running longer than 5,000 ms; the daemon log gaining "answered nothing for" or "did not
    answer within 5 s"; the ring's ping losing two of five.
  - **Burst**, 120 s: `ping -i 0.2` to .202 and .203; `nettop -P -p <pid> -L 6 -J
    bytes_in,bytes_out,rx_dupe,rx_ooo`; the socket's `netstat -anv` line and `ps -M` each
    second; one `sample <pid> 3`; `log show --last 2m` for `com.apple.networkextension`,
    `airportd` and `nesessionmanager` at +5 s and +60 s; `vox status --json` for both nodes at
    1 Hz; the daemon log's last 200 lines at the end.
  - **Reading the burst** gives one of three results, and the third is a result: ping loss in
    the same seconds means reading (A), the link or the stack; clean ping with the socket's
    receive queue above 0 for three consecutive seconds while `nettop`'s `bytes_in` for the
    daemon keeps rising means reading (B), the daemon not draining what arrived; **everything
    else is AMBIGUOUS** and authorizes no cause-specific fix (FG-10): a thread near 100 % with
    an empty queue (RcaSlow S3's shape, which answered handshakes under 100 ms); and clean
    ping with an empty queue, no drops, idle threads and the QUIC path idle-closing, which is
    exactly what a UDP-only or per-flow policy drop looks like from inside the process (no
    datagram reaches the socket, so the queue is empty and the idle connection closes; FG-15's
    own blackhole produces it) and also what the daemon's own connection management would look
    like; only per-flow ingress and egress evidence (`nettop`'s per-flow bytes for the daemon's
    flows against the peer's log of what it sent) can tell them apart, and the burst records
    both so a reader can. A network-extension or `airportd` event at the onset is recorded as
    a correlation with reading (A), not as the trigger, until FG-15 (A′) or a second capture
    reproduces it. *(changed: r3, N12.)*
  - *Why*: item 82 (H-64): "watchers armed" was not true, so a recurrence today would settle
    nothing.
  - *Changes*: none in the product. Rollback: he stops the script.
  - *Proof*: none (it is an instrument, not a claim); it is run once on the fleet's guest
    against a 12 s `kill -STOP` of a scratch daemon and MUST fire its trigger, write one burst
    and read it as AMBIGUOUS or (B); that run is a check of the instrument, not a reproduction
    of item 60.

### 7. Build stages

- **FG-17. The fleet is built in four stages, in an order that can be executed; none is a
  release point.** *(changed: finding 6.)* A stage MAY be used for reproductions and reviews as
  soon as it exists (FG-11's table); FG-1 holds only with all four.

  | Stage | What exists at its end | What it reproduces on demand, on the release asset | Cost |
  |---|---|---|---|
  | **1. The smallest fleet** | `fleet/lib.py` (one library from the five rig copies: computers, nodes, pairing, posters, sessions, the ledger, samples, doctors, the verdict writer, pid ownership of the serving process, the environment blacklist, the keychain count); `fleet/impair.py` (E-1r2's forwarder: runtime delay switch, per-datagram log, plus loss, jitter, blackhole and the control socket); `fleet/check.py` for J1 and J2's claims; J1 (trial-sync B2 and B3 shapes on loopback, the delayed member by slow path) and J2 (RcaWedge's 75 ms relay), their baseline receipts and controls, wired into `release-gate.sh`'s `fleet` step; the release suite and ADR-044's five arms run from the script inside the guest and the Linux VM, their wall clock measured (FG-3's qualification, UNVERIFIED today). All on loopback inside the podman VM (R-10): one container per computer role, the forwarder in the VM; the guest only for the suite's Mac half. | Shown today on the asset, by E-1/E-1r2 and the asset rows of RcaWedge and RcaFrozen: item 2's slot half (pinned 292/295 occupied samples under a shown 1,501 ms path), item 3 (the late joiner's facts late: 52–151 s against 2 s), item 8's delayed-path join (33.8 s; the 37 s failure mode in B3), items 1, 11, 12 (relay 75 ms: 3/677, 89 stream failures, keys not readable). Not shown here: the busy responder (items 8 and 14's actor-queue cause, item 2's responder half), which waits for stage 2's E-7. To be recorded by J1's own run: 4, 5, 7, 49, 52 as its claims. A stage-1 review is final for a stage-1 claim only once the ledger, the checker, the attainment checks and the per-claim controls exist; E-1 alone is not that receipt. | 2 days, one person; each run 12 + 8 min |
  | **2. Linux, the room model, the grower** | B (two profiles), I, S, V, A and M′ containers (`fleet/containers/`: a Containerfile with iproute2, the aarch64 build, published ports, netem profiles, `--cpus` for S, the keyring seccomp profile, the 256 MB image for I, the four install images of ADR-051 LB-6 by digest, and the emulated x86_64 build container for ADR-051's in-tree Linux arms); the busy responder by real load (E-7); J3 on the 0.5 GB store, J4, J5 (with (g)), J6, J11; `fleet/grow.py` and the first 6 h grower run on the baseline, its corpus manifest validated | 6, 9, 15–25, 26, 27, 31, 32, 36, 38, 55, 64–68, 72, 76–80, 84, 85, 86 (the stall and the leave from the reproduced state); 8 and 14 once E-7 shows the busy responder | 3 days; the grower run unattended |
  | **3. The guest and the sessions** | M as the guest with two nodes and the candidate app in a scratch account; the real extension under `fleet/omp_host.mjs`; J7, J8, J9 (with E-43-1), J12, J10's fleet half; J3 on the ≥ 2 GB snapshot; FG-15's A-1, (B) and (A′) | 10, 28–30, 33–35, 37, 39–48, 50, 51, 53, 54, 56, 70, 71, 73–75, 81; Appendix A rows | 3 days |
  | **4. The soak** | `fleet/nemesis.py` (the fixed schedule, the fault table with its contracts and onset rule, S-1 to S-5, `faults.jsonl`, the seeded random part, replay); J13 with FG-13's checker, eligibility epochs and drain; `fleet/gate.py` assembling the report with FG-19's scoped promise and the growth projection | 57; 85/87 and 64/86 under load with the sibling healthy (S-4); every item under faults | 2 days to build; 5 h per candidate; whole gate 8–10 h (R-9) |

  Hardware (R-10, R-11: the VMs on this Mac, at most 20 vCPU and 48 GB, a stop within 30 s): nothing to buy. The host has 18
  cores, 128 GB and 847 GB free; the guest takes 8 vCPU and 16 GB and the podman VM 12 vCPU and
  32 GB, which other agents' rigs share. The journeys run serially from one queue; the gate
  runs in the hours the decider sets, 8–10 h in all (R-9), under FG-4's host rules (row 66):
  the host guard first, each start announced, a stop on any VM crash. Stages 1 and 2, E-7, E-9
  and the suites' halves fit FG-4's mode (a), one VM at a time; stage 3's two-VM journeys (J7,
  J9's app acts, J10's guest half, J3 on the ≥ 2 GB snapshot, FG-15 (B)) and stage 4 need mode
  (b), which waits for the operator's authorization of concurrent VMs after mode (a)'s runs
  have shown the host healthy. VM starts are on hold until the operator says go.

### 8. A journey is a proof like any other

- **FG-18. Every rule of ADR-018 binds a journey; a claim outlives the fix that happened to
  cure it.** *(changed: finding 5.)* A journey drives the shipped binary and asserts what a
  person sees (§9); every red names its side (§10.1, FG-14); every claim has its evidence of
  its kind (§10.10, FG-9); it runs once per candidate in one profile, the candidate assets
  (§10.9); there are no report-only, warning or informational checks, and nothing in the fleet
  prints a warning and passes (§10.6); a diagnostic the receipt keeps (CPU, `Recv-Q`, a marker
  directory) is evidence for reading a red, never a claim of its own. A claim whose item lands
  with no product change of its own, because another item's fix cured it, is **kept**: it is a
  user assertion that would catch a later regression of that path, and its item mapping, its
  baseline red and its mutant stay with it. What is removed is a redundant **proof**: when two
  journeys or an in-tree proof and a journey assert the same claim under the same or harder
  staging, the weaker one goes in the same change (§10.8), and the matrix says where the claim
  now lives. The fleet's files justify themselves as new files (§10.7): each extends a rig that
  reproduced its item (J1 trial-sync `rig.py` and E-1's `/tmp/adr045/rig.py`; J2 RcaWedge
  `rig.py`; J3 RcaSlow `rig.py` and RcaKeys `newcomer.py`; J4 RcaChurn `workload2.py`; J6
  IoDrill `rig.py`, RcaFrozen `rig5.py` and ADR-040's `rig64b.py`, `rig86.py`; J7 RcaTrust
  `trust.py` and RcaSessions `rca.py`; J9 ADR-043's `x1.py`, `x2.py`), and those rigs are
  outside the tree and retire when the journey lands. The in-tree proofs the lane ADRs add
  stay as the cheap, per-change versions of their claims, each with its own baseline red. A
  proof that is green on the baseline for the item it names is not that item's proof (FG-9).
  - *Why*: AGENTS.md "Tests"; ADR-018 §7–§10; finding 5 (deleting a cured claim lets the next
    regression ship).
  - *Proof*: each journey's review (FG-11).

### 9. Fidelity, the two new failures, and the inherited rows

- **FG-19. A number counts only under the condition that produced the failure, shown on the
  run.** *(new: G-8.)* No rig, journey or spike result MAY be reported as the product's
  behaviour for an item unless the run has shown, in its own receipt, every condition the
  item's root-cause row names as necessary (a slow member measured at T, a path measured at its
  delay and loss, a store of the manifest's shape, the load attained, the late joiners present,
  the trust change applied). A run without one of them is a run of a different claim and MUST
  say so in its first line (`loopback, no load: this does not bear on item 3`). The three wrong
  answers of 2026-11-12 (Context 5) are the receipts this rule is written from: each would have
  been labelled "does not bear" by it. **What a green promises**, and what the gate's green
  summary and the release notes MUST say in these words: the enumerated user outcomes held on
  the named candidate and surrogate binaries, the named corpus and workload, the attained
  delayed and lossy userspace and container paths, the fixed fault and target coverage and the
  drain, for the run's duration. What it does not promise, and every receipt that touches the
  item MUST say: a real LAN or Wi-Fi link, MLO roaming, macOS 27.2's network-policy environment
  and LaunchServices on real hardware (item 60, 46's guest non-reproduction); a public-IP Linux
  host on a different physical machine (the guest and the podman Linux VM both run on this
  Mac's CPU, cache and disk; the containers share the podman VM's Linux kernel, the guest has
  its own macOS kernel); native `x86_64` load behaviour (Q3); a four-node daemon on 9.7 GB of
  real operator-shaped stores until the grower has produced one of that size and shape; the
  operator's own timing of hand actions. For those, the capture (FG-16) or the operator's own
  machines after the release remain the only evidence; no monotonic relation from the fleet's
  easier topology to his outage is claimed. Each still-open incident (35, 46, 47, 60; item 87
  until Vince's evidence; item E-b until E-43-1) is named in the release notes as open, with
  the decider's disposition from Q4. *(changed: r3.)*
  - *Why*: G-8; the decider's "a reproduction that also appears without the trigger is not
    evidence" (R-6) read the other way: a success that appears only without the trigger is
    not evidence either.
  - *Proof*: the staging checks of FG-4, FG-5 and FG-14 are its mechanism; a reviewer reads
    the first line of every receipt.

- **FG-20. The fleet reproduces the two failures the operator met after the plans, from the
  state the RCA found.** *(new in r2; changed: r3, N11; ledger rows 11, 17; rulings R-7, R-13.)*
  This staging blocks as a fleet journey (J5(g), S-4) while the in-tree full-volume act is
  optional by his ruling (R-13, confirmed, row 59).
  - **Items 85/87 (a node stops starting rounds while its sibling runs).** Cause KNOWN for
    robert-work (`rca-RcaSchedStall`; root-cause row 85/87; owner ADR-046 SY-24, with ADR-042
    TR-25 for the words and ADR-040 NW-1's `StoreRecovery(room)` for the wait). The fleet
    stages the trigger on the asset: a node whose data sits on a small disk image, two
    fill-and-free cycles while its peers keep posting in every room it holds, traffic continuing
    (J5(g) in the journeys; FG-12's "storage failure, retained" fault and S-4 in the soak,
    where the personal node of a two-node daemon is the target and its agent sibling keeps
    running). The claims are the person's: after the second free, every post made in every
    room renders on the node within 30 s (outcome 1), `vox status` prints `NOT ASKING` with
    TR-25's refusal words while the state lasts and nothing of the kind once it
    is gone (outcome 2, TR-25), and the sibling never stops (outcome 4); then `vox room end`
    and `vox room leave` on that node have their rooms gone ≤ 60 s (NW-7, NW-15). The
    diagnostics beside a red: `lanes.bounded.retiring`, `slots.in_use`, `per_peer`, every
    port's `queued`, `round_running`, `start_age_ms`, `last_start_refusal`. The product mutant
    (FG-9) is SY-24's: keep counting failed flows in `can_retain_new`, or skip the retry on
    `StoreRecovered(room)`; the claim goes red on the post that never renders. The control is the same
    run without the fills (RcaSchedStall control (i): every post within 6 s). The checker's
    per-node loop has its own self-check (outcome 4), which is apparatus, not this claim's
    mutant. Item 87's attribution to the same cause stays INFERRED until Vince's `vox status
    --json` and log are read; the three slots held with nothing running on robert-work are a
    second leak whose owner is UNKNOWN (SY-24's named slot owners make it visible; no fleet
    claim reproduces it yet). Not every stall is this cap: the fleet watches SY-24's predicate itself, wanted entries with a
    connected holder, nothing in flight and no named wait, from the ledger and `vox status
    --json` at every sample, and its red stands for any cause, the empty-slot leak included (L1-3), and the receipt names which `last_start_refusal` it saw, in TR-25's words.
  - **Items 64/86 (an ended room kept; a leave fails).** Owner ADR-049 LE-2 and LE-4 (from ADR-040 NW-7, NW-15); the
    same pinned flow (RcaSchedStall controls (iii), (iv)). The fleet holds them in J5(g) (end
    and leave on the stalled node), J6(h) (ended with a member unreachable, gone ≤ 70 s, no
    `sync failing`, through a restart of the ender), J5(f) (leave while the room cannot save,
    `leave.rs:60`), FG-12's room-end fault and S-4, and FG-13's outcome 3 clocks. No knob is
    needed for the failed-retirement state any more (ADR-049's E-49a reproduced the refused leave
    on the asset from it, and its success after a restart); LE-4's `test-knobs` arm stays as the
    owner's cheap arm.
  - *Why*: the decider's "people should be able to leave a room that has already been ended";
    the operator's post "only on this machine" on 2026-11-13; N11 (the RCA's reproduction
    replaces revision 2's guess).
  - *Proof*: RcaSchedStall's run on the asset is the baseline receipt (11 retiring flows, every
    port queued, 24 posts never read, `end` looping, `leave` refused) with its controls; J5(g)
    records its own when it exists.

- **FG-21. The inherited QA rows live in this ADR.** *(new: finding 19.)* The draft QA matrix's
  rows that J12 and J7 absorb are reproduced in Appendix A with their exact pass conditions,
  the notarization and Gatekeeper exception stated (Q11), and the mixed-version row withdrawn
  (Q5; ruling R-8). The draft file is deleted only after Appendix A exists in the tree.
  - *Why*: finding 19 (a contract that lives only under `/private/tmp` cannot be rebuilt).
  - *Proof*: J12's and J7's claims cite Appendix A by row.

## Review record

Review: `adr-045-sol-review` (GPT-6.1-Sol, 2026-11-12), verdict "needs redesign", 21 findings and
a coverage audit of items 1–84. Each finding was checked against the `v0.4.30` tree, the cited
scripts, rigs and receipts; E-1 was run where a fact could be settled by a run. Classifications:
CONFIRMED, PARTLY (what holds), REJECTED (what refutes it).

| # | Finding | Classification and evidence | Answered by |
|---|---|---|---|
| 1 | Duty cycle is not a slow responder | CONFIRMED. Arithmetic: 300 ms stopped per second leaves 700 ms of loopback-speed exchanges; `SIGSTOP` stops the whole daemon. E-1 built the slow path on the release asset: the newcomer's single public slot ran toward the slow member in 292 of 295 samples (median lane age 741 ms, p90 1,334 ms, max 2,678 ms), fast members' hellos at 52.5 s and 150.8 s, join through the slow member 33.8 s; the 0 ms control: 2.1 s, 2.1 s, 3.9 s. The knob run (B2-base) had 90.3 s, 95.3 s, 211.6 s. | FG-5 (slow path, real load, shown on the run; process pause a separate fault), Terms, E-1 |
| 2 | Checks blind across faults; no drain | CONFIRMED. Revision 1 FG-13 scored quiet windows only; a 45 s preparing or a post lost during a fault passed. | FG-13 (ledger, delivery of every acknowledged post with per-member deadlines, recovery clocks from events, final heal and drain), G-9 |
| 3 | Product timeouts labelled APPARATUS | CONFIRMED. Revision 1 FG-14: "a sample timed out" was APPARATUS; J3(b) and outcome 7 assert exactly that time. | FG-14 (an expired wait on the product is PRODUCT unless the driver proves its own fault; evidence kept; a later apparatus fault erases nothing) |
| 4 | `VOX_TEST_KEYCHAIN` cannot be met by the asset | CONFIRMED. `keychain.rs:18-19`: read only under `test-knobs`; `host.rs:1564-1600`: the store runs only on a keep-with-passphrase request. The login keychain holds 2 `us.vox.node` items (read 2026-11-12, before and after E-1). | FG-6 (no keep on the host; keychain count as a self-check; keychain claims only in the guest's scratch account) |
| 5 | Deleting a cured claim | CONFIRMED. Revision 1 FG-18 removed the claim. | FG-18 (claims kept; redundant proofs removed) |
| 6 | Stage order not executable | CONFIRMED. Stage 2 needed J13 (stage 4) for the nursery. | FG-7 (`fleet/grow.py`, an instrument needing only stage 2), FG-17 (reordered), FG-11 (which journey a reviewer runs per stage) |
| 7 | Extension absent from the soak | CONFIRMED. Revision 1 J13 used bridge emulation and asserted an extension print. | FG-12 (one real conversation under the shim throughout), FG-13 outcome 6, J7(b),(d) |
| 8 | Old schema and wrong semantics | CONFIRMED. ADR-042 TR-1 renames `last_sync_ms`; TR-19 forbids "Locked"; TR-2/TR-4 define NOT RECEIVING with a connected source. | FG-8 (schema rule), J1(h), J2(c), J10(a),(f), FG-13 outcome 2 |
| 9 | Pause, removal, Linux, registrations, first upgrade | CONFIRMED (ADR-043 CJ-15, CJ-12; ADR-044 RD-13; ADR-041 RS-8, RS-4). | J9(d), J6(d), J11(b), J7(f), J7(c),(c′) |
| 10 | Bounds diverged from owners | PARTLY. ADR-044 r2 sets J3's bounds as status ≤ 1 s and post p99 < 300 ms (RD-1, RD-2 "under J3"), so J3(a),(b) stood; NW-7's 70 s, CJ-8's 2 s, CJ-4's 5 s, CJ-6's 1 s/5 s and SO-11's 10 s were missed. | Matrix rows J3, J5(c), J6(h), J9(c),(g); FG-8 (bounds frozen from owners with origin) |
| 11 | Storage ratios self-inflating | CONFIRMED (RcaStoreSize §§1–3; SO-4, SO-10, SO-15). | J4(b)–(d) (fixed workloads, matched control, SO-15 categories, SO-10's ratios, zero growth without content), FG-13 outcome 5, Terms (330 B bodies) |
| 12 | "nothing but store.redb" | CONFIRMED (`/private/tmp/vox-rca/beast/node-dir-listing.txt`). | J4(e) |
| 13 | Forged row; ended room without failed retirement | CONFIRMED (ADR-047 SO-13 §708–719; ADR-040 NW-7's knob proof). | J4 (no forged row; item 21 to SO-13/S-21), J6(h), "Held elsewhere", FG-20 |
| 14 | One mutant rule for three kinds of claim | CONFIRMED. | FG-9 (R, F, apparatus self-check), FG-1/FG-2/FG-5/FG-6 proofs relabelled |
| 15 | Random schedule, no coverage, no measurable recovery | CONFIRMED. | FG-12 (fixed schedule, coverage n/n, R per fault, S-1–S-5, seeded random after) |
| 16 | Log retention not measured | CONFIRMED (`daemon_log.rs:44-47` truncates only an oversized log; 2 MiB holds about 10 h at 201,217 B/h). | J10(e) (planted 48 h volume, oldest/newest lines, repeat times, retention mutant), J7(k) (planted oversized log) |
| 17 | CPU or ping is not a cause | CONFIRMED (RcaSlow S3). | FG-16 (AMBIGUOUS result; collection independent of a hung status; bounds), FG-15 (B) (person's outcomes, diagnostics beside them), FG-10 |
| 18 | Peer bounds contradict V's netem; wrong receipt | CONFIRMED. | FG-15 (A-1, A-2 named; per-path budgets; the STOP probe is the process-pause receipt) |
| 19 | QA rows only under `/private/tmp` | CONFIRMED. | FG-21, Appendix A, J12 |
| 20 | Receipt reuse keyed on assets only | CONFIRMED. | FG-1 (reuse key: binaries, driver commit, journey and checker hashes, corpus, workload, coverage, no outstanding red) |
| 21 | Host permission stated as compliance | CONFIRMED. FX-20 authorizes VM staging, not this hardware. | R-3, FG-4, FG-6, Terms, Q3 (no compliance claimed until decided) |
| audit | 84 item rows | Each applied; see the table below. | matrix, "Held elsewhere" |
| fidelity | load precision, byte claim, corpus, real network, path attainment, per-node observation | CONFIRMED on every point (ADR-044's 0.27 posts/s measurement; RcaStoreSize §2a median body about 330 B; size is not shape; one physical host; `tc qdisc show` is not a path; one reader per computer). | FG-4 (attainment, per-node), Terms (room model), FG-7 (manifest), FG-19 |
| soak/cost | diagnostics as claims; 1 s p99 at 1 Hz; 8 h 44 not 8 h 36; a 6 h candidate soak is not 24 h evidence | CONFIRMED. The sum of the rows is 2 h 44 in revision 1 and about 3 h 20 here. | FG-13 (every outcome a person's; every sample ≤ 1 s), FG-12, Consequences, Q2 |
| citations | ci.yml clippy count; LINUX_VOX positional; FX-19 lines; ONE_TIME_WAIT_MS meaning; RcaSlow instrumented; AGENTS.md:121-125 meaning; §10.2 amendment too broad; FG-11 vs §10.13 | CONFIRMED, each; corrected in "Citations checked", G-1, G-3, G-6, FG-2, J2(b), "Superseded and amended lines" (§10.2 narrowed to this ADR's journeys), FG-1/FG-11 (§10.13 reuse). | — |

Nothing was rejected: every finding held on the code, the scripts or the receipts. Narrowings:
finding 10 (ADR-044 r2 already carried J3's two bounds). Revision 2's reading of finding 1
("measured from the asking node's lane ages") was wrong and is corrected in revision 3 (N3).

### Second review (`adr-045-sol-review-2`, "needs revision", N1–N12)

Each finding was checked against the tree at `v0.4.30`, the retained E-1 receipts, the sibling
ADRs as they stand (r2/r3) and `rca-RcaSchedStall`; E-1r2 was run to re-measure N3.

| # | Finding | Classification and evidence | Answered by |
|---|---|---|---|
| N1 | A mandatory 12 s pause makes outcome 7 red on a correct product; "failed post is its own red" rejects SO-11's and CJ-12's deliberate refusals | CONFIRMED. Revision 2's outcome 7 had no fault contract. | FG-12 "Fault contract" (expected unavailability on the attained fault's target, truthful refusals scored as words); FG-13 outcome 7; nothing exempted for delivery, recovery clocks or words |
| N2 | The grower rejects the baseline corpus for the baseline's own item 18 | CONFIRMED. Revision 2 FG-7 applied RD-11's bound (2 s / 3 s on its fixture, ADR-044 r3) to a v0.4.30 open that takes 110–134 s; its own example rejected the representative corpus. | FG-7: validity = consistency (every room opens, trust and membership equal, one post per room renders, no `[failed:`), `baseline_open_s` recorded; RD-11 and SO-2 judge the candidate in J3(d); M′ for stage 2 |
| N3 | Running ages are not completed-exchange durations; the proposed median test rejects E-1 itself; `proxy.err` has no per-datagram log | CONFIRMED. Recomputed: median age 741 ms < T, as the reviewer says. | FG-5: shown = the product's `peers[].rtt_ms` toward the member ≥ T (E-1 final status 1,501 ms; E-1r2 1,500–1,502 ms at all 299 samples, control 1 ms) plus the forwarder's per-datagram log (E-1r2: 7,048 delayed datagrams, actual delay median 1,500.8 ms, lateness p99 2.1 ms, 0 errors) plus the derived completed-round figure (occupancy / completed: ≈ 2.0 s control: too few y1-directed samples for a matched figure, r4); ages are occupancy diagnostics only |
| N4 | A delayed path is not a busy actor; E-1 proves scheduler sensitivity to a delayed peer, not plan A's queue | CONFIRMED. The slow path leaves y1's actor fast; plan A's cause is inbound admission waiting in the actor queue. | Terms (delayed member vs busy responder); FG-5 (what E-1 is evidence of; items 8, 14 and item 2's responder half wait for E-7 or are CANNOT MEASURE and owner-held); J1 split into a stage-1 and a stage-2 act; FG-17 stage 1's claims narrowed |
| N5 | The drain demands renders on members that correctly left, and deleted rooms; a late filter can erase a missed deadline | CONFIRMED. | FG-13 outcome 1: eligibility and deadlines fixed at acknowledgment; obligations closed only by an authorized leave, learned end or acknowledged removal before the deadline; missed deadlines kept; drain over open obligations and still-held rooms only; private steps named as SO-4/RD-7's |
| N6 | The APPARATUS exception fires on any coincident probe or emulator fault, not one on the operation's path | CONFIRMED. | FG-14: the exception binds to the operation's transport and interval or an emulator on its product path; `PRODUCT?/APPARATUS?` dual record, non-green; combined self-check (stop under status with V's forwarder late stays PRODUCT) |
| N7 | J10(d) expects repair to succeed on a peer-caused gap; TR-14 exits 2 with "nothing to repair here" | CONFIRMED (ADR-042 TR-14). | J10(d): TR-14's two acts (no local fault → exit 2, nothing changed; staged local fault → named, rebuilt into fresh roots, ≤ 60 s, own feed, keys, read marks unchanged); delivery after release is outcome 1's |
| N8 | J2(e) TR-6 (any authenticated answer clears), J10(f) TR-20 (dial-back kept), J11(c) TR-18 (headless silent; display arm), J7(f) RS-8 (150 s, two checks), 24 h deletion not a fleet claim; TR-24/TR-25 not consumed | CONFIRMED on each (ADR-042 r2, ADR-041 r2). | J2(e), J10(a), J10(f), J11(c), J11(d), J7(f) rewritten; FG-8's schema list and contract manifest; FG-13 outcome 2's TR-24/TR-25 branches; "held elsewhere" gains 42's 24 h |
| N9 | SO-10 is in-use vs packed with a trigger, not a per-sample ratio on data; SO-6 bounds writes, not retained bytes; SO-4 has the numbers | CONFIRMED (ADR-047). | J4(a),(b),(d); FG-13 outcome 5: SO-15's packed field, SO-10's `rewrite due` state and post-trigger result, SO-4's numbers imported, SO-6 held by its own journey |
| N10 | J1(d) passes on a placeholder alone | CONFIRMED. | J1(d): the owed row while withheld, the exact body within 60 s of a second holder serving it and after restart; SY-4's selective holder |
| N11 | The stall is reproduced; S-4's healthy end plus restart does not stage it; FG-20's "mutant" is a checker mutation | CONFIRMED (`rca-RcaSchedStall`, receipts read; `bounded_sync.rs:580, 1789-1810, 1854-1860, 4749-4757` and `runtime.rs:1814-1848` checked). | Root-cause rows 85/87 and 64/86; FG-12's "storage failure, retained" fault and S-4; J5(g) with SY-24's product mutant and RcaSchedStall's control; FG-20 rewritten; item 87 kept INFERRED; the slot leak kept UNKNOWN |
| N12 | The empty-queue branch names connection management where a UDP-only drop looks the same | CONFIRMED. | FG-16: three results; the empty-queue case is AMBIGUOUS unless per-flow ingress and egress distinguish; an airportd event is a correlation |
| E-1 audit | 292/295 is of occupied samples (299 joined); hellos clock from the join; posters stopped at 30 vs 8 posts; `sessions: 0`; not a green control for J1(b); no settling experiment for the trust non-delivery | CONFIRMED on every point. | J1's row and the Experiments entry state the denominators and the differing pre-newcomer workload, call E-1 the B2 shape and not B3, and say the control is not green for (b); ADR-043 r3 owns the observation as item E-b with settling run E-43-1, cited in J9(i); J1's staging rule for it |
| host inventory | containers run in the podman Linux VM's kernel, not this Mac's | CONFIRMED. | FG-4 B row, FG-19, Consequences |
| cost | 3 h 20 min is a sum of estimates | CONFIRMED. | the matrix total says so |
| 27 rows + 64/85/86/87 | each recheck | applied in the matrix rows named in the coverage table's "Disposition" column, updated in place below where the recheck changed it | — |

### Third review (`adr-045-sol-review-3`, "needs revision, not redesign")

| # | Finding | Classification and evidence | Answered by |
|---|---|---|---|
| F1 | Busy-load attainment (median status ≥ 1.5 s) contradicts outcome 7 (every status ≤ 1 s) | CONFIRMED. Revision 3's FG-5 "busy responder, shown" asserted the symptom; a fixed candidate could not attain it. | FG-5: attainment is the load applied (sessions, RD-14's step rate with acknowledgment, posts, store size, `--cpus 1` with CPU ≥ 80 % busy, `rtt_ms` < 50 ms); the serving delay is recorded on the baseline only as a diagnostic; the candidate is judged by J1(e)/(f)'s and J3's bounds |
| F2 | J10(a)'s positive `NOT ASKING … retained_flows_full` needs the state SY-24 removes; J5(g) requires its absence | CONFIRMED. | J10(a): the positive rendering is asserted on the baseline run of J5(g)'s staging and by TR-25's own held-demand proof (ADR-042 r3: the stall act on SY-24's rig); on the candidate J10 asserts absence plus J5(g)'s delivered posts; J5(g)'s row says so |
| F3 | A post acknowledged just before a scheduled pause keeps its 10 s deadline and must expire | CONFIRMED. | FG-12 "Fault onset": a 10 s quiet-and-drain before every fault toward its targets, the fault starting only with no open obligation toward them; obligations still unexpired at onset get the fault's deadline prospectively (recorded beside the original); an expired one keeps its red; FG-13 outcome 1 restated |
| N1 rem. | Paused `room read` samples still hit the unconditional timeout rule; paused authors have no pending-operation contract | CONFIRMED. | Fault contract: every `vox status` and `vox room read` on a paused node is `unavailable (paused)` (FG-13's and FG-14's exception named); pending-on-fault operations must return within R of `CONT` with an acknowledgment or a truthful refusal; no new operation is issued to a paused node |
| E-1r2 | 27 ms is not a matched control duration (14 samples over all peers; 520 completions include 110 pre-join); ~2 s stands | CONFIRMED (recomputed: three y1-directed occupied samples in the control's joined window). | FG-5 and the E-1r2 entry: the 27 ms figure withdrawn; 289 s / 147 ≈ 2.0 s kept; the control's `rtt_ms` 1 ms stands as its path witness |
| sign-off | E-7 and the portable stall staging must precede design sign-off; E-8 and E-43-1 may stay fail-closed before their claims; freeze the two unpublished bounds; Vince's evidence bears on 87 only; ask only policy, resources/capture, residual incidents; rulings 18–20 recorded | CONFIRMED. | "Experiments" (E-7 and E-9 marked owed before sign-off; E-8 fail-closed before J5(f)/J6(a); E-43-1 before J1's stage-1 receipts); FG-8 (two bounds frozen "proposed", checker refuses to judge them); FG-20 (87 INFERRED, 85 proven); R-8, R-9, R-10 recorded; Q2 withdrawn; Q3 narrowed to resources and hours |
| apparatus | the earlier rigs' `vox room read` paging never worked (footer on stderr, newest 200 rows) | CONFIRMED from `/tmp/trial-sync/rig.py` `read_all` (it searched stdout for the footer). | FG-13: the gate's reader pages by the stderr footer and records the pages read; earlier "never rendered" counts on the busy case are not fleet receipts (E-1's "renders" firsts are of the newest 200 rows and are so marked) |

### Fourth review (`adr-045-sol-review-4`, "needs revision"; F2 and F3's accounting closed)

| # | Finding | Classification and evidence | Answered by |
|---|---|---|---|
| 1 | CPU ≥ 80 % is work consumed, not load offered; a leaner candidate would be CANNOT MEASURE | CONFIRMED (r4 FG-5 made it an attainment minimum). | FG-5: attainment = the offered workload, the corpus and the allocation, frozen; CPU and serving delay are diagnostics, baseline figures on v0.4.30, never a candidate minimum |
| 2 | The 10 s drain before every fault removes S-1's writer saturation | CONFIRMED (r4 "Fault onset" applied to every fault). | FG-12: two onsets, named per fault and recorded: under load (default; the random part; S-1–S-5, traffic running, prospective deadlines, in-flight operations pending-on-fault) and quiescent (the fixed part's first application of each fault, the room-end and leave faults, the grower); a wrong onset is CANNOT MEASURE |
| 3 | Pending-on-fault operations still meet outcome 7's 1 s and FG-14's rule covers only samples | CONFIRMED. | Fault contract: a pending-on-fault post or step is judged by heal + R in outcome 7 and FG-14, its earlier expiry kept, its eventual acknowledgment ledgered with the delivery obligations it creates |
| gaps | E-7 and E-9 owed before design sign-off | unchanged; `fleet-experiments.md` exists with all runs pending (its first E-43-1 runs were contaminated by a lock incident and are to be rerun). | "Experiments" |

### Revision 19 (after the design passed at r18; no review finding, the siblings' and the decider's settled items)

| item | source | closure | where |
|---|---|---|---|
| 1 | ADR-044 r17 (`770d7d35e`) | J3(a) and FG-13 outcome 7: every acknowledged post exits within 5 s (rows 80–81); p50/p99/max, status latency, CPU, RSS, flushes/s recorded, blocking nothing; three clocks named; RD-10's two lanes and the head-of-lane bound (82b/82c) where cited | J3, FG-13 (7), FG-12 fault table |
| 2 | ADR-051 r5 (`561e96ef8`) | Terms "Candidate assets" (dist directory); FG-2 opening and *Changes* (Mach-O refusal retired, V431-045-03 removed); FG-4 B row (LB-6's two invocations); FG-11; FG-17 stage 2 (four images, build container); J11 setup and (e)(f)(g) with mutants, item 91; J7 setup and (l), CANNOT MEASURE where no stand-in release | Terms, FG-2, FG-4, FG-11, FG-17, J7, J11 |
| 3 | ADR-043 r17 (`562246a27`) | J9(i) is CJ-17's act (item 92); the Experiments entry for E-43-1 as the spike that found the cause; J1's staging runs `vox anchor add`; J9(e)'s E38b clause; J6(d′) owed extension (corrupt open per SO-9, removal record, R5 lines, continuation after restore or deletion, own mutant) | J9, J1, J6, Experiments |
| 4 | E-9(a) attempt 6 VERDICT | MEASURED, PRODUCT red on Linux: flows pinned on a full tmpfs, leave refused "an internal error" (item 94); J5(a)–(g) and the storage-failure fault placed on I in the Linux VM; the tmpfs block-charging sub-question owed before J5(i)'s SO-2 arms run there | E-9 |
| 5 | FleetWriteup's E-7 wording | corpus "at least 520 MB staged by the fleet's generator, shape recorded"; step acknowledgment timing CANNOT MEASURE without a correlated receipt; the VM runner named, result owed | E-7 |
| 6 | ADR-047 r14 (`762fe04e1`) | SO-12's queued-refusal wording aligned with ADR-044 RD-7 (definite refusal at `begin_write`; a waiter on the mutex gets its own transaction's result; no promised order) | J5(i) |
| 7 | ADR-048 r11 (`fc8b996a2`) | act 12 carried as J6(j): a busy member keeps posting through a roster change (item 93), with the lane bound and ADR-048's mutant | J6 |
| 8 | rows 82–82c, 83, 84, 86 | the quiescent onset no longer covers room-end and leave faults (they run under load); no act assumes a quiet room; row 86's VM-experiment caps in Q3's bounds and E-9; rows 83/84 in the acceptance paragraph | FG-12, Q3, E-9, "Owed before acceptance" |
| 9 | PerfBaseline REPORT | v0.4.30 host baseline under RD-14 load recorded with J3's record as the figures the candidate is compared with; no target | J3 |
| 10 | ADR-040 r13, ADR-049 r14, ADR-050 r11, ADR-041 r9 | TJ-10-A's "zero of either text" in J7(b); ADR-041's RS-7/RS-5 placements and ADR-049's 2-day bound already carried (r13); ADR-040's lost-receipt re-run rule already in Links | J7 |
| 11 | E-9(b), E-7 (VM) | no VERDICT under the receipts directory at writing (E9b attempts 1–2 APPARATUS by the host guard); both owed, folded in as their VERDICT lines say | E-7, E-9 |

### Coverage audit, item by item

The reviewer's letter (R = baseline red demonstrated in a report, U = unverified on the fleet,
P = partial or wrong fixture, H = housekeeping) and what revision 2 does. "Owner" = the owning
ADR's in-tree proof holds the mechanism; the fleet corroborates the person's outcome.

| Item | Letter | Disposition |
|---|---|---|
| 1 | R | J1(f), J2(a): continuous ≤ 5 s per post from the ledger, not end-of-act lag. |
| 2 | U/P | J1: the delayed-member half with FG-5's shown slow path (E-1/E-1r2: `rtt_ms` 1,501, slot pinned 292 of 295 occupied samples); the busy-responder half only after E-7 shows real load, else CANNOT MEASURE on the fleet and owner-held (SY-2, RD-16). |
| 3 | R | J1(c): `control_current` per member, not revision equality; six earlier joiners in the room model with their join times in the ledger. |
| 4 | P | J1(d): SY-4's selective holder withholds one body below the window, head past the window; the owed row while withheld, the exact body within 60 s of a second holder serving it and after restart; the owed row alone never passes. |
| 5 | R | J1(c) keeps the parent-header demand's outcome (control current ≤ 30 s) and the text on J10(b)'s blacklist; both must hold. |
| 6 | R | J3(e): `newest` and `resume`, wire progress within one exchange and the requested range complete (SY-9). |
| 7 | R | J1(g): from the first exchange to the head, ≥ 100/min, final render equal to the ledger. |
| 8 | P | J1(e): the join goes through the slow member; command to usable room; SY-10's T + 10 s; the asset's 37 s failure mode is the red. E-1: 33.8 s, E-1r2: 26.5 s on the delayed path; the busy-responder join counts only with S shown busy (E-7). |
| 9 | R | J6(b): every author's posts on every member ≤ 10 s from the join's acknowledgment, under traffic. |
| 10 | R | J8(d): accepted ≤ 10 s and rendered on a member ≤ 10 s. |
| 11 | R/U | J2(d): zero untyped closes on the 37.5 ms act plus typed answers (SY-21); the IO instance stays UNKNOWN (FG-10). |
| 12 | R | J1(i), J2(b): bodies read both ways ≤ 30 s, a person's budget, not `ONE_TIME_WAIT_MS`. |
| 13 | R/P | J2(c), J3: TR-2 verdict against the ledger; `last_round_ms` recorded only. |
| 14 | U | J1(f), J3(c): served progress as the reader's ≤ 5 s render; served wait kept as a diagnostic; the actor-queue cause (plan A, max 12–16 s) is staged only by the busy responder (E-7), never credited to the slow path. |
| 15 | R | J3(b) ≤ 1 s every sample (RD-1 under J3), load attained and recorded. |
| 16 | P | RD-7's in-tree hold proof holds durability; J3 does not claim it; FG-13 exempts no accepted post. |
| 17 | P | J3(c): every reader, every post, ≤ 5 s, including after the cold restart. |
| 18 | R | J3(d): RD-11's bound with 8,000 own and 2,000 foreign rows seeded, origin at `--restart`. |
| 19 | R/P | J11(a),(b): readback, once per start, doctor remedy. |
| 20 | P | J4(c): zero data growth and ≤ 1 MB in-use over 30 min of wedge with no content (SO-1). |
| 21 | U/P | Owner: SO-13 review plus ADR-047's spike E-7; J4(e) keeps the recovery outcome. |
| 22 | P | J4(b): fixed workloads, matched control, per-category bytes (SO-4/SO-6). |
| 23 | R | J5(a): no rewrite at all below the floor; full for a real 5 min; SO-11's 10 s. |
| 24 | R | J5(b): I is the inviter; the reason is storage; retry succeeds. |
| 25 | R/U | J4(a), J5(e): SO-15's fields; no content cap imposed. |
| 26 | P | J6(a): a pass that fails in a room that cannot save (full disk); unrelated rooms read and post; red route unverified on the asset until E-8. NW-5's own asset red (the left room's reservation, plan D `rig26`) and its held-fold and confidentiality arms stay NW-5's. |
| 27 | P | J6(a): no `[failed:` row at later starts and policy moves; the retained failed-left state across restart is NW-6's in-tree proof. |
| 28 | R/P | J7(a): a sibling's real turn ≤ 10 s during the window. |
| 29 | R | J7(a): every conversation registers and takes its next turn. |
| 30 | P | J7(b): a real turn through the refusal window, no conversation restart; NW-10 in RS-7's file. |
| 31 | U/P | J6(e) corroborates; NW-11's in-tree proof holds the selection/refusal/release path. |
| 32 | R | J6(c): read marks, a key delivery and a settlement staged before the move. |
| 33 | P | J9(a): `pair` against the unreachable inviter (CJ-7), not an invite. |
| 34 | U | J9(b): CJ-1's lines through five states. |
| 35 | U | J9(c): CJ-8's 2 s and CJ-4's 5 s; original cause UNKNOWN, kept so. |
| 36 | R/P | J6(d): CJ-12's authority; residual-room command for other rooms. |
| 37 | P | J9(d): CJ-15's words; posting not stopped (PA-2). |
| 38 | R | J9(e): NW-12's 20 of 20 sibling posts during a node create; revision counting dropped (CJ-14 withdrawn). |
| 39 | R/P | J7(c) candidate-to-candidate; J7(c′) the first upgrade's RS-4 warning. |
| 40 | R | J7(d) with the real extension: the turn in flight completes after reconnect; FG-13 outcome 6. |
| 41 | R/P | J7(e): the daemon's own lines, `ps` at 10 Hz, the socket's owner. |
| 42 | R | J7(f): kill the OMP process; ended and listed as ended within 150 s (RS-8's two checks 60 s apart), one `OMP ended`, a live OMP never ended; the 24 h on-disk removal is RS-8's clock-knob proof, held elsewhere. |
| 43 | R | J7(g): claims after the update and coordination after every worker updates; prior-peer interop is Q2. |
| 44 | R | J7(h): resume the conversation; listed before its first claim. |
| 45 | R | J8(a),(b): old process stops or refuses by name; no old post in the new profile; new posts survive restart. |
| 46 | U | J8(c): the updater's words; cause UNKNOWN stays. |
| 47 | U | J7(i): a known sender by pid, named; original sender unknown. |
| 48 | R/U | J8(e): refused by name with both identities; a new conversation works. |
| 49 | R/P | J1(h), J10(a), FG-13 outcome 2: ledger agreement; NOT RECEIVING staged with a connected withholding source. |
| 50 | P | J10(b): each branch induced and its replacement asserted; a branch not induced is CANNOT MEASURE. |
| 51 | P | J10(c): preparing listed; in-memory origin for "no completed sync"; TR-9's keyring row never adjacent to health, asserted with the owner proof's line-index check. |
| 52 | R | J1(b): TR-10's words with the negative-control node. |
| 53 | U/P | Closed "not in 0.4.31, by ruling" (row 22): no repair facility; J10(d) asserts its absence and TR-13's operator-only advice. |
| 54 | P | J10(e): planted 48 h volume, oldest/newest lines, retention mutant. |
| 55 | R | J11(c): TR-18's two acts: headless (no `DISPLAY`) → silent skip, notice within 10 s; `DISPLAY=:0` with a failing stand-in → exactly one `not available` line per run. |
| 56 | R | J10(f): a refusing daemon staged; `not attached`; no coordinator. |
| 57 | U | FG-1–FG-21; J13's green is "operator conditions proven" only within FG-19's stated limits. |
| 58 | P | FG-6: no keep on the host; count check; guest scratch account. |
| 59 | H | Procedure with the operator's go after J5(d); the fleet certifies no live file. |
| 60 | U | FG-15, FG-16; Q4 for the ship decision with it unexplained. |
| 61 | H | Disposition is Main's to state; no proof. |
| 62 | H | Outside this gate; its receipts are the reruns' completion. |
| 63 | H/P | J6(d) proves the product; the live IO clean-up is a procedure; the fleet observes nothing of IO. |
| 64 | P | J6(h): E-64b's shape; NW-7's 70 s; restart mid wind-down; the failed-retirement state on the asset is J5(g) (RcaSchedStall's recipe), no knob needed. |
| 65 | P | J6(e) corroborates turns continuing; NW-3's in-tree proof holds the refusal. |
| 66 | P | J6(g): the typed refusal NW-2 names, staged by NW-2's apparatus and recorded in the ledger; no recovery, unrelated work continues; no typed refusal recorded = CANNOT MEASURE. |
| 67 | P | J6(f): the failed pass (full disk) and its retry edge; posts ≤ 30 s from it. |
| 68 | P | RD-6's in-tree proof; J3(g) corroborates delivered attention under load. |
| 69 | P | TR-6 as revised (any authenticated answer clears the streak); J2(e) asserts that; delivery is TR-4's and outcome 1's. |
| 70 | U/P | J10(g): a repeat across a restart with first and last time and count. |
| 71 | P | J7(k): a planted log oversized for the candidate (above TR-17's 3 MiB) with a torn last line and a known oldest line; the oldest line survives in the ring; nothing truncated. |
| 72 | P | J11(d): the `DISPLAY=:0` act with a slow stand-in (headless skips it, TR-18); scored in J13's slow-notifier row. |
| 73 | R | J10(f). |
| 74 | U | J9(f): CJ-9 through preview, approval and status. |
| 75 | R | J9(g): CJ-6's four bounds. |
| 76 | P | SO-5's layout mutant proof; J4(d) corroborates on the nursery corpus. |
| 77 | P | SO-6's own named-session write-cost journey (OS bytes); J4(b) corroborates the published view equals the fold. |
| 78 | P | SO-4's proof; J4(b) imports SO-4's numeric per-step bound for the chosen option ("proposed" until chosen). |
| 79 | P | J4(d): `vox node compact` on a slack clone; content survives. |
| 80 | P | J4(d): SO-10's states (`rewrite due`, then the post-trigger ratios on in-use vs packed and file vs in-use), not a per-sample ratio on data. |
| 81 | R | J7(j): kill -9 in the guest; the manager restarts it; a real turn completes. |
| 82 | H/U | FG-16: an instrument, checked against a scratch daemon; not a reproduction of item 60. |
| 83 | U/P | FG-5: the slow path, shown by `rtt_ms` and the per-datagram log (E-1r2); evidence of the delayed member only, said so. |
| 84 | P | J3(c): every reader ≤ 5 s throughout and after the cold restart. |
| 85, 87 | — | FG-20 (cause KNOWN, reproduced; item 87 INFERRED), J5(g), FG-12's storage-failure fault and S-4, FG-13 outcomes 2 and 4 (`NOT ASKING`, per node), J10(a). |
| 86 | — | J5(f), J5(g), FG-12's room-end and storage-failure faults, FG-20. |

## Unchanged rulings

- ADR-018 §9: only real use of the shipped binary is a test; a test-side attacker or apparatus
  server is apparatus (J10's withholding server).
- ADR-018 §10.1 (the four labels), §10.3 (live-model proofs never on a gate), §10.10 (one mutant
  per claim; a `CANNOT MEASURE` is not a mutant), §10.11 (knobs only under `test-knobs`; the
  release artifact holds none), §10.13 (a proof that passed on the same binary and inputs is
  not run again unless asked; FG-1's reuse key), §6 (a clock does not decide a wedge), §12
  (pid ownership, `PRODUCT (staging)`, no green from a retried red, no restarting a shared
  service to test a theory).
- ADR-034 FR-6: the 100,000-entry Session proof stays an optional proof ("on demand, not a
  gate", the decider); it is not a fleet journey. ADR-034 PF-2: an in-tree full-disk proof
  stages the disk in userspace; J5 does the same.
- ADR-038 FX-20: staging runs on the VM setup, not on the operator's working profiles.
- The 2026-10-02 ruling: CI runs no proof.
- AGENTS.md: no `sudo`; never run `vox` against a real profile; never change the Vox version on
  the operator's machines without his go for that action; v0.4.x has no prior-release
  compatibility requirement.
- ADR-033 PA-2: pause is of Sessions, not of posting (J9(d)).

## Superseded and amended lines

Main applies these at sign-off. Quotes are exact, from the tree at `d9a8667ba`.

| ADR and rule | Current text (file:line) | Replacement text |
|---|---|---|
| ADR-018 §10.2 | "Expensive user-facing proofs MUST sit behind the cargo feature `optional-proofs` (heavy ones behind `heavy-proofs`, which implies it). An optional proof MUST block nothing: not CI and not the release gate." (`ADR-018-quality-bar-and-product-proof.md:149-151`) | "The fleet journeys J1–J13 of ADR-045 block the release through the `fleet` step of `scripts/release-gate.sh` and never run in CI; no other proof joins them without an ADR naming it. Every other expensive user-facing proof MUST sit behind the cargo feature `optional-proofs` (heavy ones behind `heavy-proofs`, which implies it). An optional proof MUST block nothing: not CI and not the release gate." |
| ADR-018 §10.9 | "A proof SHOULD be run once, in the profile CI uses." (`ADR-018…:182`) | "A proof SHOULD be run once, in the profile the release gate uses (the release suite; for a fleet journey, the candidate assets)." |
| ADR-018 §10.9 | "A verifier MUST NOT re-run the fixer's greens." (`ADR-018…:185`) | "A verifier MUST NOT re-run the fixer's greens of in-tree proofs. A reviewer of a fix MUST run the fleet journeys its item maps to himself, on the fix's assets, and read their receipts, reusing a receipt that matches ADR-045 FG-1's key; the author's fleet receipts are not the review's evidence (the decider, recorded 2026-11-12; ADR-045 FG-11)." |
| ADR-018 §10.12 | "A release gate MUST NOT require an idle machine, and a red MUST NOT be explained away by the machine's load." (`ADR-018…:197-198`) | Unchanged, followed by: "A release gate MUST measure the bounds a person feels under the load the operator runs, and only after the run has shown that load and every other condition the claim names (ADR-045 FG-4, FG-19). A bound missed while an injected fault is in flight toward the member is measured against that fault's recovery interval; a miss outside one is a product red." |
| ADR-018 §11.1 | "The gates MUST run once, in CI, on the commit that is published, on both ubuntu and macOS." (`ADR-018…:213`) | "CI MUST compile, format-check and lint the commit that is published, on both ubuntu and macOS, and MUST run no proof (the decider, 2026-10-02). The blocking proofs and the fleet journeys MUST run once, in `scripts/release-gate.sh`, on that commit and its candidate assets (ADR-045 FG-1, FG-3)." |
| ADR-038 FX-19 | "Releases MUST be small and incremental until Vox is back to "somewhat usable": each cut is one clean batch of fixes from this ADR, published and closed with its release milestone (v0.4.7, v0.4.8, …)." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:245-247`) | "From v0.4.31 a release MUST NOT be minimal or partial ("minimal continues the shit cascade", the decider, recorded 2026-11-12): it ships every item of its fix list, proven by the fleet gate (ADR-045 FG-1), or it does not ship. It is published and closed with its release milestone." |
| ADR-038 Status | "Each product requirement MUST land with its proof (ADR-018) in a small release (FX-19)." (`ADR-038…:7-8`) | "Each product requirement MUST land with its proof (ADR-018) in a release that meets FX-19." |
| AGENTS.md "Tests" | "Expensive user-facing claims are optional proofs;" (`AGENTS.md:36-37`) | "Expensive user-facing claims are optional proofs, except the fleet journeys of ADR-045, which block the release through `scripts/release-gate.sh`;" |
| AGENTS.md "Tests" | "Run a proof once, in the profile CI uses." (`AGENTS.md:45`) | "Run a proof once, in the profile the release gate uses." |
| AGENTS.md "Tests" | "Verifiers don't re-run the fixer's greens: one mutant per claim, run once, plus probes where there is smoke." (`AGENTS.md:49-50`) | "Verifiers don't re-run the fixer's in-tree greens: one mutant per claim, run once, plus probes where there is smoke. Reviewers run the fleet journeys themselves, reusing a matching receipt (ADR-045 FG-11)." |
| AGENTS.md "Tests" | "CI runs the suite on push; a CI red is the smoke. Do not duplicate CI locally." (`AGENTS.md:51-52`) | "CI compiles, formats and lints on push and runs no proof (the decider, 2026-10-02); a CI red is the smoke. The proofs and the fleet run in `scripts/release-gate.sh`, inside the VMs (ADR-045 FG-1, FG-3)." |

## Rejected alternatives

- **Deterministic simulation** (FoundationDB's Simulation, TigerBeetle's VOPR, Antithesis). The
  whole cluster runs in one process, or under a deterministic hypervisor, with the clock,
  network and disk stubbed, and any failure replays from its seed. vox-core's runtime (tokio,
  quinn, redb) has no seam for a simulated clock, socket or file, and Antithesis is a hosted paid
  service whose determinism needs its hypervisor: months of I/O rewrite or a vendor contract.
  It is the right long-term instrument and is rejected for v0.4.31. Taken from it: the fault
  ladder (`none → resilient → high_availability`), the quiet period before the final check,
  swizzle-clogging, and "every red reproducible from a recorded timeline" (as help, FG-12).
  Sources: https://apple.github.io/foundationdb/testing.html ·
  https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md ·
  https://antithesis.com/docs/product/writing_tests/controlling_faults.md
- **A userspace impairment proxy alone** (Shopify's toxiproxy). It is TCP and Vox is QUIC over
  UDP, and a proxy cannot impair the direct path. It is kept as the carrier (the forwarder's
  toxics) inside the chosen design, a live fleet with a nemesis (Jepsen), where the driver's
  ledger is the checker and `vox room read` and `vox status` are what it compares against
  (Jepsen's history checker, not the product's own counters). Sources:
  https://github.com/Shopify/toxiproxy/blob/main/README.md ·
  https://jepsen-io.github.io/jepsen/jepsen.nemesis.combined.html
- **The journeys as `cargo test` files in the tree.** They would be `CANNOT MEASURE` on every
  machine but the one with the guest, the containers and the nursery.
- **The fleet in CI.** The 2026-10-02 ruling; and hosted runners have no guest, no containers
  with `NET_ADMIN` and no nursery.
- **The load journey as an optional proof** (plan B's question 4, for ADR-044). It would leave
  the gap of G-4 exactly as it is: no place where a proof of the operator's conditions must run
  before a tag.
- **The draft QA matrix as it stands.** Twelve rows and a 30 min soak miss more than half the
  fix list (G-5); its rows are Appendix A.
- **The instrumented slow member** (`VOX_RCA_SERVE_DELAY_MS`). A knob in a non-shipped binary
  cannot run on the assets (item 83).
- **The duty-cycled slow member** (`SIGSTOP` 300 ms per second). Not a slow responder (finding
  1); kept only as the process-pause fault.
- **A forged at-rest row as the poison of item 21.** No recipe reaches the native save-failure
  path; the owner's spike holds it (finding 13).
- **The quiet-window oracle.** Blind between windows and during faults (G-9); replaced by the
  ledger (FG-13).
- **The product's own counters as the checker.** `last sync`, `holds_through` and "up to date"
  are what item 49 found wrong; the ledger compares rendered text with acknowledged operations.
- **The operator's machines or stores.** Ruling R-3; his stores are sealed to his vault and
  identity, and AGENTS.md forbids running `vox` against them.
- **Wi-Fi in the fleet.** The guest has a virtual card and shaping the host needs `sudo`; FG-15
  provokes each reading on its own, and only the capture of FG-16 can see a real Wi-Fi drop.
- **A 24 h soak, or a standing one on `main`.** Ruled out (R-9): the gate fits 8–10 h, and a
  standing run on another commit was never the candidate's evidence; what a day would have
  caught is covered by rates, projections and clock-stepped owner proofs (FG-12).

## Implementation order and related work

1. `fleet/lib.py` (stage 1), with the ledger and the keychain count. Deletes nothing in the
   tree; retires the `/tmp/rca-*`, `/tmp/trial-sync` and `/tmp/adr045` rig copies.
2. `fleet/impair.py` from E-1's forwarder (runtime delay switch) with `udpdelay_test.py` as
   its staging check; loss, jitter, blackhole, the control socket.
3. `fleet/check.py` for J1 and J2; J1 and J2 with their baseline receipts and controls; the
   `fleet` step in `release-gate.sh` and `fleet/gate.py`.
4. The containers, S with `--cpus 1`; `fleet/grow.py` and the first grower run with its
   manifest; J3, J4, J5, J6, J11.
5. The guest as M in a scratch account; `fleet/omp_host.mjs`; J7, J8, J9, J12, J10's fleet
   half; FG-15's A-1, (B) and (A′).
6. `fleet/nemesis.py` (fixed schedule, S-1–S-5, seeded random, the onset rule), J13 with the
   drain and the growth projection.
7. Appendix A into the tree; then the draft QA matrix file goes. The amendments to ADR-018,
   ADR-038 and AGENTS.md are applied by Main at sign-off of this ADR (their replacement text
   already says the fleet step "is to" exist until stage 1 lands); `docs/release/fleet.md` is
   written when stage 1 lands.
8. FG-16's script, handed to the operator with its start command, after its check against a
   scratch daemon.

Other lanes in v0.4.31 (the contract manifest of FG-8 names their revisions). Each owns the
product change and the in-tree proof; this ADR owns where its claim is held at the gate.
ADR-040 (named waits and failure containment): J6, J7(a)–(b), J9(e), the refusal rule in
J13's outcome 8, NW-7 and NW-15 in J5(f), J5(g), J6(h) and FG-20; NW-1's `StoreRecovery(room)`
(from ADR-046's ask) is the wait J5(g)'s stalled node must name. ADR-041 (restart by the
service manager): J7 and J8; RS-1 under the keyring seccomp profile and its refused case under
the default; RS-8's 150 s in J7(f) and its 24 h held by RS-8's own proof; RS-5's `kill -TERM`
case in J7(j). ADR-042 (status reports outcome): J10, the schema and words of FG-8 and
FG-13's outcome 2 (TR-2, TR-4, TR-5, TR-24, TR-25), TR-6 as revised in J2(e), no repair (row 22)
in J10(d), TR-17 in J10(e) and J7(k), TR-18's two acts in J11(c)–(d), TR-20 in J10(f). ADR-043
(adding, replacing and removing a computer): J9, J6(d), per ledger row 2; item E-b and
E-43-1 in J9(i). ADR-044 (the daemon stays responsive under agent load): J3 as RD-14 per
ledger row 7, RD-11 in J3(d) and the grower's `baseline_open_s`, J11(a)–(b) with RD-12's
kernel arm in the podman VM, FG-15 (B); its question whether the load journey blocks is
answered by Q1. ADR-046 (sync makes progress): J1, J2, J8(d), J3(d)–(e), SY-5's 1,000/min
in J1(g), SY-4's selective holder in J1(d), SY-10 in J1(e), the slow-member bounds this ADR
proposes (J1(a)), SY-24 in J5(g), FG-12's storage-failure fault and FG-20 (ledger rows 11, 14,
17). ADR-047 (storage): J4 on SO-4's numbers, SO-10's states and SO-15's fields, J5 on the
256 MB image and SO-11's floor, FG-13's outcome 5, SO-13's spike E-7 for item 21. ADR-039
(replies): item 61, no journey.

### Experiments

**Run in this revision.**

- **E-1. The slow member by slow path, on the release asset** (receipt lost in the reboot of
  2026-11-13; figures recorded here and in `adr-045-revision`; to be re-run as J1's fleet
  baseline; the scripts `/tmp/adr045/rig.py`,
  trial-sync's rig with `--slow-path MS`; `/tmp/adr045/udpdelay.py`, RcaWedge's forwarder with
  `--delay-file`; binary `/tmp/adr045/vox-0.4.30`, sha256 `f3bf4ec2…` = the published
  `vox-aarch64-apple-darwin` 0.4.30; receipts `/tmp/adr045/runs/B2-path1500/` and
  `B2-path0/` (`rig.log`, `samples.jsonl`, `summary.json`, `proxy.err`, final status JSONs; the daemon logs and data
  directories deleted after the measurements; the login keychain held 2 `us.vox.node` items
  before and after). Shape: trial-sync B2 (300 seeds, y1 and z1 at 1/s, one earlier late
  joiner, posters stopped 30 s before the newcomer, 300 s watch). After seeding, y1 is
  restarted listening on `[::1]` with the anchor reached only through the forwarder's v6 front
  (its v4 upstream is the anchor), so every peer reaches y1 relayed through that one hop; the
  hop delays y1's outbound datagrams 1,500 ms and its inbound 0 ms.
  - Slow run (`B2-path1500`): n-old1's join through y1's link 26.7 s; n-new's join 33.8 s;
    n-new rendered n-old1's hello (in its newest 200 rows: the rig's paging followed a footer
    on stdout that `vox room read` prints on stderr, so a "never" here is "not in the newest
    200"; a hello posted after the join is in that page, so the firsts stand) at join+52.5 s, z1's at +150.8 s (clocks from the join's
    return; the hello loop ran at join+0.1–0.2 s, so these are within 0.2 s of acknowledgment
    clocks, but they are not yet FG-13 ledger receipts); `control_current`'s v0.4.30 stand-in
    (governance revision equal) at +134.8 s; n-old1 rendered n-new's hello at +91.6 s; of 299
    joined-phase samples 295 had an occupied public slot and 292 of those were toward y1
    (running-age median 741 ms, p90 1,334 ms, max 2,678 ms: occupancy, not exchange
    durations); n-new's rounds toward y1 ended 145 completed, 1 partial, 4 failed (`quic
    stream: closed before the frame was written`); n-new's final `peers[]` toward y1: `rtt_ms`
    1,501, path `relayed`; y1 saw every peer at 1,500 ms.
  - Control (`B2-path0`, the same relay at 0 ms): joins 5.0 s and 3.9 s; hellos at +1.1 s and
    +2.1 s; revision equal at +2.1 s; 14 occupied samples in the joined phase, ages ≤ 24 ms;
    `rtt_ms` toward y1: 1. Not the same pre-newcomer workload: the posters stop when the
    earlier join completes, and that join took 26.7 s in the slow run and 5.0 s in the
    control, so the slow run's authors had posted 30 each and the control's 8 each. No
    sessions, no steps, 300 seeds: this is the B2 shape, not the operator-shaped B3.
  - Reading: the slow path reproduces RcaFrozen RC-2's shape on the release asset with no
    knob (the slot pinned by the member whose path answers late; the fast members' facts
    arriving a minute or more late in a quiet room), and the control shows the relay itself is
    not the trigger. It is evidence of the scheduler's sensitivity to a delayed peer; it does
    not stage plan A's busy actor (N4). Against the knob's B2-base (fast members' hellos 90.3 s
    and 95.3 s, y1's own 211.6 s) the slow path is of the same order.
  - Not measured: y1's own hello, and so J1(b) and J1(i) have no green control here. In both
    runs y1 never learned n-new's trust (y1's doctor: "n-new … not in keyring: you have not
    trusted it"; n-new's: "y1 … has not trusted you"; y1's revision 15 against the newcomer's
    16), so y1's hello could not render on n-new and y1 could not read n-new. It happened at
    0 ms too, so it is not the delay's effect: a computer reachable only through the relay did
    not receive the group's policy for a node created after it went relay-only, within 300 s.
    UNKNOWN cause (a product defect in policy delivery, or the rig's anchors file changing at
    the relay-only restart); ADR-043 owns it as item E-b with the settling run E-43-1 (two
    computers; one restarted reachable only through the anchor, at 0 ms; `vox node create` on
    the other; `status --details` sampled 2 s for 120 s on both, both logs; a direct-address
    control with the same sequence). E-43-1 ran (see its entry): the cause is CJ-17's, and J1
    stages `vox anchor add` on every computer.
  - Cost: two runs of 9 min and 8 min, five daemons on loopback.
- **E-1r2. The same slow run, re-measured for N3** (receipt lost in the reboot of 2026-11-13;
  figures recorded here and in `adr-045-revision`; to be re-run as J1's fleet baseline; was
  `/tmp/adr045/runs/B2-path1500-r2/`:
  `rig.log`, `samples.jsonl` with `n-new_peers` at 1 Hz, `datagrams.csv`, `summary.json`;
  forwarder with `--datagram-log`; run while no other measuring agent held
  `/tmp/sync-measure.lock`; same binary; keychain items 2 before and after; data directories
  deleted). Joins 27.9 s (n-old1) and 26.5 s (n-new). n-new's `peers[].rtt_ms` toward y1 at
  all 299 joined-phase samples: min 1,500, median 1,501, max 1,502 ms, path `relayed`; toward
  z1, n-old1 and sib: 0–2 ms, `direct`. Forwarder: 13,780 datagrams, 7,048 of them y1-bound
  outbound at the 1,500 ms setting with actual delay median 1,500.8 ms, p99 1,502.1 ms,
  lateness p99 2.1 ms, max 2.3 ms; the return direction at 0 ms (p99 0.1 ms); 0 send errors.
  Occupied samples 291 of 299, 289 of them toward y1; rounds toward y1 completed 147 in the
  joined window, so about 2.0 s of slot time per completed round. The control's matched figure
  is withdrawn (its joined window has three y1-directed occupied samples and its completion
  count included pre-join rounds); its path witness is `rtt_ms` 1 ms. Hellos: n-old1's at join+1.6 s this time,
  z1's at +270.8 s; n-old1 rendered the newcomer at +103.0 s; revision equal at +252.7 s. The
  spread between the two slow runs (52.5/150.8 s against 1.6/270.8 s) is the freeze's own
  variance under the pinned slot (which member's facts the single slot happens to serve
  first); the shown conditions were identical. y1 again never learned n-new (E-b). Cost: one
  run of 9 min.

**Owed before acceptance, as the first named tasks after the ADR is accepted** (the third
review's ruling: either can move a mandatory fixture or a claim's owner). An experiment agent
runs them and reports in `fleet-experiments.md`; at revision 8 that report exists with
every run pending (E-43-1's first runs contaminated by a lock incident, reruns queued behind
another measuring session). Why acceptance with them open is safe: what each can move is
enumerated and nothing else depends on it. E-7 can only decide whether items 8 and 14 and item
2's responder half count on the fleet (J1's stage-2 act) or are owner-held (ADR-044 RD-16,
ADR-046 SY-6, SY-10); J1's stage-1 act, J2 and every other journey are untouched by it, and the
allocation it freezes is the manifest's field, not a claim. E-9 can only move J5(a)–(g),
FG-12's storage-failure fault and J5(i) between the Linux VM's I and the macOS guest's
image, both of which stage 2 and stage 3 provision regardless; at worst it leaves J5(i)'s
latch-dependent acts `CANNOT MEASURE`, which keeps the gate non-green until another fixture is qualified or the
decider grants an exception (never a silent demotion to the optional in-tree form); S-4's
target is M's personal node either way. The queued E-7 runs on the stage-1 apparatus
(the host rigs, an investigation under FG-19 until repeated in the VM); the queued E-9 (a)
runs in the Linux VM already; E-7b and E-9 (b)/(c) are stage-2 and stage-3 tasks. The first
revision after results land folds them in.

- **E-7. The busy responder by real load** (FG-5 as of r5: attainment is the offered
  workload, the corpus and the allocation; CPU is a diagnostic). S with a corpus of at least
  520 MB staged by the fleet's generator, its shape recorded in the manifest (RcaSlow's `r1/A`,
  523 MB, was the first such corpus and was lost in the reboot), ten OMP-style sessions, steps offered open-loop at RD-14's rate (2 a
  second in all, one timer 500 ms apart, 2 KB each) with every step's acknowledgment timed
  against the 5 s bound, one closed-loop `vox room post` per session; the allocation named in
  the run record. Measured and recorded: offered against acknowledged steps (count, p99, those
  over 5 s; a step's acknowledgment timing is `CANNOT MEASURE` unless a receipt correlates
  that step's send with the bridge's acknowledgment of it, send completion not being a product
  acknowledgment), posts acknowledged, the store's size, `rtt_ms` toward S from a reader (< 50 ms, the
  path witness), S's `vox status` start-to-exit and the driver's `vox room read --limit 1` probe
  on S (medians; the baseline's serving diagnostic, expected seconds), S's CPU and RSS (a
  diagnostic), and the user outcomes of J1(e) (a newcomer's join through S, start to return)
  and J1(f) (every member's render of S's and the others' posts ≤ 5 s) on the baseline, with
  the control (the same without sessions, steps and posts). Settles whether the fleet's offered
  load makes the baseline red on items 8/14; if not, those claims are `CANNOT MEASURE` on the
  fleet and owner-held. The queued run (`/tmp/fleet-exp/e7.py`, `fleet-experiments.md`)
  measures this: steps with acknowledgment times and the over-5 s count, posts, `status` and
  `read --limit 1` latencies at 1 Hz, A's CPU and RSS, B's `rtt_ms` toward A, C's round
  durations toward A, the newcomer's hellos and n-new2's join through A, and a `--quiet`
  control; it differs in allocation (the members run on the host with no `--cpus 1`, 18 cores;
  `taskpolicy -b` is an OS throttle it may add) and defaults to 2 KB steps. Its result stands
  as an investigation on an unconstrained host (FG-19), with the allocation it ran recorded;
  the run that counts is E-7 in the VM configuration, whose runner (`e7vm-run.sh`, the rig
  container at `--cpus 2`, S at `--cpus 1`, under row 86's load cap of 16) is ready and whose
  result line is owed and folded in as its own VERDICT says; it freezes FG-5's allocation,
  without changing what E-7 decided unless the busy responder appears only at one allocation,
  in which case the manifest freezes that one. It must run with `--step-rate 2 --step-len
  2000` and the sessions' acknowledgments recorded; a run that applied `taskpolicy -b` says so
  as its allocation. Runs on the stage-1 apparatus (the queued run) and in stage 2 (E-7b).
- **E-9. Portable latched-I/O and sibling staging** (FG-12's storage-failure fault, J5(g),
  J5(i), S-4). Three stagings, each run with RcaSchedStall's recipe (three rooms, two
  fill-and-free cycles under a peer's posts) and each deciding one thing:
  (a) a sized `--tmpfs` in the Linux VM with the `x86_64` asset under emulation
  (`stall-container.sh`): **MEASURED**, attempt 6, 2026-11-13 18:46–18:58 PST
  (`/opt/vox-evidence/v0431/fleet-exp/receipts/E9a-attempt6-MEASURED/VERDICT.md`; podman machine
  on macOS 27.3, python:3.12-slim-trixie amd64 under emulation, A's data on a 64 MiB tmpfs;
  staging reached: anchor, A and B, mutual trust, three rooms, baseline "A reads B's post in all
  3 rooms after 3 s"): **PRODUCT red on Linux**: on a full tmpfs v0.4.30 pins its sync flows
  exactly as on the HFS+ image, A's status showing 11 retiring Public flows with 11 cleanup
  errors from the first fill that never clear; after the volume is freed every port of A stays
  queued through both cycles and A never reads anything B posted after the first fill; and
  `vox room leave` of room1 after the cycles failed with "an internal error — a bug in vox, not
  something you did" (fix-list item 94: the leave refusal reproduced on Linux), while the end of
  room3 succeeded. Decided: J5(a)–(g) and FG-12's storage-failure fault run on I in the Linux
  VM. Not decided by that run: the sub-question for J5(i), whether tmpfs charges blocks rather
  than length and fails at a data write rather than at `truncate` (the commit error read `store
  commit: I/O error: No space left on device (os error 28)`, a failure at commit, consistent
  with a data write but not shown); the `dd`-past-size and allocated-blocks check is owed before
  J5(i)'s SO-2 arms run on the tmpfs; until then they run on the guest's image. The five
  earlier attempts were APPARATUS (`E9a-attempt1…5-*`) and are kept as receipts.
  (b) a loop image inside the podman VM (an ext4 file losetup-mounted by root in the VM, no
  `sudo` on the host): decides whether redb's latched native failure (`No space left on
  device` after SO-11's admission) appears on Linux; if yes, ADR-047's SO-12 arms
  (J5(i)) may run on Linux too and the manifest may place them there; if no, they stay on the
  guest.
  (c) a 256 MB APFS image on the macOS guest (SO-11's staging; RcaSchedStall and ADR-049's
  E-49a used a 64 MiB HFS+ image, APFS is to be confirmed): decides that J5(i)'s latch-dependent acts have a host at
  all; if APFS does not latch where HFS+ did, they run on an HFS+ image (`hdiutil -fs HFS+`)
  and the manifest says so; if neither latches, they stay `CANNOT MEASURE`, and so the gate
  is not green (FG-1): nothing demotes it; another fixture is qualified (an ext4 loop image in
  the Linux VM under (b), or another filesystem on the guest) or an explicit exception for that
  coverage is obtained from the decider before the mandatory coverage changes, and the first
  revision after E-9 records which.
  Also in each: the sibling staging (two nodes on one daemon, the personal node's data on the
  image, the agent sibling healthy throughout), which decides nothing about placement but is
  S-4's precondition. (b) is running in the Linux VM as this revision is written (attempts 1
  and 2 APPARATUS: the host guard stopped them at load above the limit; ledger row 86 then set
  the VM experiments' cap to load 16 with containers at 2 CPUs, one VM experiment at a time, a
  30-minute cap); its result line is owed and is folded in as its own VERDICT says. (c) is a
  stage-3 task. 30 min each.

**Fail-closed before their claims** (may remain open at design sign-off; the claim is
`CANNOT MEASURE` until run).


- **E-2. Item 60, reading (B), on v0.4.30** (FG-15): an M-shaped daemon with two nodes on the
  largest stores available (today 526 MB and 302 MB), ten stepping sessions, the J2 wedge, a
  container peer dialling every 2 s for 30 min; then the control without sessions or wedge.
  Needs stage 2; 45 min.
- **E-3. Item 60, (A′), the policy reset in the guest**: two tries of 10 min. Needs stage 3.
- **E-4. A small volume without `sudo`** (J5's Mac side): `hdiutil create -size 200m -fs APFS
  -volname fleetfull /tmp/fleet/full.dmg` and attach; 1 min. If refused, the container side
  carries J5.
- **E-5. The grower's first run**: 6 h on v0.4.30 with V impaired; expect 1 GB or more on the
  heaviest node (the operator's Mac grew about 480 MB per 2 h); validates the manifest and
  settles whether a ≥ 2 GB store needs one run or two. Needs stage 2.
- **E-6. The `x86_64` asset as a load member** (Q3): one J3 run with B on the asset; if its
  post p99 is within 2 × the aarch64 build's, the asset can carry J7's Linux half too.
- **E-8. J5(f) and J6(a) on the asset**: the leave while the room cannot save (ADR-049's E-49a
  now supplies the pinned-flow refusal; the cannot-save refusal at `leave.rs:60` is still
  unverified), and the trust pass parked in a full room (ADR-048 TC-9-A); fail-closed before
  J5(f)'s and J6(a)'s stage-2 claims. Needs stage 2; 15 min. J5(g)'s red needs no new run:
  RcaSchedStall's and E-49a's receipts are it.
- **E-43-1** (ADR-043's spike; receipts `/opt/vox-evidence/v0431/fleet-exp/receipts/E43-*` and
  `/opt/vox-evidence/v0431/rca-relay-only/`): reproduced item E-b on the v0.4.30 asset (three
  relay shapes PRODUCT red, direct control green) and, with `rca-relay-only`, established its
  cause (the computer management holds only the serving process's startup `--anchor` list; fix:
  ADR-043 CJ-17). Its blocking proof is J9(i); J1's stage-1 staging rule is replaced by CJ-17's
  cause. The residual 60 s/`no complete frame` observation is fix-list item 95, not this act's.

## Consequences

### Positive

- A defect of the kind that reached the operator 87 times in three days is to reach the fleet
  first, with a receipt that names the claim, quotes the product, replays the schedule and
  shows the conditions it ran under.
- Every item of v0.4.31 has a claim a person would recognise, red on v0.4.30 and green on the
  fix, with its control or mutant, or names the owner proof that holds it.
- Reviews rest on the reviewer's own run.
- The product's status becomes something the gate can hold it to: outcome 2 fails a release
  whose status says "up to date" while the ledger shows nothing arriving.
- A node that stops receiving is red within seconds, on its own, whatever its sibling does.

### Negative

- About 3 h 20 min of journeys plus a 5 h soak per candidate, 8–10 h of wall clock in all
  (R-9): the cadence moves from hours to a working day. Five releases in two days is no longer
  possible; that is intended (R-1, R-2). What a longer run would have found is covered by
  rates, projections and clock-stepped owner proofs (FG-12), and that is a stated limit.
- The fleet shares one host with other work; timing bounds on shared hardware are noisy.
  ADR-018 §10.12 makes a red under ordinary load a product red; the recovery interval after
  an injected fault is the only concession.
- The guest is not on Wi-Fi; a real link drop is seen only by the capture (FG-16). Every
  computer runs on this Mac's CPU and disk (the containers inside the podman Linux VM, the
  guest in its own macOS kernel). FG-19 says so in every receipt and in the green summary.
- The `x86_64` asset runs only under emulation and carries only the asset-level claims (Q3).
- Stage 1 reproduces items 1–3's delayed-member half on demand; the busy responder (items 8,
  14) waits for stage 2's real-load fixture, and items 85/87 and 64/86 for stage 2's small
  disk image (J5(g)); it says so.
- The driver, the containers, the grower and the nursery are code and data to maintain.

### Neutral

- No product, wire or store format changes. Nothing in the product depends on the fleet;
  removing the `fleet` step returns the gate to today's.
- CI is unchanged.

## The decider's answers (2026-11-13)

Every question this ADR asked is answered (ledger row 52 and the rows R-12 to R-14 cite); the
questions are kept as asked, each with his answer. The room-wide pause, the Linux first-upgrade
credential policy and the storage choices stayed with their owning ADRs and were answered there.

- **Q1 (FG-1, FG-3, FG-11; amends ADR-018 §10.2, §10.9 and AGENTS.md).** Do the fleet journeys
  block the release as a `fleet` step of `scripts/release-gate.sh`, with CI unchanged, and do
  reviewers run them themselves (R-4)? Today ADR-018 §10.2 makes every expensive proof optional
  and §10.9 forbids re-running a fixer's green. *Recommendation: yes to both*, as "don't give
  me more broken shit" and "no minimal release" require; the §10.2 amendment names only J1–J13.
  With "no", the fleet becomes an optional troubleshooting kit and v0.4.31 has no gate that
  sees its conditions. ADR-044's question on its load journey and ADR-046's Q6 are answered
  by this choice. **Answer: yes to both** (R-11; and R-12 adds ADR-044's five arms as blocking
  and moves the whole gate into the VMs).
- **Q2.** Withdrawn: the gate's length (8–10 h, no standing run) and the old peer (all machines
  move together, no mixed-version support) are rulings R-9 and R-8, recorded in FG-12, J12 and
  Appendix A, not asked again.
- **Q3 (FG-4, FG-6, FG-17, FG-2).** Resources and hours for the VMs on this Mac (R-10 settles
  that the fleet runs inside VMs): (A) at most 20 vCPU and 48 GB; one queue, the fleet's,
  which refuses to start while another rig holds `/tmp/sync-measure.lock` or its own lock; a
  gate run of 8–10 h in the hours you name; a stop you can issue at any time (`fleet/gate.py
  --stop`, which ends every fleet process within 30 s and leaves the receipts); VM experiments
  before the fleet exists stop at host load 16 with their containers capped at 2 CPUs, one at
  a time, 30 min each (row 86); the `x86_64`
  asset carrying only the asset-level claims and the load members on an `aarch64` build of
  the same commit; or (B) the same with a separate Linux host for the containers and the
  native `x86_64` claims, this Mac's guest kept for the app journeys, and v0.4.31 waiting for
  the host. *Recommendation: A.* With (B) stages 2–4 wait for the hardware. **Answer: A**
  (R-11: the VMs on this Mac, at most 20 vCPU and 48 GB, a stop within 30 s).
- **Q4 (FG-15, FG-16, FG-19).** The open incidents: (A) v0.4.31 may tag with each named
  incident still open, item by item: 60 (provided FG-15's A-1, A-2 and (B) are green), 35, 46,
  47, 87 (until Vince's evidence), E-b (until E-43-1), and the conditions the fleet cannot
  reproduce (FG-19), each named in the release notes as open; or (B) no tag until each has a
  reproduced cause or a demonstrated invariant that removes its class. *Recommendation: A, as
  item-specific exceptions, never as "all operator conditions proven".* Item 85 is no longer
  on this list: its cause is reproduced (FG-20). The capture was asked for beside it.
  **Answer: A, and no capture on his Mac** (R-11): each incident is named as open in the
  release notes; nothing is armed, and the release notes say so; FG-16 stays as the written
  instrument.

## Appendix A. The inherited QA rows

From the draft v0.4.31 QA matrix (the decider, 2026-11-12: "STRONG QA in the vm … don't give
me more broken shit"), reproduced so that the draft file can be deleted. Every row runs on the
candidate assets in the guest or a container, never on the operator's machines; every red
names PRODUCT or APPARATUS (FG-14). Baseline for "previous release": the published v0.4.30
assets.

| # | Journey | Setup | Pass when | Held in | Kind; mutant (FG-9) |
|---|---|---|---|---|---|
| Q1 | Update with live rooms | guest: 0.4.30 app and daemon, two nodes, a room with ≥ 3,000 entries, a peer daemon reachable only through a relaying anchor (≈ 300 ms RTT), one registered agent session posting every 5 s | `vox update` to the candidate completes; the session's next post succeeds with no session restart and no `node … is unavailable`; both sides complete a sync round within 30 s; `vox room board` exit 0; the app shows the room without re-selecting | J12 | R; mutant: skip the session re-attach after the update (the post fails, `node … is unavailable`) |
| Q2 | Daemon restart under traffic, relayed | the same room; a peer posts 2/s, five sessions announce (about 100/min) | 3 restarts (rate smoke): first completed round both sides ≤ 30 s, `queued` not climbing over the following 60 s, posts readable both ways | J7 | R; mutant: restore v0.4.30's supersede (`queued` climbs) |
| Q3 | Baseline discriminates | Q2 on 0.4.30 | the wedge reproduces (rounds stop, `queued` climbs); else Q2 is not evidence | FG-9 | baseline discriminator (FG-9), not a claim |
| Q4 | Linux restart keeps the node | container: a node created with a passphrase, unlocked once | `vox daemon --restart` and `vox update` candidate → candidate leave it Ready with no input; `vox node list` says remembered; the first update from 0.4.30 prints RS-4's warning | J7(c), (c′) | R; mutant: skip the keyring store (`Locked` after the restart) |
| Q5 | Mixed versions coordinate | a 0.4.30 node and a candidate node in one room | withdrawn (ruling R-8, 2026-11-13: all machines move to 0.4.31 together; no mixed-version sync support); the one-time update path is Q1 and Q4 | — | withdrawn (R-8) |
| Q6 | Sessions survive restart | candidate daemon, a registered session | `vox daemon --restart` → the next hook call re-attaches silently, the post lands; the Locked case says `node <name> is Locked; vox node unlock <name>` | J7 | R; mutant: refuse the re-attach after a restart (a conversation restart is demanded) |
| Q7 | Fresh profile journey (v0.4.27) | candidate app, a new profile | create node → create room → inspector CREATOR ≤ 5 s without re-selecting → post → a peer joins → `2 members` | J12 | F; mutant: the inspector's CREATOR row filled only on re-select |
| Q8 | Busy-room board (v0.4.28) | 5 nodes churning claims and asks | 30 of 30 whole boards | J12 | R; mutant: drop a claim type from the board fold (a board short by one row) |
| Q9 | Burst delivery (v0.4.30) | 1 and 4 readers, 20–25 posts/s for 60 s | readers advance every few seconds (no stall > 5 s), the poster 0 failures; 4-node churn 200 of 200 claims, p99 < 1 s | J12 | R; mutant: cap the reader's advance at one page per 10 s (a stall > 5 s) |
| Q10 | Updater with a wedged app (v0.4.29) | the app `SIGSTOP`ped | the update completes and says `it was stopped` | J8(c) | F; mutant: judge the app by the cached flag (`did not quit within 30 seconds`) |
| Q11 | Release smokes | the guest smoke of the app, the Linux consumer smoke, `check-release-assets.sh` | all green on the candidate assets; notarization and Gatekeeper are not checked before the tag (the dry run signs ad hoc, FG-2) and are checked by `release.yml` and the post-release smoke | J12 | apparatus self-check of the assets (no product mutant) |
| Q12 | Soak | candidate ↔ candidate, relayed, with the Q2 load and faults | FG-12 and FG-13 replace this row (5 h, ruling R-9) | J13 | replaced by FG-12/FG-13 (their mutants) |

## Links

- ADR-018 (§6, §7, §8, §9, §10.1–§10.13, §11.1, §12), ADR-034 (FR-6, PF-2), ADR-038 (FX-19,
  FX-20), ADR-033 (PA-2).
- v0.4.31 lanes: ADR-040, ADR-041, ADR-042, ADR-043, ADR-044, ADR-046, ADR-047; ADR-039.
- Tree at `v0.4.30`: `.github/workflows/ci.yml`, `.github/workflows/release.yml`,
  `scripts/release-gate.sh`, `scripts/release-dry-run.sh`, `scripts/app-proofs-vm.py`,
  `docs/release/app-proof-vm.md`, `docs/release/optional-proofs.md`,
  `crates/vox-tui/tests/support/port_forward.rs`, `crates/vox-tui/src/keychain.rs`,
  `crates/vox-tui/src/host.rs`.
- Receipts: every directory this ADR cites under `/tmp/` or `/private/tmp/` (`/tmp/adr045/runs/`
  for E-1 and E-1r2; `/tmp/rca-RcaWedge/`, `/tmp/rca-RcaFrozen/`, `/tmp/rca-RcaSlow/`,
  `/tmp/trial-sync/`, `/tmp/plan-PlanD/`, `/tmp/adr040/`, `/tmp/adr043/`,
  `/tmp/RcaSchedStall/receipts/`, `/tmp/Adr049Leave/run.log`, `/tmp/fleet-exp/`; the operator's
  evidence under `/private/tmp/vox-rca/`, among it `mac/stall-robert-work-021627Z.json`,
  `mac/stall-omp-work-021627Z.json` and the empty `lan-outage-captures/`) was lost in the
  reboot of 2026-11-13 07:23 PST (ledger row 64). The figures stand as recorded in the named
  reports (`rca-RcaWedge`, `rca-RcaFrozen`, `rca-RcaSlow`, `trial-sync-progress`,
  `rca-RcaSchedStall`, `adr-040-revision`, `adr-043-revision`, `adr-049-revision`,
  `adr-045-revision`, `rca-RcaLanPath`, `rca-systemic`) and every baseline this ADR relies on
  is to be re-run as the fleet's own baseline receipt (FG-9) into `~/vox-fleet/receipts/`.
- External: https://apple.github.io/foundationdb/testing.html ·
  https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md ·
  https://antithesis.com/docs/product/writing_tests/controlling_faults.md ·
  https://jepsen-io.github.io/jepsen/jepsen.nemesis.combined.html ·
  https://github.com/Shopify/toxiproxy/blob/main/README.md ·
  https://www.wireguard.com/protocol/ · RFC 9000 §9 (connection migration).
- Release milestone v0.4.31.
