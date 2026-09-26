# ADR-018: Quality Bar — the Product-Proof Harness is the Test Authority

**Status**: accepted (2026-09-21) — the policy is in force from this change; the harness lands with it
and grows per capability
**Date**: 2026-09-21
**Updated**: 2026-09-21 — §7 added: a green gate is not evidence — six gates were asserting the defect ADR-017 M17.6 removed, or measuring something other than their own label, and all six were passing. Earlier the same day — §6 added: a hung proof is a failing proof. Two gate processes ran 21 hours unnoticed; the in-test `tokio` timeouts cannot bound a spinning runtime, so every gate now carries a process-level watchdog that aborts (for the thread stacks) and every CI job a `timeout-minutes`. The underlying hang is unreproduced and recorded as latent. 2026-09-21 — M18.2a: `update_proof` and `install_sh_proof` landed with the distribution
work, and the two obligations they cannot yet meet are recorded in §3's accepted-gaps table rather
than skipped.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: quality, tests, proof, receipts, gates, methodology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY** and **OPTIONAL** in this document are to
be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all
capitals.

## Context

On 2026-09-21 this repository had **877 passing tests** and every gate green. The `vox serve` →
`vox connect` → `vox up` → `ssh` flow was then run as four real commands for the first time. It failed
three times before it worked, on three separate defects:

1. `vox serve` handed the node a hyphenated passphrase while `vox connect` stripped the hyphens, so
   every join was refused with no indication why;
2. `vox node` printed `0.0.0.0` as the string to paste into `--anchor` — a bind address no client can
   dial;
3. `vox up` dialled the host *before* binding, so a node that had only just joined raced the board
   fetch and the command failed intermittently.

**Every one of the three was a handoff between two commands**, and not one of the 877 tests could see
any of them. The release gate for that very feature passed throughout, because it drove the node API
directly and used one passphrase value for both sides — the defect lived in the seam the gate stepped
over.

That is the general failure, not an unlucky day: test volume, source coverage and green intermediate
artifacts did not answer whether an operator could use `vox` successfully. The suite was optimised for
isolated implementation checks, and an ordinary manual run exposed escaped product defects in minutes.

This ADR is modelled on the same conclusion reached independently in `repo-to-cve`'s ADR-018
("the product-proof graph is the primary test authority").

## Decision

### 1. The product-proof harness is the primary test authority

A milestone or release MUST be qualified by a small, explicit graph of proofs taken **through the
surface a user or a peer actually touches** — the shipped `vox` binary, or a real peer speaking the
wire protocol — and MUST NOT be qualified by an indiscriminate execution of every test target.

The graph MUST contain all of:

1. **one node per user-facing capability**, proving its real input authority, the transformation an
   operator cares about, its authoritative output, and its diagnostics;
2. **one independently named edge assertion for every producer-to-consumer handoff** between
   capabilities — what one command *prints* and what the next command *accepts* — because that is where
   every defect found so far has lived;
3. **one single-invocation end-to-end journey** through the shipped CLI from a pristine state; and
4. **resume cases** wherever a handoff persists state, proving the consumer accepts what the producer
   actually left behind after a restart.

Each proof MUST retain its receipts: the exact command, its exit status, its output, and the artifacts
it produced or consumed.

### 2. A test MUST measure the feature, not the implementation

A test MUST answer "does this feature work for the party that uses it". A test that asserts the
behaviour of an internal helper, where that assertion can hold while the feature is broken, MUST NOT be
added.

The canonical example is in this repository. `vox shell-setup` maintains a block in a shell's startup
file. Assertions about the block's text all pass in the state where zsh has already run `compinit`,
adding a directory to `fpath` is invisible to it, and **tab completion silently does not work**. The
only test that measures the feature spawns a real `zsh`, lets it read the rc as it normally would, and
asks the shell whether a completion is registered for the command (`_comps[vox]`). That is the standard.

### 3. Absent evidence MUST NOT read as success

A proof whose prover is unavailable — an uninstalled shell, absent hardware, a missing credential —
MUST be reported as **unproven** and MUST fail the proof. It MUST NOT be silently skipped.

A gap MAY be accepted deliberately, and when it is, the acceptance MUST be explicit and visible at the
point of running (for example `VOX_PROOF_ALLOW_UNPROVEN=install.apple_gate_refuses_unsigned_bytes`)
and SHOULD be recorded here. A failing
or blocked obligation MUST be recorded as failing or blocked, never as waived-green.

**Accepted gaps, as of 2026-09-21:**

| Gap | Accepted because | What would close it |
|---|---|---|
| `install.apple_gate_refuses_unsigned_bytes` in `install_sh_proof` | the installer's Developer ID and notarization gate is macOS-only, so on Linux there is nothing to measure. On macOS it is proved, by forcing the gate on against an unsigned fixture. | nothing closes it on Linux; it is a property that does not exist there |

**Closed by `v0.2.0`, 2026-09-22: the two `update_proof` gaps — and what the second one found.**
Both were accepted because there was no earlier release to update *from*. `v0.2.0` supplied one, and
`journey.update_replaces_an_older_install` began passing with no code change, exactly as its remedy
predicted.

`verify.digest_mismatch_is_refused` did not. It failed, and the failure was the point: the
published `proof-<triple>.json` carried a `note` field explaining why its digest was deliberately
wrong, while `ReleaseRecord` is `deny_unknown_fields`. So every released `vox` refused that record
**at the parser** — "release record is not strict schema-1 JSON" — one step before the digest check
the record exists to exercise. `v0.1.0` and `v0.2.0` both shipped it. The refusal ADR-018 §3
requires to be *proved rather than assumed* had never once been reached.

Two things follow, and both are now enforced rather than remembered:

1. **A record read by a strict parser carries exactly the schema's fields and nothing else.** The
   explanation belongs in the generator's comment, where a person reads it; the record is for
   machines. `scripts/package-release.sh` now compares each record's key set against schema-1's and
   refuses to package if it differs, so this class of defect cannot reach a release again.
2. **A gap accepted for one reason can be held open by another.** These two entries sat under one
   stated cause — "no earlier release" — and when that cause was removed only one of them cleared.
   An accepted gap SHOULD be re-measured when its stated remedy lands, not assumed closed by it.

**Closed in CI, 2026-09-21: `fish` in `shell_setup_proof`.** It was accepted because the shell was
not on the runners, and the entry itself named what would close it — "installing `fish` on the
runner". The workflows now install `zsh` and `fish` before running the proofs, so **CI does not
excuse `fish`**. An accepted gap that states its own remedy SHOULD be closed rather than renewed.

The whitelist is therefore per-environment, and CI's is the strict one:

```
# CI (ubuntu + macOS, both with zsh, bash and fish installed):
VOX_PROOF_ALLOW_UNPROVEN=journey.update_replaces_an_older_install,verify.digest_mismatch_is_refused,install.apple_gate_refuses_unsigned_bytes

# a developer machine that has no fish may additionally name it:
VOX_PROOF_ALLOW_UNPROVEN=fish,journey.update_replaces_an_older_install,verify.digest_mismatch_is_refused,install.apple_gate_refuses_unsigned_bytes
```

A local list MAY be longer than CI's; it MUST NOT be shorter, and CI's MUST NOT grow to match a
developer's machine. The point of the mechanism is that the strict list is the one that gates the
repository.

Removing an entry MUST make the proof fail until that gap is closed — that is the point of it. The
value is set once, in `.github/workflows/ci.yml`, so the accepted gaps are visible in the gate
itself and not only here. (`release.yml` carried a copy while it re-ran the gates; since 2026-09-26 it
runs no proof — see "Publish only what CI proved".)

A whitelist entry matches either a whole claim id or its first segment, so a gap MAY be accepted
precisely (`verify.digest_mismatch_is_refused`) rather than by area (`verify`). Accepting by area
would silently absorb claims added later, which is the failure this section exists to prevent.

### 4. The in-source unit tests are removed

The ~800 in-source unit tests that assert internal helpers are deleted by this change, together with
the `#[cfg(test)]`-only scaffolding that existed solely to serve them (`Argon2Profile::REDUCED`,
`VOX_SUITE_TEST_WEAK`, `test_support`, `SenderChain::new_with_parts`). No integration proof referenced
any of it — verified before deletion, not assumed — so no proof loses evidence.

### 5. Retained suites, and the reason each is retained

The following in-source suites are **kept**, because each measures a property that matters and has no
equivalent reachable through an external surface today. Each entry MUST name that reason, and any entry
that stops being true MUST be either replaced by an external proof or deleted.

| Suite | Property measured | Why it is not an external proof |
|---|---|---|
| `governance/vectors.rs::golden` | the authorization engine's verdict on real signed structures, including `DenyReason` and order-invariance | ADR-007 names this suite as a release gate; the verdicts are not observable from outside without a multi-node partition harness |
| `governance/evaluator.rs::causality_tests` | two nodes converge on one answer regardless of the order entries arrive | the same missing harness; convergence under partition is the property, and a single node cannot exhibit it |
| `join/cpace.rs` | the CFRG Appendix-B CPace vectors | conformance to a published standard is interoperability with *other* implementations, which no local run can demonstrate |
| `cbor.rs` | the RFC 8949 canonical-encoding vectors | as above; these bytes are the contract between versions |
| `nat/portmap/upnp.rs::mock` + its tests | port mapping against a spec-faithful IGD, including real-router quirks | **the only UPnP evidence that exists** — no router on the development LAN answers SSDP, and there are zero integration gates (real-hardware validation remains pending, ADR-012) |
| `deniable/tests.rs` | the full 4-round DGKA among m≥3 members, and the `0x000B` codec every round is carried through | a multi-party key agreement cannot be exhibited by one node, and deniable mode is **not enabled**, so it has no external surface at all — the same reason as the evaluator's convergence suite. Recorded 2026-09-21: it survived the M18.2 purge without being listed here, which this row corrects |
| `atrest/sek.rs::production_timing_spike` | the production Argon2id profile actually costs what ADR-010 requires | a measured cost, not an assertion; nothing outside the process can observe it |

### 6. A hung proof is a failing proof

Every gate and proof process MUST carry a **wall-clock bound that ends the process**, and CI jobs
MUST carry one too. This is not the same obligation as §3, and it is not met by the in-test
timeouts the gates already have.

**What happened.** On 2026-09-20 two `node_m15_anchor_gate` processes were found still running
**21 hours** after they started, each consuming about 1.5 cores, alongside a stuck `cargo test`
parent. Rebuilding this repository at `92a79f8` (the M15.1 merge) reproduces their binary hash
exactly, so they were that milestone's code; they started seven minutes before that merge, and are
almost certainly the abandoned runs of the debugging session that found and fixed a `connect_direct`
hot-spin in the same window. Nothing reaped them, and **nobody noticed for a day**.

**Why no gate caught it.** A hung test emits nothing — no failure, no output, no exit status. It is
indistinguishable from a test that is still running. Every one of the six gates reports on results;
none of them can observe the absence of a result.

**Why `tokio::time::timeout` was not enough.** Every wait in those gates is already wrapped in a
120-second timeout, and the poll loops sleep between iterations. That bounds *one await inside a
runtime that is still working*. It cannot bound a task spinning without yielding — which starves the
timer that would have to fire — nor a blocking call on a runtime thread, nor anything after
`block_on` returns, nor the process once libtest believes the test is over. The observed ~150% CPU
says spinning, which is precisely the case an in-runtime timeout cannot see.

**The bound MUST therefore be outside the runtime, on the wall clock, and MUST end the process.**
`crates/vox-core/tests/support/watchdog.rs` does this and MUST be armed by every gate and proof.
It MUST abort rather than exit, so the operating system records every thread's stack — a hang's
whole difficulty is that it leaves nothing to look at, and this incident left nothing. The budget is
generous by design (600 s against a ~53 s worst case): it is not a performance assertion, it is the
line past which "slow" stops being a credible explanation. `VOX_TEST_WATCHDOG_SECS` overrides it and
`=0` disables it, for attaching a debugger.

Its own proof is `watchdog_proof.rs`, which re-executes the test binary with a test that spins
forever on purpose and requires the child to die, by `SIGABRT`, inside its budget, having said why.
Mutation-checked: disabling `arm()` makes it fail with "the watchdog did not kill a deliberately
hung test within 60s".

**The underlying hang was not reproduced** — 12 sequential and 12 concurrent runs of that exact
binary, none hung — and no sample or crash report from the original window was retained. It MUST
therefore be recorded as **still latent**, not fixed. What this change buys is that the next
occurrence is a loud failure with thread stacks rather than a silent process burning a core until
someone happens to run `ps`.

### 7. A green gate is not evidence: a gate can assert the bug

**Added 2026-09-21**, from ADR-017 M17.6, where removing one defect broke **six gates that were all
green.** The number is the point: green is what made them invisible. Numbered here rather than inserted
earlier so the existing `ADR-018 §N` references in the tree keep pointing where they did.

Two failure modes; the second is the dangerous one.

**(a) The gate asserts the defect.** The removed behaviour was that joining a room released the joiner's
sender key to whichever member answered the join — a consent grant nobody decided. Four gates
(`node_m14_gate`, both in `node_m15_anchor_gate`, `node_m18_revocation_gate`) *waited for that key to
arrive* as their setup, so each was a standing assertion that the defect was present, and each went red
when it was fixed.

The instructive one is `node_m18_revocation_gate`, whose comment read *"Alice must hold both joiners'
keys before she serves anything: an ADR-004 responder has no sending chain until it has received."* The
**premise is true** — a PQXDH responder genuinely cannot send until it receives a ratchet message. The
conclusion was the defect: what it needs is a *ratchet message*, not a *sender key*. A gate can be wrong
while every word of its reasoning is right.

**(b) The label has drifted from the assertion.** Worse, because nobody ever chose wrongly: it rots as
the code moves and stays green throughout. `node_m15_anchor_gate` asserted `entries >= 3` and called them
"genesis, consent and the message" — the genesis is never a DAG entry (`entry_count()` is `dag.len()`),
so the third was another node's automatic consent, synced in. Both gates in `node_m19_trust_gate`
labelled a check *"both members admitted"* while asserting `entries > 0`, that entry being the same
automatic consent; once it was gone the check could never pass, while the property in the label had been
true all along.

Therefore:

- When a gate fails after a behaviour is **removed**, the first question is whether the gate was
  *asserting that behaviour*. If it was, **rewrite it** — do not extend it, and never restore the
  behaviour to make it pass. Record in the governing ADR what changed and whether the property under test
  is unchanged or weakened. Precedent: ADR-017 records M17.3's gate the same way.
- **Read every gate's comment against its assertion.** Where they disagree the comment is usually the
  intended property and the assertion is the accident. It is a cheap audit: it found one instance in a
  suite whose author then checked the other five and found them sound.
- **Expect more than one.** Six surfaced over four full release runs, one at a time, because a run stops
  at the first failing binary. The first green run after a fix is not the end of it.
- **Instrumentation can be load-bearing.** A debug round that logged a frame send *sent it twice*, masking
  a real race so the failing gate passed. Remove instrumentation and re-run before believing a green.

### 8. A proof must never restate a constant it depends on

**If a test hard-codes a number that has to stand in a relationship to a constant in the
source, it must reference the constant.** A comment cannot enforce a relationship between
two numbers, and nothing checks a comment.

The case that produced this rule, 2026-09-22. `service_rehearsal_proof` — the flagship
real-binary proof — contained:

```rust
// Longer than `node::up::HOST_PATIENCE`, or this times out on the proxy's own wait
// and reports EAGAIN instead of what the proxy decided.
s.set_read_timeout(Some(Duration::from_secs(150)))?;
```

`HOST_PATIENCE` was later raised to 300s. **The comment stayed true as prose and stopped
being true as fact**, and the gate then failed roughly half its runs with
`Resource temporarily unavailable (os error 35)` about 155 seconds in — the test giving up
while the proxy was still legitimately waiting, with the operating system reporting the
read timeout as EAGAIN.

What made it expensive is that it does not look like a test bug. It looks like a race in
the service path: a different error text at a different stage on each run. Two sessions
spent hours on it, one of them chasing `ConnectionManager::file` and the
one-connection-per-peer rule on a shared hypothesis that three distinct error texts could
not be one cause.

**Two lessons, both general:**

1. **Export the constant and derive from it.** `HOST_PATIENCE` is now `pub` and the proof
   adds to it, so the invariant is carried by the compiler. The same applies to any bound a
   proof must outlast — a retry deadline, a patience window, a watchdog.
2. **"A timeout fails the same way every time" is false for a read timeout.** The kernel
   surfaces the same expiry as `EAGAIN` when it lands on a connect-shaped wait and as a
   reset when it lands mid-stream, so *one* cause routinely wears several faces. Distinct
   error texts are therefore **not** evidence of a race, which is what both sessions
   believed. Treat varied symptoms as a reason to find the common deadline first.

### 8b. Whatever knows why must say why

The general form of §8, and of §7, arrived at after a single day produced four instances of
one shape. In each, something held the answer and did not report it, and each cost about an
hour:

| Where | What knew, and stayed quiet |
|---|---|
| A test | `assert!(out.is_done(), "carol joins")` discarded the `Outcome`. Printing it gave `Failed(Unreachable)` and the diagnosis in one run. |
| Three golden vectors | They pinned a live vulnerability as the guaranteed behaviour, and being green said nothing. |
| A comment | It asserted a relationship between two constants; when one moved, nothing checked it (§8). |
| The product | The ADR-012 dial ladder returns `Unreachable` without naming which rung failed — direct, punch, or circuit. |

The last is the important one, because it is the product rather than the scaffolding. A
serverless overlay's hardest failures are reachability failures, and "it did not work" is
the least useful thing the code can say about one. **A failure must carry what the code
learned while failing**, at least to the degree that does not leak across a trust boundary —
and a *local* diagnosis leaks nothing, since the dialer already knows what it tried.

This is distinct from what the *wire* may say. ADR-013's dark-services rule deliberately
makes a refusal indistinguishable from "no such service" **to the peer**; that stays. The
rule here is about what a node tells its own operator.

Applies to: `Fault::Unreachable` from a dial (which rung, and what each said), a join
(which candidate, and why each was rejected), and any bound expiring (which bound, and what
it was waiting for).

Related: §7, and the rule that a red gate has three possible meanings — the product is
broken, the test asserts a model that was withdrawn, or the environment cannot prove the
claim — and its colour distinguishes none of them.

### 8a. The six gates remain

`fmt`, `clippy -D warnings`, `test`, `rustdoc -D warnings`, and the release-only `--ignored` run remain
REQUIRED for every change. This ADR changes what `test` *contains*, not whether it must pass.

## Consequences

### Positive

- The thing that gets proved is the thing an operator does. The harness automates by construction the
  manual run that found three defects the suite could not.
- Handoffs get named obligations. All three known defects were handoffs, and none had an owner.
- Absent evidence becomes visible. A missing prover fails loudly and a deliberate gap is written down.
- The suite gets smaller and faster, and what remains is either a proof or a published vector.

### Negative

- **Coverage of internal helpers is genuinely gone.** A refactor that breaks a helper in a way no proof
  exercises will not be caught by a test; it will be caught by a proof only if it changes observable
  behaviour. This is accepted deliberately: those tests were not catching the defects that escaped.
- The harness is slower per run than a unit test, so the feedback loop for a small change is longer.
- Writing a proof requires a real prover — a shell, a peer, a socket — so some properties become harder
  to test, and a few (convergence under partition) are not testable at all until the harness for them
  exists. Those are listed in §5 rather than pretended away.

### Neutral

- Golden **wire-byte** vectors for the ADR-008 struct tags remain UNMET (see `docs/adr/README.md`). This
  ADR does not change that; it records that cutting `v0.1.0` is when it starts to matter, because
  `v0.1.0`'s bytes become what `v0.2.0` must not break.

## Implementation plan

Each item is one branch, red→green, with this ADR updated in the same change (house rule).

- **M18.2 — remove the unit tests.** Delete the in-source test modules and the `cfg(test)`-only
  scaffolding, retaining exactly the suites in §5. Gate: the nine integration proofs and the six gates
  stay green, and the retained suites still run.
- **M18.2a — distribution, proved as it was built (done 2026-09-21).** `vox update` and `install.sh`
  landed with `update_proof` (11 claims: the ownership refusals, the marker→record channel lookup, the
  live `--fail`/404 premise with its negative control, `--check` changing nothing, and rollback
  including the `update → shell-setup` edge) and `install_sh_proof` (8 claims, driving the real
  `install.sh` against a loopback release server: the happy path, and every refusal — wrong digest,
  wrong size, foreign target, foreign kind, and a `vox` the installer did not install). Both report
  their blocked claims as failures, which is how the two gaps above came to be written down.
- **M18.3 — the proof harness.** The node/edge/journey matrix above, driving the shipped binary, with
  retained receipts. Its first obligations are the four edges the rehearsal exercised:
  `anchor → serve`, `serve → connect`, `connect → up`, `up → ssh`. Gate: each of the three known defects
  is reproduced by the harness when its fix is reverted.

## A third, and a gate that asserted a guarantee the model declines to make (2026-09-24, CLOSED same day)

`work_board_proof::two_agents_split_work_and_only_one_holds_a_contested_resource` is excluded from
the release gate, by name, with its cause identified. It is worth its own entry because it is the
**mirror image** of the failure this ADR is mostly about: not a gate that asserts a bug, but a gate
that asserts a promise the product explicitly does not make.

ADR-020 §5 says it plainly: *"Resolution is deterministic but not causal within one second."*
`created_secs` has one-second resolution, so two entries in the same second are ordered by an
entry-hash tie-break — every node computes the same answer, and that answer need not match the order
things happened in. The proof asserts causal outcomes at two sites: that a later claim **loses**
(step 3), and that a fresh claim **succeeds** after a release (step 4). Both fail whenever the two
actions land in the same second.

**Pre-existing, and measured on both arms rather than assumed:**

| tree | result |
|---|---|
| `main` (tonight's 8 commits) | 1 failure in 3, quiet box, loads 6-7 |
| `3f1cb7d` (v0.2.5, shipped) | 1 failure in 3, quiet box, loads 6-9 |

Same assertion, both arms. So it is not a regression, and the eight commits in between were
eliminated two ways: by measurement above, and by reading — the accept-loop refactor's serial path is
statement-for-statement identical, and the other seven touch only docs, the workflow, daemon stdin
parsing, or rendered strings, none of which can reach claim convergence.

**It is LOAD-INVERTED, which is why it looked new.** A busy box spreads the claim and the release
across seconds and never reaches the tie-break; a quiet box completes both inside one second and does.
So it passed a gate run that spent 32 of 45 minutes compiling, and failed one that ran on a quiet box.
That is the opposite of the usual reading, and it is a reminder that "it only fails when the box is
loaded" is a hypothesis, not a category.

**Two things were tried and are recorded so they are not re-proposed.**

- *Use the log's DAG order instead of the hash tie-break.* Wrong, and `log/dag.rs` says why: across
  authors entries are **concurrent by design** — the ADR-008 entry schema has no cross-author parent
  field, so no happens-before edge exists between two authors' entries. The information needed to
  order them causally is not in the data. Closing this means finer timestamps or an ADR-008
  amendment; ADR-020 §5 calls that M19.9.
- *Sleep past the one-second boundary in the proof.* Tried, and **reverted**. It stopped site 3
  firing and site 4 started instead — it relocated the race rather than removing it, and 8 further
  reps then passed, which is worse: a gate made green by moving a race reads as evidence. That is the
  failure mode §"gates can assert the bug" exists to forbid, arrived at from the other direction.

**What this costs a person, and it belongs in the release notes rather than only here.** Two agents
claiming the same work item **within one second** can both be wrong about who holds it. Agents are
fast; two sessions reaching for the same item milliseconds apart is the ordinary case for the feature
ADR-020 exists to build, not a pathological one. The work board is usable and that limitation is real.

**CLOSED 2026-09-24, and closed the way a gap entry is supposed to close: by fixing the cause, not
by re-reading the red.** M19.9's remaining piece landed — `Content` and the claim record carry
`created_millis`, and `claim::resolve` sorts on it — so the tie-break moved from the common case to
the rare one it was always meant to be. Two agents now have to collide inside the *same millisecond*
to reach it.

| tree | result |
|---|---|
| before, `main` and v0.2.5's commit | 1 failure in 3 each, quiet box |
| after, millisecond ordering | **6 of 6**, loads 4-45 |

`work_board_proof` is back in the blocking set of `release.yml` and its warning copy is deleted,
because a proof that can pass for a reason belongs in the gate. Note which direction the load
evidence runs: a **quiet** box is the harder condition for this race, because it is what packs a
claim and the release that follows it into one second — so 6 of 6 spanning loads 4 through 45
includes the conditions that produced the failures, and is not the usual "it passed because the box
was busy".

**What this entry is retained for.** The diagnosis above was right and cost two releases anyway,
because the exclusion comment was allowed to stand as an explanation. The rule this reinforces is
already written in §"an accepted gap can hide a defect": a gap entry names its own exit condition,
and the moment the remedy lands somebody must re-run the red rather than re-read the note. The exit
condition here was one sentence — "removing this name must fail until M19.9 lands" — and it is what
made the close mechanical.

## Two proofs are excluded from the release gate, by name (2026-09-23)

**Status: open defects, not accepted gaps.** Both are excluded from `release.yml`'s `--ignored` step
so a release can be built at all, and both still run in the same job as warnings so a change in their
rate is visible rather than buried.

| proof | measured |
|---|---|
| `cross_process_join_proof::two_agents_on_separate_processes_join_through_an_anchor_and_talk` | 4 ok of 6 locally; failed the v0.2.2 release gate |
| `relayed_path_is_retried::a_relayed_pair_finds_a_direct_path_once_one_becomes_possible` | 5 of 5 at v0.2.1, 4 of 5 on main (that one a build error); failed the v0.2.2 rerun |

**Why excluding them is the right call and what it costs.** The alternative was re-running the
release until luck let it through, which is the thing this ADR exists to forbid: a green that came
from a retry is not evidence. Naming them, with their rates, keeps the claim honest — **a release
built this way has not been shown to carry a log entry between two processes**, and the release notes
must say exactly that.

**What is known about the first, which is the real defect.** The failure is bimodal: a passing run
completes in 26-27s, a failing one burns past the proof's 60s budget. That is not latency, it is an
entry that never arrives — so shortening `SYNC_INTERVAL_SECS` or pushing more eagerly cannot fix it,
and an attempt to do both was measured making it *worse* (3 of 8). Two leads remain: a peer only gets
a `SyncSchedule` when `NetEvent::Connected` is handled for it, so no `Connected` means no sync ever;
and the proof's own `Proc` helper pipes the daemons' stderr and never reads it, so a daemon that
writes enough to fill that pipe blocks on `write` — a hang, not a failure, and bimodal in exactly this
shape. `support/voxproc.rs` drains stderr for that reason and cites §6 of this ADR; this helper does
not. Whichever it is, the fix belongs in the product or the helper, not in the gate.

**What must happen before either is removed from the exclusion list.** A run that says why it failed.
Neither currently does: the daemon has no event reader, so every `NodeEvent` it produces goes nowhere,
and the one configuration where a person cannot watch a foreground verb is the one with no reporting
at all.

## A red on a gate's *precondition* is still a product defect (2026-09-23)

`a_join_is_not_hostage_to_one_member` blocked **v0.2.2, v0.2.3 and v0.2.4** from publishing — three
tags, three CI runs of roughly forty minutes each, all dying on the same line. That line is not the
gate's claim. It is the gate checking, before it measures anything, that the anchor came to know both
members of the room, and saying "this gate cannot measure a fallback" when it had not.

Everything about that phrasing invited the wrong response. It reads like the gate apologising for
itself, so the available moves looked like raising the timeout or adding it to the exclusion list
above — and both would have shipped the defect. What it was actually reporting: a newcomer's member
bundle never reached the anchor's board, so a room stopped being joinable by anyone else the moment
its creator went offline. Measured **1 of 2 members in 2 runs of 3**.

Three rules come out of it.

**A precondition must accuse the product, or it will be read as the gate's own weakness.** The gate
now opens that panic with "PRODUCT DEFECT, not a flaky gate", states what the board knew, and says
outright not to raise the timeout or exclude it. A red nobody can attribute is as bad as a green that
asserts the bug — the same failure this ADR was written about, one level up.

**An intermittent red is a lost event until proven otherwise.** The instinct is latency: measure the
distribution, find it long, shorten an interval. It was not latency. The joiner's own put is refused
by design and the one path that works fired before the record existed, so no duration existed to
measure and no timeout would ever have been long enough. "Bimodal" is the tell — a passing run in
seconds and a failing run that burns the whole budget is an event that never arrived, not a slow one.

**The reason was being produced all along and had nowhere to go.** Every board put was
`let _ = client.put(..).await`, and `vox daemon` — the always-on host — had no event reporter at all,
so its stderr measured **0 bytes** across a full run. Wiring both took under an hour and the anchor
then named the cause in one run: `rejected: author is not a channel member`. Three releases were lost
to a missing `eprintln!`, which is the cheapest possible lesson and was not learned cheaply. Before
theorising about an intermittent failure, check whether the component that knows the answer is able to
say anything at all.

**And the box was lying, because of us.** Both sessions working this were reasoning against a load
average of 42 caused by **324 orphaned `vox` processes**, the oldest alive 2h46m, leaked by harnesses
that cleaned up with `pkill -f "$datadir"` — a pattern that matches nothing, because `vox node`'s argv
carries no path and `VOX_DATA_DIR` is an environment variable `pgrep -f` cannot see. That is not an
excuse for the red (it was deterministic once instrumented, and §"gates flake under load" still
stands: never explain a red with the environment). It is a rule about measurement: record `$!`, kill by
PID, and assert zero strays at the end of a run. A *functional* pass under high load is stronger
evidence than a clean one; a *timing* number under load is worth nothing.

## An observation about a parent process is not an observation about the work (2026-09-23)

A method failure, recorded because it cost time twice in one day and both times the honest reading
was narrower than the inference drawn from it.

Thirteen `sccache rustc` processes sat at 0.0% CPU in state `S` with `cargo` also at 0.0%, and that
was read as a deadlocked cache server. It is the normal shape: `sccache rustc` forks the real
compiler and waits on it, and the `ps` output being read had already printed the busy child on the
next line. The shared server was restarted on that reading — cold-starting a 10 GiB cache mid-build —
and three compiler processes were killed by hand, any of which could have belonged to another
project. The machine was simply loaded, by other things: `qemu` at 159%, `opencode` at 48%, Teams at
41%, and exactly **two** vox processes.

Two rules, and the second corrects the first attempt at the first:

- **Check the process tree, not the process.** `ps` on a wrapper reports idle every single time.
- **`%CPU` cannot answer "is this working now" on macOS**: it is a ratio of CPU time to elapsed time,
  a lifetime average. It reads low for a process that is busy after a long wait, and high for one
  that worked hard and then blocked. The column that answers the question is `state` — `R` against
  `S` — or repeated instantaneous samples.

And: **never restart or kill a shared service to test a theory.** The theory here was falsifiable with
one more line of the `ps` output already on screen.

This is the same error the product defects in this ADR are made of. `Fault::Unreachable` meant
"nobody answered", not "the address is wrong". 0% on a wrapper means "this process is waiting", not
"nothing is happening". A red that is intermittent means "an event was lost", not "a timeout is too
short". Each time the observation was real and the inference did not follow — which is why §"gates
flake under parallel load" forbids explaining a red with the environment even when the environment is
genuinely bad. It was genuinely bad today, and it still was not the cause.

## The admission window: one cycle, and moving the join off the actor widened it (2026-09-23)

**FIXED 2026-09-23, and the window is closed rather than narrowed.** `run_responder` takes an
`admit_before_accepting` callback, awaited after the exchange succeeds and **before the `Accepted`
frame goes out**. The node turns it into `NetEvent::JoinAdmit` with a `oneshot` and waits for the
actor to answer — on the slot's task, so the actor is still never the thing waiting, which is the
property the slot exists for. The joiner is therefore an admitted author before it is ever told it is
in, which is the ordering the inline version got for free. `JoinAdmit` is deliberately cheap and local
(admit, answer, done); everything touching the network stays on `JoinAnswered`, after acceptance, so a
joiner never waits on this node's round trips to somebody else. A dropped `oneshot` resolves the wait,
so a shutting-down actor cannot strand a joiner mid-exchange.

Measured on the harness that discriminates, written by the other session (five reps each):

| tree | third person gets in |
|---|---|
| `main` | 6 of 10 |
| the join-slots branch, before this | **0 of 10** |
| with the admission window closed | **5 of 5** (12s, 12s, 14s, 15s, 12s) |

Better than `main`, not merely recovered — because closing the window also removes the narrow version
of the same cycle that gave `main` its 6-of-10 and the hostage gate its 3-of-5.

**The record of the regression is kept below rather than deleted, because the mechanism is the lesson.**

Answering a join was moved into a slot so a stranger could not hold the node (ADR-016 §"Answering a
join runs off the actor"). That change **defers the responder's `admit_author` by one event hop**: on
the previous code the responder admitted the joiner in the *same actor turn* the exchange ended, before
the joiner's `join` call had returned. With the exchange in a slot it completes, posts
`NetEvent::JoinAnswered`, and the admission happens when the actor reaches that event.

In that window the newcomer has already returned from its join and published its records to the
responder's board, where they are refused `author is not a channel member`. Nothing retries. So the
responder's oracle never lists the newcomer, no record is ever admitted, the `BoardGrew` hook never
fires because it fires *on admission*, the anchor's board stays at one member, and the next person to
join the room is handed the one member that is offline and never tries the one that is up.

Measured, real binaries, one host plus two joiners, the creator killed between them:

| tree | third person gets in |
|---|---|
| `main` | 6 of 10 |
| the join-slots branch | **0 of 10** |
| bisected: the join-slots commit alone, reorder absent | **0 of 5** |

The failures are five identical ~11s, and that constancy is the tell: **a structural window does not
vary.** The same reading explains main's 6-of-10 and the 3-of-5 on
`a_join_is_not_hostage_to_one_member` before this work — there the window is narrow but real, so the
cycle is possible and merely rare. It is **one cycle with two widths**, not two defects, which also
retires the idea that the board-population failure and the join failure were independent.

**Why a retry is the wrong fix.** Retrying the newcomer's publish, or polling until the responder
catches up, makes the symptom rarer and leaves the cycle in place — which produces exactly the
unexplainable 4-of-5 this ADR exists to forbid. The window has to close: **the joiner must be admitted
before its join returns**, which means the admission has to be part of the exchange completing rather
than an event the actor reaches afterwards. That is a design question about how a slot hands work back
to the actor, and it has to keep the property the slot was introduced for — no network wait on the
actor — while restoring the ordering the inline version got for free.

Both acceptance tests now exist and a change must satisfy both: the two-joiner reproduction above
(which discriminates at 5-of-5) and `a_join_is_not_hostage_to_one_member`.

**Process note, since it is the same lesson as the rest of this ADR.** Three mechanisms were proposed
for the `:490` failure and measurement killed each one — the publish ordering, the candidate list, and
trust gating the connection. Two of them were coherent enough to have been written up as the cause.
The localisation of *this* regression was also proposed wrongly first (the two-line publish reorder)
and settled only by bisecting with the suspect change verifiably absent from the arm. A coherent
mechanism is a hypothesis, and the only thing that ever separated them was a measurement.

## Root cause of `service_rehearsal_proof:490`: a host serves one joiner, then no one for 30s (2026-09-23)

> **CLOSED 2026-09-24 (v0.2.8)** — the accept loop no longer serialises handshakes; see ADR-017
> "Open proof gap" for the change and its measurement. `service_rehearsal_proof` is back in the
> blocking `--ignored` step of `release.yml` (3/3 locally), and `order4.sh`'s second joiner is in
> 5/5 where pristine `main` locked it out 5/5.

`:490` — "the stranger must still be able to JOIN" — is **not** a flaky proof and **not** about the
stranger. It reproduces deterministically with two joiners and no trust involved at all:

```text
J1 rc=0 in  2s     (first joiner, in immediately)
J2 rc=1 in 21s     (second joiner, locked out)
J2 dialed 127.0.0.1:50116 — the host's real, still-bound, listening port
host stdout: "vox: <J1> joined"   and nothing whatsoever about J2
```

Three controls establish the shape:

| test | result |
|---|---|
| a **lone** joiner 35s after the host starts | in, 2s — so the host does not stop accepting with age |
| J2 immediately after J1 | locked out |
| J2 **40s** after J1 | in — so it recovers, it is not permanently broken |

The recovery at 40s names the cause: **`spawn_accept_loop` awaits `finish_incoming` inline**, so the
accept path handles one connection at a time and is occupied for up to `HANDSHAKE_TIMEOUT` (30s) by
a handshake that does not complete. A joiner's `vox connect` exits as soon as it has joined, leaving
the host mid-handshake on something, and for the next 30 seconds the host answers nobody. The socket
stays bound, which is why the symptom is a **timeout** rather than a refusal, and why it surfaces
three nodes away as `Fault::Unreachable` on a peer that is up.

**This is the same defect class as the join exchange running on the actor, one layer below it.** The
decider's requirement was that nobody attempting to join can render a node inoperable; answering a
join now runs in a slot, and the *accept* of the connection that carries it still does not. Any peer,
malicious or merely abrupt, costs a node 30 seconds of deafness.

**It is also the ADR-017 "Open proof gap", now with a deterministic reproduction.** That gap records
that spawning phase two — quinn's own documented shape, which is the obvious fix — was measured
*worse*: serialised 40-52s consistently green on `m15_two_clients_behind_symmetric_nats`, split 68s,
140s, and a timeout at 247s, with the cause "a cross-connection interaction in circuit establishment
that is still unidentified". So the fix is known, was tried, regressed two NAT gates, and was
reverted for a reason nobody has explained yet.

What is new here is that the gap has a **cheap, deterministic, two-process reproduction of its cost**
rather than only a flaky proof: `scratchpad/order4.sh` in that session, or any host plus two
sequential `vox connect`s. ADR-017 says those two NAT gates are the acceptance test for splitting the
handshake; this is the acceptance test for *not* splitting it, and the two must now be satisfied
together. That is what makes it tractable where it was not before.

**Not fixed in v0.2.5.** It is pre-existing — reproduced on `0590cdc` (v0.2.4's commit) 5 times of 5,
and present in CI history on v0.2.3's runs, before any of this session's work existed.

## Open defect: a node joining a room answers nobody for 30 seconds (2026-09-23)

Found by typing `vox connect` and watching, on a room whose members cannot be reached:

```text
vox: busy 30535ms — joining a room — nobody could be answered
vox: cannot join: ...
```

Three runs, 30.5s each — a bound, not a variance, and consistent with `HANDSHAKE_TIMEOUT` being
awaited inline. `busy … nobody could be answered` is `NodeEvent::Stalled`, and `joining a room` is
`command_name(NodeCommand::JoinChannel)`, so this is not the network being slow: it is **the joiner's
own actor held for the whole half minute**, during which that node answers no sync, no message and no
inbound join.

It is the initiator half of the defect this release fixed on the responder half. Answering a join now
runs in a slot (ADR-016 §"Answering a join runs off the actor"); *making* one still runs on the actor.
The fix is the same shape — decide on the actor, wait in a slot, outcome as an event — and is
deliberately **not** in v0.2.5: it is an unproved actor change, and this release already carries
measured evidence for what it does change. Bolting it on would trade that for a guess.

Two things to fix together, since they are one experience:

1. The walk holds the actor. Nothing else on that node runs for up to 30s per unreachable member tried.
2. The walk says nothing while it waits. `forward` prints a verdict per rung (ADR-013); the join walk
   has exactly the same information — which member it tried and what that member said — and discards
   it, so a person sees a blank terminal for thirty seconds and is then told no.

Recorded here rather than left to be rediscovered: the `Stalled` line above exists only because this
node was made to say when it cannot answer, which is the same instrumentation that found the
board-growth defect. Before that, this was thirty silent seconds and nothing in the product could have
told anyone why.

## Publish only what CI proved (2026-09-26)

**Decision.** The gates run **once**, in CI, on the commit that is published. `release.yml` runs no
proof: its first job, `ci-passed`, waits for CI's `push` run on `main` for exactly the tagged SHA and
passes only if that whole run succeeded. The builds depend on it. A tag on a commit CI never ran on
`main` is refused within minutes, not built.

**Why.** Until v0.2.9 `release.yml` re-ran the entire suite that CI had just run on the same commit.
That proved one tree twice, cost roughly 60 minutes per release, and the duplicate was the copy that
hit its time budget on v0.2.9's second tag: cancelled at 60 minutes with 141 results green and nothing
red. §6's rule is unchanged: nothing is published from a tree the gates have not passed on. The tree
CI proved and the tree published are the same SHA.

**What this makes stricter.** CI runs on ubuntu **and** macOS. The old release gate ran on ubuntu
only, so a macOS-only red could not block a release; now it does. Both are shipped platforms.

**How the suite is laid out in CI.** `build-test` (both OSes) runs fmt, clippy, the debug suite,
rustdoc and the release `--ignored` suite **without** the PRD-001 transport gates, which run in
parallel in `transport-gates` (`r40_`, `r41_`, `r42_`; ~20 minutes, the relay gate alone 11-22).
Both are blocking. The by-name exclusion recorded in "Two proofs are excluded from the release gate,
by name" now lives in `ci.yml`: `cross_process_join_proof` runs in `flaky-watch`, which reports and
can never fail CI. Every `cargo test` runs `--no-fail-fast`, so one red cannot hide the rest.

**Re-running.** If CI on the tagged commit fails and a re-run of that CI run passes, re-run the
release workflow (its `ci-passed` job reads the run's latest conclusion). Nothing is re-tagged.

## Links

**Depends on**: ADR-007 (the golden evaluator suite this retains), ADR-010 (the Argon2 cost this
measures), ADR-012 (UPnP's pending real-hardware validation), ADR-017 (the flow whose rehearsal
prompted this).
- Depended on by: every later ADR's gate wording.
- Modelled on: `repo-to-cve` ADR-018, "Quality Bar, Testing Strategy, and Evaluation Harness".

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a
  feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no
  false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in
  front of a client.
