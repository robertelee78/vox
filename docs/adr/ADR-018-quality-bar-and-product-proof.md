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
| `journey.update_replaces_an_older_install` in `update_proof` | there is no earlier release to update *from*. The version the binary reports is compiled in, so an older `vox` cannot be fabricated locally. | publishing a second release. The proof already asks GitHub for the newest release other than the current one, fetches it, and drives *its* `vox update`; it starts measuring at `v0.1.1` with no code change |
| `verify.digest_mismatch_is_refused` in `update_proof` | reaching the updater's digest check needs a release *newer* than the running binary whose record does not describe it, so it is gated behind the same missing earlier release. The equivalent refusals in `install.sh` **are** proved today, against a loopback release server. | the same second release. The `proof-<triple>.json` record ADR-015 requires is published from `v0.1.0` onwards, so this too starts measuring at `v0.1.1` |

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
value is set once in `.github/workflows/ci.yml` and `.github/workflows/release.yml`, so the accepted
gaps are visible in the gate itself and not only here.

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
