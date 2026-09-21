# ADR-018: Quality Bar — the Product-Proof Harness is the Test Authority

**Status**: accepted (2026-09-21) — the policy is in force from this change; the harness lands with it
and grows per capability
**Date**: 2026-09-21
**Updated**: 2026-09-21 — M18.2a: `update_proof` and `install_sh_proof` landed with the distribution
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
point of running (for example `VOX_PROOF_ALLOW_UNPROVEN=fish`) and SHOULD be recorded here. A failing
or blocked obligation MUST be recorded as failing or blocked, never as waived-green.

**Accepted gaps, as of 2026-09-21:**

| Gap | Accepted because | What would close it |
|---|---|---|
| `fish` in `shell_setup_proof` | `fish` is not installed on the development machine and is not in CI's default image. `zsh` and `bash` are proved against real shells, including the `compinit`-already-ran case. | installing `fish` on the runner; the proof then covers it with no code change |
| `journey.update_replaces_an_older_install` in `update_proof` | there is no earlier release to update *from*. The version the binary reports is compiled in, so an older `vox` cannot be fabricated locally. | publishing a second release. The proof already asks GitHub for the newest release other than the current one, fetches it, and drives *its* `vox update`; it starts measuring at `v0.1.1` with no code change |
| `verify.digest_mismatch_is_refused` in `update_proof` | reaching the updater's digest check needs a release *newer* than the running binary whose record does not describe it, so it is gated behind the same missing earlier release. The equivalent refusals in `install.sh` **are** proved today, against a loopback release server. | the same second release. The `proof-<triple>.json` record ADR-015 requires is published from `v0.1.0` onwards, so this too starts measuring at `v0.1.1` |

The gates therefore run as:

```
VOX_PROOF_ALLOW_UNPROVEN=fish,journey.update_replaces_an_older_install,verify.digest_mismatch_is_refused \
  cargo test --workspace
```

Removing an entry MUST make the proof fail until that gap is closed — that is the point of it. The
value is set once in `.github/workflows/ci.yml` and `.github/workflows/release.yml`, so the accepted
gaps are visible in the gate itself and not only here.

An allow-list entry matches either a whole claim id or its first segment, so a gap MAY be accepted
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
| `atrest/sek.rs::production_timing_spike` | the production Argon2id profile actually costs what ADR-010 requires | a measured cost, not an assertion; nothing outside the process can observe it |

### 6. The six gates remain

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
