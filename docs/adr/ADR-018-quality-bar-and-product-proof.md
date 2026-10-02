# ADR-018: Quality Bar — the Product-Proof Harness is the Test Authority

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted (2026-09-21), in force. Each requirement below is built on integrate/v0.3.0
unless its own status line says otherwise. Several 2026-10-01 rulings are built on integrate/v0.2.10
(#301) and reach integrate/v0.3.0 with the v0.2.10 sync (#226); they are marked **planned on
v0.3.0**.
**Deciders**: Robert E. Lee <robert@agidreams.us>

## Context

On 2026-09-21 the repository had 877 passing tests, and every gate was green. The first real run of
`vox serve` → `vox connect` → `vox up` → `ssh` failed on three defects. Each one sat in a handoff
between two commands, and none of the 877 tests could see it. Test volume and green intermediate
artifacts did not answer the only question that matters: does `vox` work for the person using it?
This ADR makes real use of the shipped binary the only evidence a release accepts.

## Requirements

### §1 The product-proof harness qualifies a release

1. A milestone or release MUST be qualified by proofs taken through the surface a user or a peer
   actually touches: the shipped `vox` binary, or a real peer speaking the wire protocol. It MUST NOT
   be qualified by running every test target indiscriminately.
2. The proof graph (M18.3) MUST contain: one node per user-facing capability; one named edge
   assertion for every handoff between commands (what one command prints and the next accepts); one
   single-invocation journey through the shipped CLI from a pristine state, with an anchor and
   without one; and a resume case wherever a handoff persists state.
3. Each proof MUST retain its receipts: the exact command, its exit status, its output, and the
   artifacts it produced or consumed.

*Status:* planned (M18.3). Built so far: `service_rehearsal_proof` drives the anchored
serve → connect → up journey through the shipped binary. The node/edge matrix, the receipts and the
anchorless arm are not on integrate/v0.3.0. M18.3's acceptance: each of the three 2026-09-21 defects
MUST be reproduced by the harness when its fix is reverted.

### §2 A test measures the feature, not the implementation

1. A test MUST answer "does this feature work for the party that uses it". A test whose assertion
   can hold while the feature is broken MUST NOT be added. Example: `shell_setup_proof` asks a real
   `zsh` whether a completion is registered (`_comps[vox]`); it does not check the rc file's text.

### §3 Absent evidence is not success

1. A proof whose prover is unavailable (an uninstalled shell, absent hardware, a missing credential)
   MUST report itself as unproven, and MUST fail. It MUST NOT be silently skipped.
2. A gap MAY be accepted deliberately, only through `VOX_PROOF_ALLOW_UNPROVEN`. That value MUST be set
   once, in `.github/workflows/ci.yml`. `scripts/release-gate.sh` MUST unset it.
3. A whitelist entry MUST match a whole claim id or its first segment, so a gap MAY be accepted
   precisely (`verify.digest_mismatch_is_refused`) rather than by area.
4. A developer machine's list MAY be longer than CI's. It MUST NOT be shorter. CI's list MUST NOT grow
   to match a developer machine.
5. Removing an entry MUST make the proof fail until that gap is closed.
6. A failing or blocked obligation MUST be recorded as failing or blocked, never as waived-green.
7. An accepted gap SHOULD be re-measured when its stated remedy lands, not assumed closed by it. A gap
   whose entry names its own remedy SHOULD be closed, not renewed.
8. A record read by a strict parser MUST carry exactly its schema's fields. `scripts/package-release.sh`
   MUST refuse to package a release record whose key set differs from schema-1's.

*Status:* built. CI's list is `opencode`.

### §4 No unit tests

1. A crate's `src/` MUST NOT contain a `#[test]` or `#[cfg(test)]` item, nor scaffolding that exists
   only to serve one. *Status:* built; none exist on integrate/v0.3.0. (The suites §5 once retained are gone,
   and §5 is retired.)

### §6 A hung proof is a failing proof

1. Every gate and proof process MUST arm the wall-clock watchdog
   (`crates/vox-core/tests/support/watchdog.rs`). The watchdog's bound is outside the async runtime, so
   a spinning task cannot starve it.
2. The watchdog MUST end the process by abort (`SIGABRT`), not by exit.
3. Before it aborts, the watchdog MUST write to file descriptor 2 directly, not through libtest's
   captured output. It MUST name the tests still running and put every thread's stack in the log:
   `/usr/bin/sample` on macOS; on Linux, a `/proc` census of every thread with its state and recent CPU,
   plus `gdb` backtraces where `gdb` can attach.
4. The default budget MUST be 600 s. `VOX_TEST_WATCHDOG_SECS` MUST override it, and `=0` MUST
   disable it.
5. Every CI job MUST carry a `timeout-minutes`.

*Status:* built.

### §7 A green gate is not evidence

1. When a gate fails after a behaviour is removed, whoever fixes it MUST first establish whether the
   gate was asserting that behaviour. If it was, the gate MUST be rewritten, not extended. The removed
   behaviour MUST NOT be restored to make the gate pass. The governing ADR MUST record whether the
   property under test is unchanged or weakened.
2. A reviewer MUST read each gate's comment against its assertion. Where they disagree, the
   assertion MUST be corrected to the property the comment names.
3. Instrumentation added while debugging MUST be removed, and the gate re-run, before a green is
   believed.

### §8 A proof never restates a constant it depends on

1. A test whose number stands in a required relation to a constant in the source (a patience window, a retry
   deadline, a watchdog budget) MUST reference that constant, not repeat its value. The constant MUST
   be exported for that purpose (for example `node::up::HOST_PATIENCE`).

### §8a The six gates

1. Every change MUST pass `fmt`, `clippy -D warnings`, `test`, `rustdoc -D warnings`, and the release
   `--ignored` run.

### §8b Whatever knows why says why

1. A failure MUST carry what the code learned while failing, to the operator of the node that failed.
   It MUST NOT carry anything across a trust boundary (ADR-013's dark-service refusals stay
   indistinguishable to the peer).
2. This applies at least to: a dial's `Fault::Unreachable`, which MUST name each rung and what it said
   (`LadderExhausted`); a join, which MUST name each candidate and why it was rejected (and tell the
   board, `BoardUnreachable`, from every member, `Unreachable`); and any bound that expires, which MUST
   name the bound and what it waited for.
3. A component that can know the cause of a failure MUST be able to report it. `vox daemon` and every
   board put MUST report what they refused, and why.

### §9 Only real use of the product is a test

1. A test MUST drive the shipped `vox` binary the way a person would, and MUST check what that person
   would see or depend on. Every participant in a proof MUST run as the shipped binary. A test MUST NOT
   start a node in-process (`Node::spawn`, `NodeHandle`, `Node::start`), assert an internal value, or
   stand in a proxy for what a person sees.
2. A test-side attacker is apparatus. A test MAY craft forged or malicious input, even with Vox's own
   library code, and send it to a real, running, shipped `vox`. The verdict MUST come from what the
   real binary does.
3. An instrument a proof needs (for example the R41 link emulator) MUST report its own fidelity in the
   proof's output.

*Status:* built. No test on integrate/v0.3.0 starts a node in-process.

### §10 What may block a release, what is optional, what is deleted

1. **Valid proofs block.** A test MAY block a release only if it satisfies §9 and every red it can
   produce names its side, as one of:
   - `PRODUCT:` — what the product did wrong, quoting it;
   - `PRODUCT (staging):` — a product step the proof needed before its claim failed;
   - `CANNOT MEASURE:` — staging the run did not achieve, so the claim was not measured;
   - `APPARATUS:` — the test's own sockets, tools, threads or harness failed.

   An unlabelled red is a proof defect, and a verifier MUST reject it. A test whose red does not name
   its side MUST NOT block.
2. **Optional proofs are fully optional.** Expensive user-facing proofs MUST sit behind the cargo
   feature `optional-proofs` (heavy ones behind `heavy-proofs`, which implies it). An optional proof
   MUST block nothing: not CI and not the release gate. Without the feature, each optional proof MUST
   compile a stand-in (`not_run!`, `crates/vox-tui/tests/support/optional_proof.rs`), listed and ignored
   as `OPTIONAL PROOF NOT RUN`, which prints that when run. It MUST NOT read as a pass. CI MUST compile
   optional proofs without running them, and `docs/release/optional-proofs.md` MUST list them. The
   live-model OpenCode proofs and R40, R41 and R42 are optional proofs.
   *Status:* the feature, the stand-in macro and `heavy-proofs` are built. Planned on v0.3.0 (built on
   v0.2.10, #301): `docs/release/optional-proofs.md`; CI's compile-only step; moving the live-model
   proofs and R40/R41 behind the feature. Until then, integrate/v0.3.0's `ci.yml` still runs R40/R41 in
   the blocking `transport-gates` job, and `scripts/release-gate.sh` still requires the live-model
   proofs.
3. **Live-model proofs run only on request, sandboxed.** A proof that gives a live model a shell MUST
   run only at the decider's request, and only inside a sandbox that keeps the model away from the
   host's private files. It MUST NOT run in CI or the release gate. Without the sandbox feature it MUST
   print `OPTIONAL PROOF NOT RUN`.
   *Status:* `an_agent_wake_is_safe_and_bounded_proof` case 6 is behind `live-model-sandbox`. Planned:
   the same gate for `agent_rehearsal_proof`, `drain_self_filter_proof`, `opencode_plugin_proof` and
   `tracker_rehearsal_proof`, and the sandbox itself.
4. **A spike is valid.** It MUST be run, and its result reported in the post. It MUST NOT be committed
   to the gate. A fix with no user-facing proof MUST rest on review plus such a spike.
5. **Everything else is deleted.** A unit test, an in-process library test, a test of an internal
   value, and a gate that adds CI time without proving a feature works for a user MUST NOT exist in the
   tree. A verifier MUST reject a candidate that adds a harness, mechanism, counter or
   non-user-visible-timing test.
6. There MUST NOT be report-only, informational or warning checks.
   *Status:* planned on v0.3.0. integrate/v0.3.0's `ci.yml` still reports R41's WAN link on macOS
   (`VOX_PERF_REPORT_ONLY=WAN`).
7. A new claim SHOULD extend an existing user-journey proof rather than add a test file. A new test file
   MUST justify itself.
8. A fix MUST delete the tests it makes redundant, in the same change.
9. **Run once.** A proof SHOULD be run once, in the profile CI uses. It MUST be repeated only on smoke
   (a red, a flake someone has seen, a timing near its bound, or a claim that is itself a rate), and
   whoever repeats it MUST say why. Callers' proofs MUST be run only where the diff plausibly reaches
   them. A verifier MUST NOT re-run the fixer's greens. After a clean re-merge, only what the conflict
   touched MUST be re-run. Nobody SHOULD run locally what CI already runs.
10. **One mutant per claim.** Every proof MUST have, for each claim, a mutant: the product broken on
    purpose, under which the proof goes red on the assertion that makes that claim, labelled
    `PRODUCT:`. A `CANNOT MEASURE` is not a red and MUST NOT be counted as the mutant's result. A
    multi-step exploit proof MUST assert that every escalation step succeeded.
11. **Test knobs.** A `VOX_TEST_*` knob MUST exist only under the cargo feature `test-knobs`. A knob MAY
    only lower or shorten staging; it MUST NOT change what the product decides. A shipped build MUST NOT
    enable `test-knobs`, and the packaged release artifact MUST contain no knob. A proof that needs a
    knob MUST build with the feature, and MUST refuse a `vox` without it as `CANNOT MEASURE`.
    *Status:* built (V210-105).
12. **Latency bounds hold under ordinary load.** A latency bound MUST hold on a machine doing ordinary
    work. A red under ordinary load is a product defect. A release gate MUST NOT require an idle
    machine, and a red MUST NOT be explained away by the machine's load.

### §11 Publish only what CI proved

1. The gates MUST run once, in CI, on the commit that is published, on both ubuntu and macOS.
   `release.yml` MUST run no proof. Its first job, `ci-passed`, MUST pass only if CI's `push` run on
   `main` succeeded for exactly the tagged SHA, and every build MUST depend on it.
2. Every `cargo test` in CI MUST run `--no-fail-fast`.
3. A proof MUST NOT be excluded from the gate by name. A proof is blocking, optional (§10.2), or deleted.
4. If CI on the tagged commit fails and a re-run of that run passes, the release workflow MUST be re-run.
   The tag MUST NOT be re-created.

*Status:* built.

### §12 Measurement discipline

1. A proof that kills or cleans up processes MUST record each child's PID, kill by PID, and assert that
   no strays remain at the end of a run. It MUST NOT clean up by pattern (`pkill -f`).
2. A red on a proof's precondition that the product failed MUST be labelled `PRODUCT (staging):` and
   MUST be treated as a product defect, not as the proof's weakness.
3. An intermittent red SHOULD be treated as a lost event until proven otherwise. A red whose failing
   runs all burn the full budget while passing runs finish in seconds is an event that never arrived,
   and no longer timeout will fix it.
4. A green obtained by retrying a red MUST NOT be accepted as evidence.
5. Whoever investigates a red MUST check the process tree, not one process, and MUST read process
   state (`R`/`S`), not lifetime `%CPU`. A shared service MUST NOT be restarted or killed to test a
   theory.

## Consequences

- What gets proved is what an operator does. Handoffs between commands have named obligations.
- Coverage of internal helpers is gone deliberately. A refactor that breaks a helper is caught only if
  it changes what a person sees.
- Proofs are slower per run than unit tests, and some properties (convergence under partition) are
  not testable until a harness for them exists.
- Golden wire-byte vectors for the ADR-008 struct tags remain unmet (`docs/adr/README.md`).

## Known gaps

| Gap | State |
|---|---|
| The proof graph, receipts and anchorless journey of §1 (M18.3) | not built on integrate/v0.3.0 |
| Golden wire-byte vectors for the ADR-008 struct tags | unmet (`docs/adr/README.md`) |
| The live-model sandbox (§10.3) | not built; live-model proofs are stopped until it exists |
| §10.2 and §10.6 on integrate/v0.3.0: R40/R41 block in `transport-gates`, R41's WAN arm is report-only on macOS, and `scripts/release-gate.sh` requires the live-model proofs | built on integrate/v0.2.10 (#301); reaches v0.3.0 with #226 |
| CI still accepts the `opencode` gap (§3) | the live-model proofs need OpenCode and a model account CI lacks |
| The watchdog's Linux stack dump (§6.3) has not been run | open |
| `cross_process_join_proof` saw one fast red (`Unreachable` straight after an invite, 1 in 3 on 005b801) whose cause was never named; it has not recurred (12/12, 15/15) and the next red names its side (#192) | open |
| UPnP port mapping has no real-router validation (ADR-012) | open |
| Claims left unmeasured by the 2026-09-26 test deletion | proved since: `no_consent_without_a_ring_entry_proof`, `revocation_rotates_the_key_proof`, `the_path_mtu_follows_the_socket_buffer_proof`; the rest are tracked by #204 |

## Related ADRs

- ADR-007 (governance verdicts), ADR-010 (the Argon2id cost floor, proved by RP-07), ADR-012 (dial
  ladder diagnostics and UPnP hardware validation), ADR-013 (dark-service refusals), ADR-017 (the flow
  whose rehearsal prompted this ADR).
- Every later ADR's gate wording depends on this one.

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
