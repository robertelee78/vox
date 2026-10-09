# Rules for every agent working on Vox

These are the decider's standing rules. Follow them without being reminded. Quoted words are the
decider's own. Each rule names the ADR section that holds the full record.

## Tests

- **A test exists only to prove a feature works for a user.** It drives the shipped `vox` binary
  the way a person would and asserts what that person sees or gets. "I am religiously opposed to
  unit tests/gates in principle because they're worthless". Otherwise there is no test: the fix
  rests on review plus a spike that is run and reported in the post, not committed. (ADR-018, "Only
  real use of the product is a test")
- **No unit tests and no in-process library tests.** No `#[test]` in `src/`, no in-process `Node`,
  no assertion on an internal value or a proxy for what a person sees. Why: a red from real use has
  one meaning, and any other red has three. (ADR-018, same section)
- **A test-side attacker is apparatus, and allowed.** A test that crafts forged or malicious input
  (even with Vox's own library code) and sends it to a real running shipped `vox` is apparatus.
  What's forbidden is testing internals in-process or asserting on internal values; "the verdict
  must come from what the real binary does". (Decider, 2026-10-01; ADR-018, 2026-10-01 section)
- **A gate that grows CI without proving a feature works for a user is invalid.** "gates that
  increase CI without proving a product/feature actually works for a user, invalid"; "yet we still
  build bullshit tests". Do not add one. A verifier rejects a candidate that adds a harness,
  mechanism, counter or non-user-visible-timing test. (ADR-018, "What may block a release, what is
  optional, what is deleted (2026-10-01)")
- **Every red names product or test.** "If I cannot tell the difference between a broken product
  and a broken test, it's not a valid test." Each red names a PRODUCT verdict (quoting what the
  product did) or an APPARATUS fault (staging not achieved, precondition unmet, watchdog, emulator
  late, harness error). An unattributed red is a proof defect, and the verifier rejects it.
  (ADR-018, 2026-10-01 section; §8b)
- **Only valid proofs block; everything else is optional or deleted.** "Valid proofs block; rest
  optional." (ADR-018, 2026-10-01 section)
  - "spike tests are valid": run them and report the result; never commit them to the gate.
  - "optional tests are valid", and "Fully optional": an optional proof blocks nothing, not CI and
    not the release gate, and is loud when not run: it prints that it did not run, never a silent
    `ok`, and never reads as a pass. "those types of tests are great to have at the ready for
    troubleshooting". One mechanism: the cargo feature `optional-proofs`. Expensive user-facing
    claims are optional proofs; the live-model OpenCode proofs and R40, R41 and R42 are fully
    optional and never block a tag. CI compiles optional proofs without running them, and
    `docs/release/optional-proofs.md` lists each one and how to run it (#301). Without the
    feature, each optional test compiles a stand-in that says `OPTIONAL PROOF NOT RUN`
    (`not_run!` in `crates/vox-tui/tests/support/optional_proof.rs`).
- **Run a proof once; repeat only on smoke.** "it feels wasteful to test the same things
  2398439487398327492847239847234 times"; "test when you find smoke"; "not just for funzies". (ADR-018,
  2026-10-01 section)
  - Run a proof once, in the profile CI uses.
  - Repeat only on smoke (a red, a flake someone has seen, a timing near its bound, a claim that is
    itself a rate), and say why.
  - Run callers' proofs only where the diff plausibly reaches them, in one profile.
  - Verifiers don't re-run the fixer's greens: one mutant per claim, run once, plus probes where
    there is smoke.
  - After a clean re-merge, re-run only what the conflict touched. CI runs the suite on push; a CI
    red is the smoke. Do not duplicate CI locally.
- **No report-only, informational or warning checks.** "you know how I feel about fake tests". A
  check that can't fail is a fake test: it blocks as a valid proof, runs as an optional proof, or is
  deleted. (ADR-018, 2026-10-01 section)
- **Extend before adding.** Extend an existing user-journey proof rather than adding a file; a new
  test file must justify itself. Why: one journey shows the handoffs between commands, where the
  defects live. (ADR-018 §1, 2026-10-01 section)
- **A fix deletes the tests it makes redundant.** (ADR-018, 2026-10-01 section)
- **Every proof has a mutant that turns it red on its own assertion.** A CANNOT MEASURE is not a
  red and does not count as the mutant's result. Why: a green gate is not evidence, and a gate can
  assert the bug. (ADR-018 §7)
- **No test knobs in the shipped binary.** `VOX_TEST_*` knobs are to be compiled out of what
  users install (#300, not merged yet): a proof that needs one is to build `vox` with the cargo
  feature `test-knobs`, and the packaged release artifact is to hold none (the decider, 2026-10-01;
  V210-105).

## Anchors

An anchor bridges hosts that cannot otherwise find each other. Nothing else needs one. This has
been the design since the first line of code (ADR-012).

- "anchors effectively bridge hosts that can't otherwise find each other"
- "for all other use cases, direct is fine, sans anchor"
- "an anchor is only required for the initial Rendezvous for two hosts that are both behind NAT --
  it shouldn't strictly always be required to join/create a room"

Never wait on, fail on, or blame an anchor that wasn't needed. Nothing may wait on, fail on, or
refuse because of an absent anchor when the peer is directly reachable (a link address, a port
mapping, the same LAN): not create, serve, invite, join or connect. Never call an anchor
unreachable when it was reached. When an anchor is missing, say truthfully what that costs.
(ADR-012, N-1–N-8)

## Releases

- **Every known defect is fixed in the current release.** Never defer one to "next release". Why: the
  decider ruled it; the one exception, shipping a known break so a feature can be tested, is the
  decider's call alone. (The decider, 2026-09-26; the v0.2.10 release plan)
- **An upgrade never breaks a person's data.** "we need a way to upgrade folks so we don't break
  their old profiles when we make changes." A change to any on-disk format (the data root's layout,
  the vault, a store encoding, a config file) ships an automatic upgrade from every release since
  v0.4.0, proven on a data root the previous published release wrote
  (`a_data_root_of_the_previous_release_opens_with_nothing_lost`), and raises the data root's format
  (`.daemon/format`). Upgrade code is never deleted while a supported release could have written
  the data. Data from before v0.4.0 is out of scope. (The decider, 2026-10-08; ADR-026 F-3)

## Safety

- **Never run `vox` against a real profile.** Every `vox` you start sets both `VOX_DATA_DIR` and
  `VOX_CONFIG_DIR` to a scratch directory. Why: even a failed unlock writes to the profile's store.
- **Never use `sudo`**, even a `sudo -n` that does not prompt. Shape traffic and do everything else
  in userspace.

## Work tracking

- This repository is managed by the github-work-accountability skill. Run `awa status --json` once
  before editing. Each tracked item's issue carries a `work-accountability:key` block; bind your
  work to that key and keep its issue and Project current.

## Words

- Write whitelist and blacklist, in code, comments, docs and messages. Never allow-list or
  deny-list. This is a standing ruling of the decider's.

## House rule

- Never state planned work as done: write "is to" or "must" until it has landed.
