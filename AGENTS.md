# Rules for every agent working on Vox

These are the decider's standing rules. Follow them without being reminded. Quoted words are the
decider's own. Each rule names the ADR section that holds the full record.

## Tests

- **A test exists only to prove a feature works for a user.** It drives the shipped `vox` binary
  the way a person would and asserts what that person sees or gets. "I am religiously opposed to
  unit tests/gates in principle because they're worthless." (ADR-018, "Only real use of the product
  is a test")
- **No unit tests and no in-process library tests.** No `#[test]` in `src/`, no in-process `Node`,
  no assertion on an internal value or a proxy for what a person sees. Why: a red from real use has
  one meaning, and any other red has three. (ADR-018, same section)
- **A gate that grows CI without proving a feature works for a user is invalid.** "gates that
  increase CI without proving a product/feature actually works for a user, invalid"; "yet we still
  build bullshit tests". Do not add one. (ADR-018, "What may block a release, what is optional,
  what is deleted (2026-10-01)")
- **Every red names product or test.** "If I cannot tell the difference between a broken product
  and a broken test, it's not a valid test." Each failure path says whether the product failed a
  person or the apparatus failed to measure. (ADR-018, 2026-10-01 section; §8b)
- **Only valid proofs block; everything else is optional or deleted.** "Valid proofs block; rest
  optional." (ADR-018, 2026-10-01 section)
  - "spike tests are valid": run them and report the result; never commit them to the gate.
  - "optional tests are valid": opt-in, never blocking, and loud when not run. A skipped optional
    test never reads as a pass. (ADR-018 §3)
- **No report-only, informational or warning checks.** "you know how I feel about fake tests." A
  check either blocks as a valid proof, runs as an opt-in optional test, or is deleted. (ADR-018,
  2026-10-01 section)
- **Extend an existing user-journey proof rather than adding a file.** Why: one journey shows the
  handoffs between commands, where the defects live. (ADR-018 §1)
- **A fix deletes the tests it makes redundant.** Why: a test that proves nothing new only adds CI
  time and another way to be red. (ADR-018, 2026-10-01 section)
- **Every proof has a mutant that turns it red on its own assertion.** Break the product, run the
  proof, and see it fail on the line that makes the claim. A CANNOT MEASURE is not a red and does
  not count as the mutant's result. Why: a green gate is not evidence, and a gate can assert the
  bug. (ADR-018 §7)

## Anchors

An anchor bridges hosts that cannot otherwise find each other. Nothing else needs one. This has
been the design since the first line of code (ADR-012).

- "anchors effectively bridge hosts that can't otherwise find each other"
- "for all other use cases, direct is fine, sans anchor"
- "an anchor is only required for the initial Rendezvous for two hosts that are both behind NAT --
  it shouldn't strictly always be required to join/create a room"

Never make an anchor a precondition for creating or joining a room, and never call an anchor
unreachable when it was reached. When the anchor is missing, say truthfully what that costs.
(ADR-012, "The anchor principle, restated (2026-10-01)")

## Releases

- **Every known defect is fixed in the current release.** Never defer one to "next release". Why: the
  decider ruled it; the one exception, shipping a known break so a feature can be tested, is the
  decider's call alone. (The decider, 2026-09-26; the v0.2.10 release plan)

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
  deny-list.
