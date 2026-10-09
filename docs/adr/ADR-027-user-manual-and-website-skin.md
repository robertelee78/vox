# ADR-027: One user manual, automatically skinned by voxlucis.us

**Status**: Accepted — decider authorization 2026-10-04; independent technical review by `manual_practice_research` on 2026-10-04.
**Execution**: [manual work and acceptance](https://github.com/robertelee78/vox/issues/421); [website work and publication](https://github.com/robertelee78/voxlucis.us/issues/2). Acceptance of this decision is not a delivery claim.
**Date**: 2026-10-04
**Deciders**: Robert E. Lee
**Tags**: documentation, user-experience, website, troubleshooting
**Related**: ADR-001, ADR-018, ADR-020, ADR-021, ADR-026

ADR-026 ships in v0.3.0: `integrate/v0.3.0`, the v0.3.0 release candidate, contains `rearch/v030`.

## Context

Vox has architecture records, a README and release-proof instructions, but no coherent user
manual. A reader facing a refused join, an unavailable file or a silent agent should not need
to read the implementation or guess which architecture proposal is already available.

The decider requested deep research, this ADR, source-bound GitHub work, execution, and public
publication. The manual may live in `docs/manual` in Vox. Its website must automatically skin
the canonical Markdown, following the existing hf2q.us pattern, rather than maintain a copied
or manually pinned body of prose. Both repositories' changes must be committed and pushed.

Research found three incompatible command surfaces: released v0.2.10, an older
`integrate/v0.3.0`, and node-based `rearch/v030`. `integrate/v0.3.0` has since merged
`rearch/v030` and is the v0.3.0 release candidate, so v0.3.0 is the node-based surface. A moving documentation source does not mean a
development command works in an installed release. Source code and observed behavior decide
what instructions claim; an accepted but unimplemented ADR does not.

## Decision

### D1 — Author once, in Vox

`docs/manual/` is the canonical user manual. It contains plain Markdown chapters and a small
`manifest.json` defining ordered navigation, stable slugs, descriptions and applicability.
GitHub renders the same Markdown a user can read offline. voxlucis.us owns layout, typography,
navigation and rendering only. No independently edited manual prose lives in the website.

The manifest has schema version 1 and a nonempty `pages` array. Each page declares `slug`,
`path` (a flat `.md` filename), `title`, `description`, and `appliesTo`. Slugs and paths are unique.
`appliesTo` is `all`, `development`, or an exact `vMAJOR.MINOR.PATCH` release, not free-form prose.
The first page is `index`, mapped to `/docs/manual/`; other slugs map to
`/docs/manual/<slug>/`. Each chapter has one H1 matching its manifest title. Ordinary relative
Markdown links keep GitHub useful; the skin maps known manual files to their public routes.
Preserve published slugs and heading fragments; a rename needs a compatibility route/anchor or
an explicit redirect, not a silently broken inbound link.

### D2 — Separate learning, doing, understanding and recovery

The first edition must provide installation, one first-room walkthrough, identity/keyring,
rooms/messages, services, files, agent communication, troubleshooting and safe reporting.
Concepts explain the model; task chapters show prerequisites, who runs each step, its effects,
and the observation that confirms success. Reference points to exact command help and sources.
The example local alias is `robertGPT` (not `rob`). Do not imply case-preserving development node
names where the implementation lowercases them.

Troubleshooting starts with evidence before changes. Each entry names an exact error or visible
symptom, applicability, meaning (including what cannot be inferred), safe checks, cause/fix,
verification, and escalation. Dedicated symptom entries remain expanded and directly linkable.
Do not suggest deleting a profile, clearing locks, trusting everyone or disabling integrity checks.
Explain destructive scope before a command. Never promise that deleting a local copy erases a
recipient's independently retained copy.

### D3 — Tell the truth about versions and evidence

Every page shows applicability. The manual describes the current release, v0.3.0, as it is; it
carries no chapter or passage about earlier releases or how they differed.
The installer follows the established `https://voxlucis.us/install.sh` transport; GitHub remains
the executable source of truth. Updating the manual must not change installer promotion policy.

An evidence map records implementation refs, paths and the behavior each chapter depends on.
Commands are checked against the matching parser/help, and practical walkthroughs against a real
binary in disposable data/config roots. Source inspection is not reported as an execution test.
Do not claim an agent-hook exit 0 proves delivery, a ping timeout proves offline, a refused join
proves a wrong passphrase, or `not received yet` is a generic trust marker. Do not advertise
development-only diagnostics in stable troubleshooting.

### D4 — Auto-skin at build time, resolve a coherent revision

Website builds follow Vox `main`, resolve it once to a full Git commit, and fetch the manifest
and every chapter at that same commit. The site has no maintained manual SHA and no checked-in
chapter copies. An explicit build ref may select a review branch or reproduce an artifact.
The resolved SHA is deployment provenance, not a manually maintained content snapshot.

The loader bounds requests, response bytes, chapter counts and total bytes; checks HTTP status,
content types and UTF-8; validates schema and navigation; and fails on invalid input. Plain
Markdown is data, not code: no MDX, raw HTML, scripts, images or executable imports. Link
rewriting operates on the Markdown AST, never code samples. It rejects unsafe schemes,
ambiguous/root-relative URLs and path escapes. Known chapter links retain valid fragments;
source links use immutable GitHub URLs. Missing local pages/anchors fail publication checks.

The website emits static, accessible HTML with a source link, revision, applicability and digest.
These provenance fields are public; fetch/deployment credentials must never enter HTML, metadata,
build receipts or published evidence. An API token is used only in the request header.
Navigation, previous/next, table of contents and sitemap derive from the same manifest. Reading
and navigation work without JavaScript; copy is an enhancement. Prose reflows at 320 CSS pixels,
wide code/tables scroll within themselves, focus stays visible, and print output remains usable.

### D5 — Publication is explicit and recoverable

An upstream edit is picked up on the next website build without a website prose edit or SHA bump.
This first implementation does not install a recurring production publisher or claim that a
GitHub merge alone changes the live server. Adding such a publisher would require its own
credential, failure-alert and approval design. The existing SSH publication boundary remains.

A failed fetch/build/review must leave the known-good live site untouched. Build from committed
source, verify the exact output, retain the previous deployment, then compare public bytes with
the tested artifact. Do not publish a new Vox binary release as part of this documentation work.

### D6 — Maintenance and ownership

Changes to a covered user-visible command, error, state or client behavior must update the manual
and its evidence in the same work item, or explicitly record why the manual remains correct.
Version applicability is reviewed when a release changes; do not silently relabel development
prose as released. Authoring instructions include the chapter schema, symptom template, link
rules and verification approach. Bug-report guidance requests minimal reviewed output, never
whole state directories, secrets or unreviewed full logs.

## Implementation and acceptance

### M27.1 — Canonical manual

Deliver the manifest, complete first-edition chapters, evidence map and authoring guidance in
Vox, linked from its README. Acceptance: stable and development instructions are visibly distinct;
every manifest chapter exists with the correct heading; tasks and symptom entries satisfy D2/D3;
installation uses the vanity transport. Independent review checks version-sensitive examples.
Delivery boundary: committed manual on Vox's public default branch. No binary release required.

### M27.2 — Practical verification

Verify the first-room instructions and representative failure/recovery paths with the released
binary in isolated roots. Record exact binary version, commands, observed results and limits;
the walkthrough must prove receipt in both directions, not just a successful local post.
Agent-delivery acceptance must observe client-appropriate receipt, not infer it from setup success;
where no live harness session is exercised, disclose that limit rather than claim delivery proof.
inspect documented commands against source/help. Classify a failure as PRODUCT or APPARATUS,
not an unattributed red. These are on-demand documentation acceptance proofs, not a new generic
Vox CI gate. An independent reviewer must identify any unsupported promise before acceptance.
Delivery boundary: public evidence attached to the manual work item.

### M27.3 — Website contract

Implement D4/D5 in voxlucis.us under a related, repository-owned work item. Acceptance: a source-only
chapter edit flows into a rebuild without website prose changes; all chapters share one resolved
source revision; unsupported content and broken navigation are refused; browser checks prove
reading/navigation at narrow width, with keyboard and without JavaScript; exact public files match
the accepted artifact. Existing installer and landing pages must remain working.
Delivery boundary: verified public manual at `https://voxlucis.us/docs/manual/`.

Order: approve the content/rendering contract; implement canonical content and skin independently;
verify both together; publish the canonical source, build from it, then publish the website.
GitHub issues hold attempts, acceptance and delivery; this ADR holds the requirements. Use one
document Project per owning repository and cross-link their contract items.

## Consequences and alternatives

- One authoring location prevents divergent fixes and lets product changes carry their docs.
- Explicit version context costs some repetition but avoids unsafe or impossible instructions.
- Remote content makes builds depend on GitHub; static delivery keeps reading independent of it.
- Strict Markdown limits rich media initially; add an asset contract only when a real chapter
  needs it. It is safer and smaller than remotely executable MDX.
- A whole-manual revision avoids the torn multi-page build possible if each file resolves its
  own last-changing commit.
- A copied website manual, browser-side GitHub fetch, giant generated CLI dump and another docs
  framework were rejected: none improves this existing static site's authoring/reading contract.
- A fixed manual SHA was rejected by the decider. Automatic build-time skinning does not require
  sacrificing immutable evidence for the artifact that was actually reviewed and published.

## Research

See [research record](../research/manual-2026-10-04.md) for the local evidence and external primary sources.
