# Maintaining the Vox user manual

The canonical manual is `docs/manual/`. ADR-027 is the content/publication contract. These
instructions and `docs/manual-evidence.md` are maintainer documents, deliberately outside
the public navigation manifest. The website skins canonical text; never fix manual prose
only in the website repository.

## Update the behavior and explanation together

When changing a covered command, argument, error, state or client integration, inspect the
matching task and troubleshooting entry. Update both in the same work item, or record why
the current explanation remains accurate. Inspect the actual parser and error path; an
ADR's accepted decision is not proof that its implementation has shipped.

Keep released and development guidance separate. Review `appliesTo`, visible applicability,
examples, diagnostics and evidence references when promoting a release. Never mechanically
replace every version string and treat that as review. The installation transport can
select a later binary; the manual must tell readers which commands it actually describes.

## Chapter contract

`manifest.json` contains `schemaVersion: 1` and a nonempty ordered `pages` array. Each entry has:

```json
{
  "slug": "first-room",
  "path": "first-room.md",
  "title": "Your first shared room",
  "description": "Create two identities, exchange trust, and verify a message in both directions.",
  "appliesTo": "v0.2.10"
}
```

Slugs and paths are unique. Paths are flat Markdown filenames. `index` is first and maps to
the manual root; other slugs map to their named route. `appliesTo` is `all`, `development`,
or an exact `vMAJOR.MINOR.PATCH`. Each chapter has one H1 exactly matching its manifest title
and a visible applicability statement. Description is reader-facing navigation text, not
an internal work-item note.

Use ordinary Markdown paragraphs, headings, lists, tables, block quotes, fenced code and
links. Do not add MDX, raw HTML, images, scripts, embeds or imports without changing the
approved rendering/asset contract. Keep tables narrow and explanations usable as linear
text. Do not hide symptoms in collapsed disclosures.

Use flat relative links such as `troubleshooting.md#the-room-is-closed` between public
chapters. Use HTTPS source links to exact implementation commits for behavioral evidence.
Keep slugs and heading fragments stable; moving or renaming a published target requires
compatible anchors/routes or a coordinated explicit redirect. Do not link to an unpublished
local file as though the skin can automatically invent a route for it.

## Task template

A task must tell the reader:

1. Which version, actor, machine/profile/node and prerequisites apply.
2. What the action changes, including access and destructive consequences.
3. The commands or UI actions in order, with actual input sources and placeholders explained.
4. What output/observation confirms success on the relevant side of the interaction.
5. Where to go when the observed result differs.

Use `robertGPT` for the example local alias. Keep development node names lower-case where
the implementation case-folds them. Do not equate an alias with an SSH login, room ID,
sender-chosen username or authenticated human identity.

Avoid secret literals in shell history and examples. Prefer terminal prompts or explicit
supported passphrase input. Do not suggest profile deletion, lock-file deletion, automatic
trust, verification bypasses or broad recursive cleanup as recovery. Explain scope before
trust removal, room departure/ending, service withdrawal or data deletion.

## Symptom template

Use a dedicated descriptive heading and expanded text:

```text
Exact symptom and applicable version
Meaning: what was established, and what was not
Check: smallest safe observations before changing state
Fix: likely causes and the corresponding scoped actions
Verify: observation that establishes recovery
If it persists: the minimal evidence to report, with privacy warnings
```

Do not turn plausible causes into facts. A failed join does not always mean wrong passphrase;
no ping reply does not prove offline; a missing body is not generic missing trust; a hook's
zero exit does not prove delivery. Preserve the product's distinctions between these cases.

## Evidence and on-demand verification

Update `docs/manual-evidence.md` with exact source revisions, paths and claim boundaries.
Test a practical walkthrough with the matching real binary in disposable roots, setting
both `VOX_DATA_DIR` and `VOX_CONFIG_DIR` for every process. Never run against a real profile,
and never use sudo. Use harmless content and retain useful evidence privately until reviewed.

An ordinary first-room verification must show receipt in both directions. A client
integration verification must observe the message in the real target harness; generating
configuration or launching a hook does not meet that claim. State when a path was only
source-reviewed, not executed. A same-host reproduction is not a NAT proof.

Classify failed checks as a product observation or an apparatus/precondition failure. Run
focused checks once; repeat on concrete smoke, not to accumulate green counts. Do not add a
unit test or generic Vox CI gate just to validate documentation metadata. Manual rendering
and link checks belong to the website's existing build/acceptance workflow.

## Publication

Commit and push canonical manual changes to Vox's public default branch through the managed
work item. A website build resolves that branch once, then reads every manifest chapter at
the same commit. It emits provenance alongside the skinned static HTML. There is no manually
maintained manual SHA in the website and no checked-in duplicate chapter body.

An upstream merge does not by itself deploy the website. Trigger the authorized website
build/publication workflow, review its exact artifact, keep the previous deployment, and
verify public bytes. Fetch, schema, navigation or review failure must leave the existing
public site untouched. Do not publish a new Vox executable release as a side effect of a
documentation update.

GitHub issues/Projects own attempts, acceptance and delivery. An ADR or evidence file should
not call the manual published until the public source and website boundaries are verified.
