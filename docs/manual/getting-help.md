# Get help safely

Applies to: all versions. Diagnostic commands must still match your installed version.

A useful report says what happened, what should have happened, and the last step that worked.
It does not need your private conversation or a copy of your identity.

## Before opening a report

Find the matching entry in [Troubleshooting by symptom](troubleshooting.md). Keep the original failure text
and the result of each check. Do not make several trust, network and identity changes at
once: that removes the evidence that distinguishes causes.

Check the executable path and version on **each relevant peer**. For agents, include the
harness name/version and whether the symptom is ordinary next-turn delivery or an urgent
wake. For a website-only problem, include the page URL and the source revision shown there.

## Collect a minimal report

Use this outline in the [Vox issue tracker](https://github.com/robertelee78/vox/issues), after
checking for an existing report:

```text
Vox version on each affected node:
Operating systems and CPU architectures:
Command or UI action (secrets and private identifiers redacted):
Expected result:
Actual result, exact error, and exit status:
Last step that worked:
Checks already performed and their results:
Whether peers are on the same machine, same LAN, or separate networks:
Whether an anchor was actually used:
Reproduction with harmless data, if available:
```

For an agent issue, add the harness version, settings scope, hook event and whether the
receiving session was actually running. Say whether you observed the message in that
session; do not replace that observation with “the plugin installed successfully”.

If using a source build, include its commit and note that it is not a published release.
Do not infer a remote version from a website example or local Cargo manifest.

## Review before sharing

Never post:

- Identity or room passphrases, tokens, private keys, vaults, stores or entire state directories.
- A room link together with the room's passphrase.
- Unreviewed `env` output, full configuration files, full agent transcripts or full logs.
- Private message bodies, attachments or another participant's details without permission.

Review even a supposedly harmless status report. Fingerprints identify nodes; room IDs,
aliases, IP addresses, hostname paths, session IDs and timestamps can reveal associations.
File hashes can identify a known document. Mask sensitive values consistently, for example
`PEER_A` everywhere, so the sequence remains understandable.

Keep exact error words, field names and the relation between the affected nodes. Replace
only the sensitive values; paraphrasing “a member refused” as “network failed” destroys the
distinction needed to help.

## Use a harmless reproduction

If a maintainer asks for a reproduction, create fresh disposable identities and room state,
with both `VOX_DATA_DIR` and `VOX_CONFIG_DIR` set to dedicated temporary roots. Never point
a diagnostic experiment at valuable family or agent state. Use a small made-up message/file.

State what the reproduction does and does not cover. Two local nodes prove a local workflow,
not a cross-network NAT path. Source inspection is not an executed test. A test harness that
never reached its precondition is not evidence of a product failure.

## If it may be a security problem

Do not publish secrets or a working attack transcript to demonstrate severity. Describe the
affected version, component and impact without sensitive details, and arrange an appropriate
private way of reporting with the maintainer before supplying more. This manual does not
promise a monitored private address or response deadline that the project has not published.

If the problem is only documentation, identify the chapter and sentence, your installed
version, and the command/output that contradicts it. The canonical text lives in Vox;
website styling problems belong to the website repository.
