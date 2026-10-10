# Get help safely

A useful report says what happened, what you expected, and the last step that worked. It never
needs your private messages or a copy of your identity.

## Before you report

Find the matching entry in [Troubleshooting by symptom](troubleshooting.md) and keep the result
of each check. Change one thing at a time: several changes at once remove the evidence that tells
causes apart. Note `vox --version` on each machine involved. For an agent, note the harness and
its version.

## What to include

Open an issue in the [Vox issue tracker](https://github.com/robertelee78/vox/issues), after
checking for an existing one:

```text
Vox version on each machine:
Operating systems and CPU architectures:
Command or app action (secrets and private identifiers removed):
Expected result:
Actual result, exact error, and exit status:
Last step that worked:
Checks already done, and their results:
Whether the machines are the same machine, on one LAN, or on separate networks:
Whether an anchor was used:
A reproduction with harmless data, if you have one:
```

For an agent, add the harness's settings scope and hook event, and whether you saw the message
arrive in the running session. "The plugin installed" is not the same observation.

If you built Vox from source, give the commit.

## What never to post

- Identity or room passphrases, tokens, keys, vaults, stores, or whole data directories.
- A room link together with its passphrase.
- Unreviewed environment output, whole configuration files, agent transcripts or logs.
- Message text, files, or another person's details without their permission.

Fingerprints, room IDs, names, IP addresses, paths, session IDs and timestamps can reveal who
talks to whom. Replace each sensitive value with the same placeholder everywhere, such as
`PEER_A`, so the report still reads. Keep the exact error words: paraphrasing "a member refused"
as "the network failed" loses what tells the causes apart.

## Make a harmless reproduction

Use fresh nodes, with `VOX_DATA_DIR` and `VOX_CONFIG_DIR` both set to new empty directories, and a
small made-up message or file. Never test against nodes that matter. Say what the reproduction
covers: two nodes on one machine do not test a path across networks.

## Report a security problem

Do not publish secrets or a working attack. Describe the affected version, the part of Vox, and
the impact without sensitive details, and ask the maintainer for a private way to send more.

For a mistake in this manual, name the page and sentence, your `vox --version`, and the command or
output that contradicts it.
