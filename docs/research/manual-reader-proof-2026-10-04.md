# Independent reader proof: first room and three recovery paths

Recorded 2026-10-05T01:22:33Z (2026-10-04 America/Los_Angeles).
Verifier: `manual_practice_research`, independent of the manual author.

## Verdict and scope

PASS for the first-room journey and the specific recovery paths below. This is an on-demand
manual acceptance exercise, not a new generic CI gate and not a claim that every manual
example was executed. No Vox source changes were made by this verifier.

The exercise used the published macOS arm64 v0.2.10 binary on macOS 27.2 (26B5091g), two
same-host peers on direct IPv4 loopback, and one additional scratch identity for refusal.
It did not measure WAN/NAT traversal, anchors, other platforms, live model/harness delivery,
file transfer, service transport, all command examples, or development-only behavior.
In particular, development `not received yet` semantics remain source-reviewed, not tested
by this released binary.

## Exact inputs

- GitHub asset: `vox-aarch64-apple-darwin` from release `v0.2.10`.
- Artifact SHA-256: `01cdb1979406849979037c89431fe922770af0ccffe06c097624731130c75167`.
- Parent verified the downloaded release checksum before the verifier started the binary.
- Independently observed `vox --version`: `vox 0.2.10`.
- `codesign --verify --strict` exited 0.
- `codesign -dv --verbose=2` identified `us.vox.cli`, Developer ID Application
  `ROBERT E LEE (3T2D2YNTVW)`, team `3T2D2YNTVW`, and runtime flag `0x10000(runtime)`.
- This verifier did not perform a fresh online Apple notarization check.
- First-room manuscript read and followed:
  `docs/manual/first-room.md`, SHA-256
  `f4214bd261181e3c69e1df4ceb7575ccc8ecdd9812b01258c09207ee8ea76836`.
  It was still an uncommitted authoring-lane file during the exercise; this receipt's final
  content review must separately identify the integrated commit.

## Isolation and apparatus

Scratch root: `/tmp/vox-manual-reader.EjQXme`, created with `mktemp -d`.
Each peer had separate `data` and `config` subdirectories and selected `--profile family`.
Every Vox invocation explicitly set BOTH `VOX_DATA_DIR` and `VOX_CONFIG_DIR`; no real profile
was opened. No `HOME` override, sudo, anchor, provider account or model process was used.
Daemons/TUI bound `--listen 127.0.0.1:0` to keep this proof on same-host loopback.

The primary journey used real PTYs and masked prompts for both identities, both daemons,
room creation and the first join. Trust was added after joining, matching the manuscript.
The third scratch identity/daemon used a synthetic identity passphrase in its environment;
its two join attempts still used the actual masked terminal prompt.

One staging error was APPARATUS, not PRODUCT: the tool initially sent LF instead of terminal
Return (CR) to the first identity prompt. LF became part of the masked input; confirmation
therefore correctly failed with `the two passphrases differ; nothing was created`. Only that
setup step was retried with CR. The successful journey was then completed once; no product
failure was rerun until green.

## Reproducible scenario

Use the exact verified binary and new scratch roots, never personal profiles. A wrapper such
as the following keeps both roots attached to every command. Its arguments deliberately
contain no passphrase:

```sh
proof_root=$(mktemp -d /tmp/vox-manual-reader.XXXXXX)
vox_binary=/absolute/path/to/verified/vox-aarch64-apple-darwin
peer_vox() {
  proof_peer=$1
  shift
  env -i PATH="$PATH" TERM="${TERM:-xterm-256color}" \
    VOX_DATA_DIR="$proof_root/$proof_peer/data" \
    VOX_CONFIG_DIR="$proof_root/$proof_peer/config" \
    "$vox_binary" "$@"
}
```

Set the same `proof_root` and wrapper in the relevant terminals. Do not run daemon and TUI
simultaneously for one peer. Terminal Enter is CR in the verifier's PTY interface.

1. `peer_vox robert --version`; `peer_vox robert id --profile family`;
   `peer_vox ann id --profile family`. Choose synthetic, retained identity passphrases at the
   masked prompts. Record and compare both full fingerprints.
2. Before starting a runtime, `peer_vox robert room list --profile family` produces the
   no-runtime error below.
3. In separate foreground terminals run
   `peer_vox robert daemon --profile family --listen 127.0.0.1:0` and
   `peer_vox ann daemon --profile family --listen 127.0.0.1:0`.
   Supply each identity passphrase at the prompt. Leave them running.
4. From another terminal, run each peer's `room list --profile family`; both initially print
   `no rooms`.
5. `peer_vox robert room create --profile family --name family`, entering and confirming a
   synthetic room passphrase; then `room list` and `room invite --profile family ROOM_ID`.
   Replace `ROOM_ID` with the printed unique room prefix in every subsequent command.
6. `peer_vox ann room join --profile family 'COMPLETE_INVITE' --name family`, using the room
   passphrase at the masked prompt. Verify `room list` and `room roster` on both peers.
7. `peer_vox robert trust add --profile family ANN_FULL_FINGERPRINT --name ann` and
   `peer_vox ann trust add --profile family ROBERT_FULL_FINGERPRINT --name robertGPT`.
   Inspect both `trust list --profile family` outputs.
8. `peer_vox robert room post --profile family ROOM_ID "hello from robertGPT"`; read from Ann.
   Then `peer_vox ann room post --profile family ROOM_ID "hello back from ann"`; read from
   Robert. Both remote texts must actually appear; post exit 0 is not the assertion.
9. Create/start a third isolated peer, `refused`, using the same root discipline. Join the
   same invite with a deliberately wrong room passphrase; capture refusal. Repeat that
   join with the correct passphrase and verify the room appears. This is the intended
   recovery action, not a retry concealing failure.
10. Stop Ann's daemon with Ctrl-C. Start
    `peer_vox ann tui --profile family --listen 127.0.0.1:0`, unlock at its identity prompt,
    select the existing room with Enter, and execute `:close`. A separate Ann `room read`
    must report the closed-room error. In the TUI use `:back`, select the closed room,
    `:open`, and enter the room passphrase. The same CLI read must again show both messages.
11. Quit the TUI with `:quit`; stop the two remaining owned daemons with Ctrl-C/SIGTERM.
    Check that no runtime for this verified temporary asset remains.

## Observed evidence

### First-run and runtime prompts

The first identity creation printed:

```text
vox: this profile has no identity yet; creating one.
new identity passphrase:
again:
```

The daemon asked `identity passphrase:` and then printed its identity and the scratch
profile's `node.sock` path. It began serving without requiring Ctrl-D.

Creation asked `room passphrase:` and `again:`, then printed:

```text
vox: created family
     `vox room list` shows its id; that id is what agents pass as --room
```

The room list printed `q5a2ggi2ef4j  family`; that 12-character prefix worked in the subsequent
commands. The complete invite named `/ip4/127.0.0.1/udp/52191`, with no anchor configuration.
The first join asked only `room passphrase:` and exited 0 with:

```text
vox: joined family
     you read a member once you trust it and it trusts you: `vox trust add`
```

Both rosters contained exactly the expected two full fingerprints before the later refusal
scenario. Both trust lists contained the intended opposite fingerprint and local alias;
`robertGPT` preserved its case. The fresh unlocked runtime required no additional passphrase
for these trust changes and printed scope/direction consequences.

### Actual receipt in both directions

Ann's read exited 0 and contained:

```text
rmzdgylu2joer7gcxuvkk25sh73z7kypdmaswo42c6tj5jteedya robertGPT hello from robertGPT
```

After Ann replied, Robert's read exited 0 and contained:

```text
rmzdgylu2joer7gcxuvkk25sh73z7kypdmaswo42c6tj5jteedya you hello from robertGPT
lzxcirrkfk3v3ae7kqr525cdl3oxrt7lcn56lfsfrm2in45wr6ua ann hello back from ann
```

### No runtime, then recovery

Before daemon startup, `room list` exited 1:

```text
vox: no node is running for this profile, so there is nothing to ask.
       Start one:  vox daemon        (holds this profile's rooms, no terminal needed)
              or:  vox tui           (the interactive client)
       `vox node` will NOT do: it is an anchor, it holds no room and serves no socket.
```

Starting the same profile's daemon made the same list command exit 0 and print `no rooms`.

### Refused join, then recovery

The third scratch peer reached live members and its wrong-passphrase join exited 1:

```text
vox: cannot join: a member answered and refused the join
       usually the room passphrase is wrong — it is checked by them, not by you,
       so a typo arrives here rather than as a passphrase error
       if you are sure of it, they may have revoked you, or be on a different room
```

The diagnostic also named direct exchanges and `join refused: responder refused` for the
two reached members. Repeating with the correct room passphrase exited 0, printed
`vox: joined family`, and the third peer's `room list` named the same room. No identity or
profile was recreated between refusal and recovery.

### Closed room, then recovery

After a real TUI `:close`, Ann's CLI read exited 1:

```text
vox: room q5a2ggi2ef4jbh2uf5cc7xcdb7oyf535oxhhrfis4kcixo3dgpra is closed on this node, so there is nothing to read or post. A daemon reopens every room it held open, so this one was closed in `vox tui` or did not reopen. Open it in `vox tui`, or give `vox daemon` a line with its passphrase
```

TUI `:back` then `:open` displayed `Open channel` and `channel passphrase (1/1):`.
Entering the correct room passphrase restored the CLI read, exit 0, with the two original
message hashes and texts. No room leave/join, profile deletion, store editing or lock removal
was used. This proves the TUI recovery path; the alternate daemon room-passphrase-line path
was not executed in this exercise.

## Cleanup and limits

Ann's daemon exited 0 on SIGINT before the TUI was started. The TUI exited 0 on `:quit`.
Robert's daemon exited 0 on SIGINT; the third peer's daemon exited 0 on SIGTERM delivered to
its previously identified owned PID. A final process listing found no remaining daemon or
TUI using this temporary asset. Scratch data was retained for inspection, not published.

This receipt contains only synthetic identities, room/message IDs and sanitized observations.
The private passphrases used for the exercise are intentionally absent. No real Vox profiles,
model sessions, credentials, configuration files or user repositories were touched.
