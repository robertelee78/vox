# Troubleshooting by symptom

Applies to: v0.3.1. Check `vox --version` first: the fixes here are for the version they name.

## Before changing anything

Keep the **complete error**, including the line before it and any suggested next action.
Note which machine, binary and node produced it, and what you expected to happen.

```sh
command -v vox
vox --version
vox node list
vox room list
vox status
```

Use the actual affected node, with `--node NAME` when several are attached. If you ran
`vox daemon` in a terminal, look at that terminal's output. A daemon started in the background
writes its output to `.daemon/log` in the data root (see [local state](reference.md#local-state)).
If a service manager started it, use that manager's log for the same process.

`vox status --json` offers detailed local observations. It can reveal room and peer
identifiers, addresses and topology; inspect it before sharing. A status from one node is not
proof of what every other node holds or what a person has read.

Do not delete a node, remove a lock file, trust an unknown node or turn off verification
as a first diagnostic step. For every entry below, if the stated verification still fails,
follow [Get help safely](getting-help.md) with the exact symptom and checks already performed.

## Vox is not found or shows the wrong version

**Meaning:** the shell did not find the intended installation, or found another binary first.
This does not establish a broken room or identity.

**Check:** run `command -v vox`, then inspect the version from that executable. Compare it
with the installation destination. Open a new shell after installation so its marked PATH
block is read.

**Fix:** repair the intended installation's shell setup or select its exact path. Do not
recreate identity data and do not install as root to resolve a user's PATH ordering.

**Verify:** the selected path and `vox --version` agree with the release you intend to use.
If not, report both paths/versions with personal directory components redacted.

## The node is not attached

**Exact symptoms:**

- `no vox daemon is running for this data root, so node robertgpt is not attached.` followed by
  `Start one: vox daemon (or vox node attach robertgpt)`;
- `node robertgpt is not attached; attach it first: vox node attach robertgpt`;
- `there is no node in … yet; make one: vox node create <name>`.

**Meaning:** a one-shot command (`room`, `status`, `trust`, `share`, `service`) asks an attached
node and found none to ask. It does not mean the node has no rooms on disk, and it is not a
damaged node.

**Check:** run `vox node list`: each node is `attached` or `detached`. Compare `--node`,
`VOX_NODE`, the data/config roots and the OS user with the terminal or agent that should hold the
node. A node attached because a session needed it, such as `vox forward`, detaches again when
the last of them ends. An agent's hook never attaches its node: the agent says `node NAME is not
attached, and a hook never attaches it`, and you attach it, in a terminal outside the agent's
session.

**Fix:** `vox node attach robertgpt`. Do not create a second node to get past this message: a
new node is a new identity, with no rooms and no trust. To keep a node attached across daemon
restarts, attach it with `--keep` (see [passphrase input](reference.md#passphrase-input)).

**Verify:** `vox room list` returns the rooms or `no rooms`, not the attach message. If the
same message remains, report the selected roots and the exact message.

## A keyring change asks for the passphrase, or is refused

**Exact symptoms:**

- `vox: changing who you trust needs your identity passphrase: it was not entered for a keyring
  change in the last 30 minutes`, then `identity passphrase:` at a terminal;
- the same line, then `it is typed at a terminal, and taken from nothing else (not
  VOX_IDENTITY_PASSPHRASE, not a file). Run it in a terminal: vox trust add …`, and the command
  exits 1;
- `vox: --identity-passphrase-file is refused: a keyring change's passphrase is typed at a
  terminal, never read from a file`.

**Meaning:** a keyring change (`vox trust add`, `remove`, `rename`, `drive`, `read`) needs the
identity passphrase unless one was typed for a keyring change in the last 30 minutes. Attaching
the node does not count. The passphrase is typed at a terminal; a file, `VOX_IDENTITY_PASSPHRASE`
and an agent's session are never asked for it. Nothing is changed when the command is refused.

**Check:** `vox status` says `keyring asks for the passphrase` or `keyring open Nm` on its second
line.

**Fix:** run the command the message names in a terminal of your own, outside any agent's session,
and type the passphrase at the prompt. For an agent's node, you, its operator, run it.

**Verify:** `vox trust list` shows the change, and `vox status` says `keyring open 30m`.

## A daemon is already running

**Exact symptom:** `a daemon is already running for …`.

**Meaning:** each data root
has **one** daemon, and every command, the TUI and agent hooks are its clients. A second
`vox daemon` for the same data root stops with that message. Attaching a node that is already
attached simply succeeds.

**Check:** you rarely need to start `vox daemon` yourself. If you meant to use another data
root, compare `VOX_DATA_DIR` in both terminals.

**Fix:** use the running daemon: the TUI, the CLI and agents can all run at once. To stop the
daemon you started in a terminal, Ctrl-C it; that detaches every node it holds, which stops their
rooms, services and agent delivery. Do not kill unrelated Vox processes.

**Verify:** the intended command runs against the one daemon and the existing room data remains
available. Never delete the lock or database to defeat ownership. If you cannot identify the
holder, stop here and report the observation before making destructive changes.

## The room is closed

**Exact symptom:** `is closed on this node, so there is nothing to read or post`.

**Meaning:** the node knows the room but has not opened it, for example after `:close` in the
TUI. This differs from an unknown room ID and from having no rooms at all.

**Check:** inspect the room list and daemon output. Check that you selected the intended node.

**Fix:** open it in the TUI: `vox` (or `vox tui --node robertgpt`), select the closed room, Enter
or `:open`, and give its room passphrase. `:back` returns to the room list. Do not leave and
rejoin just to open a locally closed room. For unattended operation, see the
[daemon passphrase-file format](reference.md#passphrase-input).

**Verify:** `room read` succeeds for that room. An empty successful read may be legitimate;
it is not the same error. If opening is refused, retain that new error and ask for help.

## I cannot join a room

**Check first:** retain the entire `cannot join` explanation, confirm the full room link
with its sender, and ask whether the relevant member is online. A room link and a room
passphrase have different jobs; do not replace both at random.

### A member answered and refused the join

**Meaning:** a responder was reached. The usual cause is a wrong room passphrase, but a
refusal can also involve revocation or a different room. It does not prove which one.

**Fix:** confirm the room passphrase separately with its sender, checking accidental spaces
or copying mistakes. If it is correct, ask the room's creator about the intended room and your
membership. Do not bypass admission or change trust merely to get a join accepted.

**Verify:** join reports `joined` and the room appears in `room list`; then separately verify
trust and readable messages. If refusal remains, report the exact explanation, not secrets.

### The room is full or has ended

**Exact symptoms:** after `vox: cannot join:`, one of

- `the room is full, so you were not admitted`
- `another newcomer took the room's last place at the same moment, so you were not admitted`
- `a member of the room did not agree to take you in, so you were not admitted`, with a `said:`
  line naming the member, for example `member bob did not answer within 5s, and every member
  online must agree before the room takes a newcomer`
- `that room has ended — a member or its board said so — so it takes nobody in`

**Meaning:** in the first three your passphrase was accepted. A room takes at most 1,024
members, and every member online must agree before it takes a newcomer (see
[Create or join](rooms.md#create-or-join)). The first means the room is at its cap. The second
means you and another newcomer asked for its last place together, and the other got it. The third
means a member the room could reach did not answer in time or does not yet count the member that
answered you as part of the room. The last means its creator or an admin ended the room, or it
ended itself after an idle time its creator chose; your passphrase was never checked.

**Fix:** for a full or ended room, ask the room's creator; an ended room is gone, and they can
make a new room and share its link. After the second or third, run the join again: a place
another newcomer did not take is free again, and a member that was busy or still syncing usually
answers the next time. If the same member is named again, ask its owner whether it is running.

### No board or no member answered

**Meaning:** connectivity failed before a completed passphrase check. “Your passphrase was
never checked” means exactly that, not that it was correct or incorrect.

**Check:** distinguish the room host/anchor not answering from a board answering but none of
its members being reachable. Also distinguish a member that was reached but stopped
answering during the join exchange. These are different last successful steps.

**Fix:** restore the specifically named host/member's availability or route, then retry.
An anchor matters only if direct reach is unavailable; do not add one to cure a member's
explicit refusal. A member reached and then silent may have disconnected or become busy.
If a machine changed network shortly before, see
[after a network change](#peers-cannot-find-me-after-a-network-change).

**Verify:** the join reaches a responder and completes. If the same step fails, report that
step, timing and whether the peers share a LAN, without posting their private addresses.

### The address is bad or the room is absent from the board

**Meaning:** a parse failure points to the room link. A parsed link whose room is absent
can mean the host has not published it, or the room portion was mistyped; parsing does not
prove that the link names the intended room.

**Fix:** compare the full room link with its sender and keep the hosting member online.
**Verify:** the corrected link joins the intended room. If it still fails, share the
error category and redacted structure, not the room link and passphrase together.

## We joined but cannot read each other

**Meaning:** membership is not trust. Trust is directional; a successful join does not
release every member's message keys. The TUI can show `[locked — not shared with you]` rather
than readable text.

**Check:** both people run `vox trust list` and `vox room roster ROOM_ID` as the intended node.
Compare the actual fingerprints, not just local aliases. Then inspect connectivity with
`vox status`: each member's line says `trusted`, `connected` and when it was last synced. An
offline peer cannot immediately deliver a changed key or a message.

**Fix:** if a trust decision was genuinely missing, compare the full fingerprint and make
that decision on the correct side. If trust is already correct, restore availability and
allow sync rather than repeatedly removing and re-adding trust.

**Verify:** post a new harmless message and see it on the other node; repeat in reverse.
Do not infer that an old inaccessible message must become readable. If new messages still
fail, report each side's trust direction and reachability without posting message bodies.

## A message says not received yet

**Symptom:** `(not received yet)` occupies a position in the timeline.

**Meaning:** this node holds the signed envelope, but its unexpired message body is still
owed. It is not a blanket label for an untrusted sender and does not expose that sender's
plaintext. The row has no arrival cursor until the body arrives.

**Check:** inspect `vox status`, the affected room and peer connectivity. Compare whether
another available member actually holds the missing message. Do not infer wrong trust or a
broken signature from this placeholder alone.

**Fix:** restore the relevant peers' availability and let the node request the body. Do not
reset identity, change trust indiscriminately or use the placeholder as a `--since` cursor.
If no member holds the body, do not promise a central server can recover it.

**Verify:** the placeholder is replaced by the received message, or the actual retention
state explains its removal. If it persists despite a reachable holder, report the exact
versions and sanitized sync observations using [Get help safely](getting-help.md).

## The service is unreachable

**Meaning:** joining the room, publishing an offer, local proxy availability and the actual
service being reachable are separate facts.

**Check:**

- the host's local service is running;
- the host trusts the guest fingerprint;
- both use the intended room;
- `vox service list ROOM_ID` names the intended offer and shows **your** address for it;
- the guest has a node attached, so its daemon's proxy runs (`vox up` says where, or why it
  is not running), or its `vox forward` is still running;
- the ordinary client uses that loopback proxy or forward.

A readable address from someone else's screen uses their names for the node and room, which may
mean nothing on your machine. Use the readable address your own `service list` prints, or the
canonical address under it, which is the same on every member's machine.

**Fix:** restore the missing piece. A forward that says `tunnel refused or cut — the host
refused "ssh" — it has not trusted this identity, or offers nothing there, or its service did not
answer` names three possible causes; check each with the host. If access was explicitly
withdrawn, ask the host; retrying does not recreate permission. If the local service refuses
authentication, investigate that service rather than weakening Vox trust or disabling SSH
host-key checking.

**Verify:** the expected application answers through Vox using its normal authentication.
If it still fails, report the last successful step and exact refusal, not a generic “SSH broken”.

## Peers cannot find me after a network change

**What Vox does:** when the machine's addresses or default route change, such as moving from home
Wi-Fi to a hotspot, the daemon hears it from the operating system and acts within seconds. It
writes one line to its log (`.daemon/log` in the data root, or the terminal of a `vox daemon` you
started there), for example:

```text
vox: the network changed: addresses came: 10.9.1.7; went: 10.9.0.1; IPv4 default route 10.9.0.254 → 10.9.1.254; this node now advertises /ip4/10.9.1.7/udp/55525, /ip4/127.0.0.1/udp/55525, and republished 0 room(s) to its board and its anchors
```

It forgets the outside addresses it had seen, asks the router for its port mappings again,
publishes each attached node's new addresses to its rooms' boards and anchors, and dials its
peers and anchors again. A connection that does not answer after the change is closed and dialled
again. `vox status --json` names the last change under `network_changed`, with its time (`at`)
and the same sentence (`change`); it is `null` when there has been none since the daemon started.
There is nothing to restart.

**Check:** if a peer still cannot reach you after a minute:

- `vox status --json`: is `network_changed` the change you expected? If it is `null`, the
  daemon did not count a change: only a change of routable addresses or of the default route
  counts.
- `vox status`: under `gateway`, did a router answer (see
  [reading status](reference.md#output-cursors-and-status))? Behind a new NAT with no mapping
  answered, a peer that is also behind NAT can reach you only through an anchor; see
  [when an anchor is needed](services.md#when-an-anchor-is-needed).
- `vox status` on both sides: is the peer `connected`, and by which path, `direct` or relayed?
- A VPN, a firewall or a captive portal on the new network can block UDP; check it the way you
  would for any other program.

**Fix:** restore what the checks name: sign in to the captive portal, allow UDP, or give both
sides an anchor they can reach. Do not delete the node or change trust to cure a network fault.

**Verify:** the peer shows `connected` in `vox status` and a new message arrives.

## The file is unavailable or fails verification

**Meaning:** a share's message can stay in the room after its sharer stops serving it. An
unreachable share can also mean missing trust; a hash failure means the received bytes do not
match the signed announcement, not that the check should be disabled.

**Check:** identify the sharer and the exact share. Ask whether it is still shared: the sharer's
`vox share list ROOM_ID` lists it, and a share given `--count` or `--for` stops by itself. A pull
from a share that has stopped says `the offer of FILE is gone: NAME no longer serves it`; one
whose sharer cannot be reached says `the offer of FILE cannot be collected now` and gives the
reason. Inspect any reported size/hash or stall reason. If `--out` already exists, that is local
destination protection, not a transfer failure. A share your node did not pull by itself is
either addressed to someone else or from a node not in your keyring (see
[where a shared file lands](files.md#where-a-shared-file-lands)).

**Fix:** have the sharer share the intended unchanged file again if needed, then pull again.
Use another output path for a collision. Do not salvage or open a failed `.part` as though
verified; this workflow rejects incomplete/mismatched transfers and removes its partial file.

**Verify:** the command names the saved file and says it `matches its announced SHA-256`. If repeated attempts fail,
use a harmless reproduction file and record expected/received byte counts, without publishing
the private file or treating its hash as anonymous.

## The agent does not respond

**Meaning:** no answer can mean no session, wrong node, missing hook/plugin, missing trust,
next-turn delivery, or an agent that has not acted. It is not proof that encryption failed.

**Check:** run `vox agent doctor --node AGENT_NODE --room ROOM_ID` on the agent's machine. It
checks the node, the room, the installed hook or plugin, the drain, session records, trust in
each direction and versions, and prints a fix for each problem. From another node,
`vox room ping ROOM_ID AGENT_ALIAS` asks the agent's daemon which sessions it holds. Then use
ordinary `vox room read --node AGENT_NODE ROOM_ID`: if the agent's node cannot see the question,
solve room/trust/connectivity first.

**Fix:** install the generated integration once at user scope with the agent's `--node`. For
Codex, keep `async: false` and trust the final hook command. Reload the harness after
configuration changes. Start a normal turn in the existing session and observe a distinctive
harmless room question. Codex reads at its next turn even when a post is urgent; there is no
mid-turn interruption to repair. For Claude/OpenCode, urgent wakes still require their live
endpoint. Do not run the hook manually to simulate a real session's successful receipt.

**Verify:** observe the question in the receiving session and its reply in the intended room.
A clean doctor and a hook's exit 0 are not enough. A ping without an answer cannot distinguish
an offline node, a node that is not attached and missing trust. If the actual session still
does not receive, report the harness and Vox versions, event, scope and redacted hook.

## A claim is uncertain or coordination is refused

**Meaning:** exit 5 leaves a claim posted but not fully agreed; exit 3 means a version
mismatch; exit 1 means another holder won. None is exclusive ownership.

**Check:** read the named reason and `vox room board ROOM_ID` as the agent's node and session.
For exit 5, a member may be unreachable, missing the claim, disagreeing, or reporting
incompatible clocks. Do not reset an identity to clear an ownership result.

**Fix:** restore the specific connectivity/trust/time condition, or coordinate with the
current holder. Align participant versions for exit 3. Retain the same operation ID when
retrying the same operation. Do not reuse it for different content.

**Verify:** obtain an agreed claim or intentionally leave the work with the existing holder.
Record progress on the GitHub issue, not by manufacturing a successful room outcome. If
uncertainty persists, report the named reason and sanitized board state.

Sources: [node selection and attach messages](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/client.rs),
[join diagnostics](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/tunnel_cli.rs),
[room and file diagnostics](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/room_cli.rs),
[the daemon](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/daemon.rs),
[wake behavior](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/wake.rs)
and [network changes](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/docs/adr/ADR-012-nat-traversal-and-reachability.md).
