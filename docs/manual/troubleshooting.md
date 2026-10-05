# Troubleshooting by symptom

Applies to: v0.3.0. If your command uses `--profile`, you are running v0.2.10 or following
v0.2.10 instructions; read [Coming from v0.2.10](development.md) first. Do not mix fixes across
versions.

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

## No node is running for this profile

That was v0.2.10's wording. In v0.3.0 the same situation reads:

- `no vox daemon is running for this data root, so node robertgpt is not attached.` followed by
  `Start one: vox daemon (or vox node attach robertgpt)`;
- `node robertgpt is not attached; attach it first: vox node attach robertgpt`;
- `there is no node in … yet; make one: vox node create <name>`.

**Meaning:** a one-shot command (`room`, `status`, `trust`, `share`, `service`) asks an attached
node and found none to ask. It does not mean the node has no rooms on disk, and it is not a
damaged node.

**Check:** run `vox node list`: each node is `attached` or `detached`. Compare `--node`,
`VOX_NODE`, the data/config roots and the OS user with the terminal or agent that should hold the
node. A node attached because a session needed it, such as `vox forward` or an agent session,
detaches again when the last of them ends.

**Fix:** `vox node attach robertgpt`. Do not create a second node to get past this message: a
new node is a new identity, with no rooms and no trust. To keep a node attached across daemon
restarts, attach it with `--keep` (see [passphrase input](reference.md#passphrase-input)).

**Verify:** `vox room list` returns the rooms or `no rooms`, not the attach message. If the
same message remains, report the selected roots and the exact message.

## Another Vox process is using this profile

That was v0.2.10's wording; v0.3.0 has no profile lock. **Meaning in v0.3.0:** each data root
has **one** daemon, and every command, the TUI and agent hooks are its clients. A second
`vox daemon` for the same data root stops with `a daemon is already running for …`. Attaching a
node that is already attached simply succeeds.

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

**Exact symptoms:** `the room is full, so you were not admitted`, or `that room has ended — a
member or its board said so — so it takes nobody in`.

**Meaning:** the first means your passphrase was accepted but the room takes no more members.
The second means its creator or an admin ended it, or it ended itself after an idle time its
creator chose; your passphrase was never checked.

**Fix:** ask the room's creator. An ended room is gone; they can make a new room and share its
link.

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

### The room was made before v0.3.0

**Exact symptom:** `this room was made by vox before v0.3.0, and its message format changed, so
this vox cannot open it`.

**Fix:** make the room again with `vox room create` and share its new link with the members.
Trust carries over; the old room's messages do not.

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
If the body is no longer available, do not promise a central server can recover it.

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
- the guest's `vox up` or `vox forward` is still running;
- the ordinary client uses that loopback proxy or forward.

Copy the address your own `service list` prints, not one from someone else's screen: the node
and room parts are each viewer's own names.

**Fix:** restore the missing piece. A forward that says `tunnel refused or cut — the host
refused "ssh" — it has not trusted this identity, or offers nothing there, or its service did not
answer` names three possible causes; check each with the host. If access was explicitly
withdrawn, ask the host; retrying does not recreate permission. If the local service refuses
authentication, investigate that service rather than weakening Vox trust or disabling SSH
host-key checking.

**Verify:** the expected application answers through Vox using its normal authentication.
If it still fails, report the last successful step and exact refusal, not a generic “SSH broken”.

## Peers cannot find me after a network change

**Meaning:** v0.3.0 does not notice when the machine changes network, such as moving from home
Wi-Fi to a hotspot, and off Linux it does not read the default route. Peers can go on trying the
addresses the daemon published before the change. Detecting changes is planned for v0.3.1; this
release does not do it.

**Check:** `vox status` on both sides: is the peer `connected`, and by which path?

**Fix:** if peers stay unreachable after the change, restart the daemon: it learns and publishes
its addresses when it starts. A `vox daemon` you run in a terminal: Ctrl-C it and start it again.
A daemon started in the background exits once no node is attached and no client is connected:
detach each node with `vox node detach NAME`, stop any `up`, `forward`, `serve` or agent session
holding one, then attach again. A restart interrupts every node's rooms, services and agent
delivery while it happens. This remedy follows from the source and was not exercised by the
manual's v0.3.0 check.

**Verify:** the peer shows `connected` in `vox status` and a new message arrives.

## The file is unavailable or fails verification

**Meaning:** the room can retain an announcement after its live offer stops. An unreachable
offer can also mean missing trust; a hash failure means the received bytes do not match the
signed announcement, not that the check should be disabled.

**Check:** identify the sender and exact offer; ask whether `room send` or `share` is still
running (a `share` with `--count` or `--for` stops by itself). A fetch from an offer that has
stopped says `the offer of FILE is gone: NAME no longer serves it`; one whose sender cannot be
reached says `the offer of FILE cannot be collected now` and gives the reason. Inspect any reported size/hash or stall reason. If `--out` already exists, that
is local destination protection, not a transfer failure.

**Fix:** have the sender re-offer the intended unchanged file if needed, then fetch again.
Use another output path for a collision. Do not salvage or open a failed `.part` as though
verified; this workflow rejects incomplete/mismatched transfers and removes its partial file.

**Verify:** the command reports `verified` and names the saved file. If repeated attempts fail,
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

Sources: [v0.3.0 node selection and attach messages](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/client.rs),
[join diagnostics](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/tunnel_cli.rs),
[room and file diagnostics](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/room_cli.rs),
[the daemon](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/daemon.rs),
[wake behavior](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/wake.rs)
and [network-change work for v0.3.1](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-012-nat-traversal-and-reachability.md).
