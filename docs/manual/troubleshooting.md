# Troubleshooting by symptom

Applies to: v0.2.10. If your command uses `--node`, or the symptom is `(not received yet)`,
start with the [development guide](development.md) instead. Do not mix fixes across versions.

## Before changing anything

Keep the **complete error**, including the line before it and any suggested next action.
Note which machine, binary and profile produced it, and what you expected to happen.

```sh
command -v vox
vox --version
vox room list --profile family
vox status --profile family
```

Use the actual affected profile, not `family` by habit. If a daemon is running in a terminal,
look at that terminal's output. If a service manager started it, use that manager's log for
the same process. This release does not promise a universal `vox logs` command or an
automatically populated development `.daemon/log` file.

`vox status --profile family --json` offers detailed local observations. It can reveal room
and peer identifiers, addresses and topology; inspect it before sharing. A status from one
node is not proof of what every other node holds or what a person has read.

Do not delete a profile, remove a lock file, trust an unknown node or turn off verification
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

**Exact symptom:** `no node is running for this profile, so there is nothing to ask.`

**Meaning:** a room command needs a running daemon/TUI for this profile and did not find its
control socket. It does not mean the profile has no rooms on disk.

**Check:** compare `--profile`, `VOX_PROFILE`, data/config roots and the OS user in both
terminals. Confirm whether the intended daemon exited or is waiting for a passphrase.

**Fix:** start `vox daemon --profile family` in a terminal, or use the TUI for that profile,
then retry the client in another terminal. `vox node` will not fix this: in v0.2.10 that
command runs an anchor, which holds no room and serves no agent control socket.

**Verify:** `vox room list --profile family` returns the rooms or `no rooms`, not the socket
error. A socket that exists but has no listener is a different message; starting the node
again replaces a stale socket. Preserve other handshake errors rather than calling all of
them “offline”. If the same error remains, report the selected roots and exact socket error.

## Another Vox process is using this profile

**Exact symptoms:** `a vox is already running for this profile` or
`another vox is still using this profile`.

**Meaning:** this release allows only one holder of a profile. A running daemon, TUI, anchor
or unfinished command can own it. A command suspended with Ctrl-Z may still hold it.

**Check:** read whether the message names a control socket or an unfinished holder. The
message can give an `lsof` command for the exact profile directory; inspect that process
before deciding it is unwanted.

**Fix:** use the `vox room` verbs that ask the running daemon, or intentionally stop the
holder before starting a standalone command/TUI. Let an unfinished operation finish, or
resume a suspended one if that is what you intended. Do not kill unrelated Vox profiles.

**Verify:** the intended command starts with one holder and the existing room data remains
available. Never delete the lock or database to defeat ownership. If you cannot identify the
holder, stop here and report the observation before making destructive changes.

## The room is closed

**Exact symptom:** `is closed on this node, so there is nothing to read or post`.

**Meaning:** the node knows the room but has not opened it. This differs from an unknown
room ID and from having no rooms at all.

**Check:** inspect the room list and daemon output. Check that you selected the intended
profile and that the daemon received the room passphrase it needs.

**Fix:** stop that profile's daemon deliberately, then start `vox tui --profile family`
and unlock the identity. In the room list, select the closed room, use `:open` and enter
its room passphrase. If you are still in a closed timeline, `:back` returns to the room
list. Do not leave and rejoin just to open a locally closed room. For unattended operation,
see the explicit [daemon passphrase-file format](reference.md#passphrase-input).

**Verify:** `room read` succeeds for that room. An empty successful read may be legitimate;
it is not the same error. If opening is refused, retain that new error and ask for help.

## I cannot join a room

**Check first:** retain the entire `cannot join` explanation, confirm the full invitation
with its sender, and ask whether the relevant member is online. An address and a room
passphrase have different jobs; do not replace both at random.

### A member answered and refused the join

**Meaning:** a responder was reached. The usual cause is a wrong room passphrase, but a
refusal can also involve revocation or a different room. It does not prove which one.

**Fix:** confirm the room passphrase separately with its sender, checking accidental spaces
or copying mistakes. If it is correct, ask the room owner about the intended room and your
membership. Do not bypass admission or change trust merely to get a join accepted.

**Verify:** join reports success and the room appears in `room list`; then separately verify
trust and readable messages. If refusal remains, report the exact explanation, not secrets.

### No board or no member answered

**Meaning:** connectivity failed before a completed passphrase check. “Your passphrase was
never checked” means exactly that, not that it was correct or incorrect.

**Check:** distinguish the room host/anchor not answering from a board answering but none of
its members being reachable. Also distinguish a member that was reached but stopped
answering during the join exchange. These are different last successful steps.

**Fix:** restore the specifically named host/member's availability or route, then retry.
An anchor matters only if direct reach is unavailable; do not add one to cure a member's
explicit refusal. A member reached and then silent may have disconnected or become busy.

**Verify:** the join reaches a responder and completes. If the same step fails, report that
step, timing and whether the peers share a LAN, without posting their private addresses.

### The address is bad or the room is absent from the board

**Meaning:** a parse failure points to the address. A parsed address whose room is absent
can mean the host has not published it, or the room portion was mistyped; parsing does not
prove that the address names the intended room.

**Fix:** compare the full invitation with its sender and keep the hosting member online.
**Verify:** the corrected address joins the intended room. If it still fails, share the
error category and redacted structure, not the invitation/passphrase pair.

## We joined but cannot read each other

**Meaning:** membership is not trust. Trust is directional; a successful join does not
release every member's message keys. The released TUI can show
`[locked — not shared with you]` rather than readable text.

**Check:** both people run `vox trust list` and `vox room roster` with the intended profile.
Compare the actual fingerprints, not just local aliases. Then inspect connectivity with
`vox status`. An offline peer cannot immediately deliver a changed key or a message.

**Fix:** if a trust decision was genuinely missing, compare the full fingerprint and make
that decision on the correct side. If trust is already correct, restore availability and
allow sync rather than repeatedly removing and re-adding trust.

**Verify:** post a new harmless message and see it on the other node; repeat in reverse.
Do not infer that an old inaccessible message must become readable. If new messages still
fail, report each side's trust direction and reachability without posting message bodies.

## The service is unreachable

**Meaning:** joining the room, publishing an offer, local proxy availability and the actual
service being reachable are separate facts.

**Check:** the host's local service is running; the host trusts the guest fingerprint;
both use the intended room; `vox service list` names the intended offer; the guest's `vox up`
or forward is still running; and the ordinary client uses that loopback proxy/forward.
Copy the hostname printed by Vox, not an address from a development screenshot.

**Fix:** restore the missing piece. If access was explicitly withdrawn, ask the host; retrying
does not recreate permission. If the local service refuses authentication, investigate that
service rather than weakening Vox trust or disabling SSH host-key checking.

**Verify:** the expected application answers through Vox using its normal authentication.
If it still fails, report the last successful step and exact refusal, not a generic “SSH broken”.

## The file is unavailable or fails verification

**Meaning:** the room can retain an announcement after its live offer stops. An unreachable
offer can also mean missing trust; a hash failure means the received bytes do not match the
signed announcement, not that the check should be disabled.

**Check:** identify the sender and exact offer; ask whether `room send` is still running.
Inspect the reported size/hash or stall reason. If `--out` already exists, that is local
destination protection, not a transfer failure.

**Fix:** have the sender re-offer the intended unchanged file if needed, then fetch again.
Use another output path for a collision. Do not salvage or open a failed `.part` as though
verified; this workflow rejects incomplete/mismatched transfers and removes its partial file.

**Verify:** the command reports a verified successful save. If repeated attempts fail, use
a harmless reproduction file and record expected/received byte counts, without publishing
the private file or treating its hash as anonymous.

## The agent does not respond

**Meaning:** no answer can mean no session, wrong profile, missing hook/plugin, missing trust,
next-turn delivery, or an agent that has not acted. It is not proof that encryption failed.

**Check:** first use ordinary `room read` on the agent's selected profile. If it cannot see
the question, solve room/trust/connectivity first. If it can, check that the correct generated
integration is installed once at user scope and selects the same profile. For Codex, keep
`async: false` and trust the final hook command. Reload the harness after configuration changes.

**Fix:** start a normal turn in the existing session and observe a distinctive harmless room
question. Codex reads at its next turn even when a post is urgent; there is no mid-turn
interruption to repair. For Claude/OpenCode, urgent wakes still require their live endpoint.
Do not run the hook manually to simulate a real session's successful receipt.

**Verify:** observe the question in the receiving session and its reply in the intended room.
Hook exit 0 is not enough. v0.2.10 has no `vox agent doctor` or `vox room ping`; those commands
belong to [development diagnostics](development.md#agent-diagnostics). If the actual session
still does not receive, report the harness and Vox versions, event, scope and redacted hook.

## A claim is uncertain or coordination is refused

**Meaning:** exit 5 leaves a claim posted but not fully agreed; exit 3 means a version
mismatch; exit 1 means another holder won. None is exclusive ownership.

**Check:** read the named reason and `vox room board ROOM_ID` under the agent's profile and
session. For exit 5, a member may be unreachable, missing the claim, disagreeing, or reporting
incompatible clocks. Do not reset an identity to clear an ownership result.

**Fix:** restore the specific connectivity/trust/time condition, or coordinate with the
current holder. Align participant versions for exit 3. Retain the same operation ID when
retrying the same operation. Do not reuse it for different content.

**Verify:** obtain an agreed claim or intentionally leave the work with the existing holder.
Record progress on the GitHub issue, not by manufacturing a successful room outcome. If
uncertainty persists, report the named reason and sanitized board state.

Sources: [released join and profile diagnostics](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/tunnel_cli.rs),
[room and file diagnostics](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/room_cli.rs),
and [wake behavior](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/wake.rs).
