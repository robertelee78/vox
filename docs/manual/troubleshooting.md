# Troubleshooting by symptom

Applies to Vox v0.4.10.

Find the message or behaviour you see, then follow its steps. Each entry says what the symptom
means, what to check, how to fix it, and how to confirm the fix.

## Before changing anything

Keep the complete error, including the line before it. Note which machine and node produced it.
Then gather:

```sh
command -v vox
vox --version
vox node list
```

Then read `vox room list` and `vox status` with the affected node's actual name in `--node`.
The node list identifies it; do not let another Ready node decide the diagnostic context.
A daemon started in the background writes to `.daemon/log` in the data root ([local state](reference.md#local-state)).

Do not delete a node, remove a lock file, trust an unknown node or turn off a check as a first
step. Each of these destroys the evidence that tells causes apart. If an entry's fix does not
work, see [Get help safely](getting-help.md).

## Vox is not found or shows the wrong version

**Meaning:** the shell found no `vox`, or found another one first. Your rooms and nodes are not
affected.

**Fix:** run `command -v vox` and compare the path with where you installed Vox. Open a new
terminal so the shell reads the setup block the installer added. Do not install as root to fix
your `PATH`.

**Confirm:** `command -v vox` and `vox --version` name the `vox` you meant.

## The node is Locked or its daemon is unavailable

**Symptoms:**

- `no vox daemon is running for this data root, so node robertgpt cannot be used until it starts.`
- `node robertgpt is Locked; unlock it first: vox node unlock robertgpt`
- `no vox daemon answers at …; to start one, open Vox (or run `vox daemon` in a terminal)`
- `there is no node in … yet; make one with vox node create and a name for it`

**Meaning:** the command needs a Ready node and found none. The node and its rooms are still
on disk.

**Check:** `vox node list` shows each node as **Ready** or **Locked**. Compare `--node`,
`VOX_NODE` and `VOX_DATA_DIR` with the terminal or agent that should hold the node. An agent's
hook never asks for its passphrase. You unlock a protected node in your own terminal; a
passphrase-free node becomes Ready automatically.

**Fix:** run `vox node unlock robertgpt`. Do not make a new node to get past the message: a new
node is a new identity, with no rooms and no trust.

**Confirm:** `vox room list --node robertgpt` shows this node's rooms, or `no rooms`.

## A keyring change asks for the passphrase, or is refused

**Symptoms:**

- `vox: changing who you trust needs your identity passphrase: it was not entered for a keyring change in the last 30 minutes`
- the same, then `it is typed at a terminal, and taken from nothing else (not VOX_IDENTITY_PASSPHRASE, not a file). Run it in a terminal: …`
- `vox: --identity-passphrase-file is refused: a keyring change's passphrase is typed at a terminal, never read from a file`

**Meaning:** a change to the keyring needs the identity passphrase, typed at a terminal, unless
one was typed for a keyring change in the last 30 minutes. Nothing changed.

**Fix:** run the command the message names in your own terminal, outside any agent's session, and
type the passphrase.

**Confirm:** `vox trust list` shows the change, and `vox status` says `keyring open 30m`.

## A daemon is already running

**Symptom:** `a daemon is already running for …`

**Meaning:** each data root has one daemon, and every command, the terminal interface and the
agents are its clients. A second `vox daemon` for the same data root stops with this message.

**Fix:** use the running daemon. To stop a daemon you started in a terminal, press Ctrl-C there.
That stops every node it holds. Never delete the lock or the database.

## A pasted command is cut off or refused by the shell

**Symptoms:** zsh says `zsh: no matches found: vox://…`. Or, in bash, `vox room join` says
`that room link or id will not parse (anchor has no address): check you copied all of it, exactly
as it was sent`, and the shell reports a job it started in the background.

**Meaning:** the room link was typed without single quotes. zsh reads its `?` as a file pattern,
and bash ends the command at its first `&`. Nothing was joined, and the link is fine.

**Fix:** construct `vox room join` with the entire actual link and the intended node in `--node`,
following the [shell-quoting rule](reference.md#commands-you-can-paste). Commands Vox prints for
you to paste are already quoted: copy the whole line.

**Confirm:** Vox asks for the room passphrase, then says `vox: joined` and the room's name.

## The room is closed

**Symptom:** `is closed on this node, so there is nothing to read or post`

**Meaning:** the node holds the room but has not opened it, for example after `:close` in the
terminal interface.

**Fix:** open the terminal interface with `vox`, select the room, press Enter, and give its
passphrase. Do not leave and join again.

**Confirm:** `vox room read` works for that room.

## I cannot join a room

Keep the whole `cannot join` message. Confirm the full link with its sender, and ask whether a
member is online. The link and the passphrase do different jobs. Do not change both at once.

### A member answered and refused the join

**Meaning:** a member was reached and refused. The usual cause is a wrong room passphrase.

**Fix:** confirm the passphrase with the sender by another way, and watch for spaces and typing
mistakes. If it is right, ask the room's creator whether you have the right room.

**Confirm:** the join says `vox: joined`, and the room appears in `vox room list`.

### The room is full or has ended

**Symptoms:** after `vox: cannot join:`, one of:

- `the room is full, so you were not admitted`
- `another newcomer took the room's last place at the same moment, so you were not admitted`
- `a member of the room did not agree to take you in, so you were not admitted`, with a `said:`
  line naming the member
- `that room has ended — a member or its board said so — so it takes nobody in`

**Meaning:** in the first three, your passphrase was accepted. A room holds up to 1,024 members,
and every member online must agree to a newcomer. An ended room takes no one, and your passphrase
was never checked.

**Fix:** after the second or third, join again: a member that was busy usually answers next time.
For a full or ended room, ask the creator for a new room.

### No board or no member answered

**Symptom:** the message says the room's host did not answer, or no member was reached, and `your
passphrase was never checked`.

**Meaning:** the join reached no one who could check the passphrase. It says nothing about the
passphrase.

**Fix:** make sure a member is online and reachable from your network. If both machines are behind
NAT and cannot reach each other, you need an anchor
([when an anchor is needed](services.md#when-an-anchor-is-needed)). If a machine just changed
network, see [after a network change](#peers-cannot-find-me-after-a-network-change).

### The address is bad or the room is absent from the board

**Meaning:** the link is incomplete or mistyped, or the member who shares the room has not
published it yet.

**Fix:** copy the whole link again from its sender, inside single quotes.

## We joined but cannot read each other

**Meaning:** joining is not trust. Each of you reads the other only once each trusts the other.
The terminal interface shows `[locked — not shared with you]` for a message you cannot read.

**Check:** both of you run `vox trust list` and `vox room roster family`, and compare whole
fingerprints, not names. Then run `vox status`: each member's line says whether it is `trusted`
and `connected`, and when it last synced.

**Fix:** if a trust decision is missing, make it on the right side. If trust is right, get both
nodes online and let them sync. Do not remove and add trust again.

**Confirm:** post a new message and see it on the other node, then the other way round.

## A room question says governance is refreshing

**Symptom:** a room, administrator, trust or service question says `room governance is
refreshing`, or a read says `the room changed while reading; refresh and retry`.

**Meaning:** a changed room decision is being applied, or the read's selected view changed.
Vox must not answer an authorization question using superseded grants or an expired
administrator certificate. Unchanged questions use the completed in-memory room facts;
after restart those facts are rebuilt from the sealed index.

**Fix:** refresh the question as instructed. Do not remove and re-add trust or erase the
profile to clear it. Once the changed decision is current, `vox room admin list <room>`,
`vox room roster <room>` and `vox service list <room>` show it without a restart.

## A post is waiting for disk, or the room cannot save

**Meaning:** a post succeeds only after its own data is durably saved. A slow disk can also
hold other writes using the same profile's store. It does not make already-saved messages,
status, or Session attention selection wait for that flush.

**Check:** run `vox status --node <name>` and `vox room read <room> --node <name>`.
The pending post is not a successful post yet. A definitive save failure names the room and
the storage error instead of reporting that the message was posted.

**Fix:** resolve the underlying storage problem. Vox recovers the room automatically when
writes succeed again; do not erase the profile or its store to clear the error. Already-saved
history remains available while the room recovers.

**Confirm:** the room can save a new post again, and `vox room read` shows that post together
with its previously saved messages.

## A restored node writes nothing until its own history is recovered

**Symptom:** `this node's record of its own history in this room is behind what a member holds`.

**Meaning:** a member holds signed entries from this node that its restored profile does not.
Writing from the older position would reuse its own history. Vox refuses writes in this room
until it verifies the missing prefix and recovers the content and sender state needed to resume
safely. Held messages and incoming peer messages remain readable during recovery.

**Check:** run `vox status --node <name>` for the affected node. A connected member's held
position is not a promise that it still has every missing body or historical key.

**Fix:** keep a trusted room member that retains the missing entries and keys online and reachable.
Recovery runs automatically, including gaps older than the live window, and resumes after restart.
Do not remove trust, leave and rejoin, erase the profile, or run another copy of the same node
to bypass the refusal. Missing data cannot be recreated if no member retains it.

**Confirm:** the daemon says `this node recovered its own history; it can write here again`.
`vox room read` shows the recovered messages as this node's own, and another member reads its
next new post.

## A message says not received yet

**Symptom:** `(not received yet)` in a room.

**Meaning:** your node has the message's signed envelope, and its text is still to come from a
member. It does not mean missing trust or a bad signature.

**Fix:** get the members who hold the message online. A member busy saving room history can
delay delivery; keep it online while its save finishes. If no member holds the message, it
cannot be recovered: there is no server.

**Check:** `vox status --json` lists each room and peer under `lanes.ports`. Its
`last_recorded_unavailable_response`, when present, identifies a history request that peer
could not serve and whether it lacked the body or source evidence. The requested bounds
identify the request; for a page they do not identify a particular missing entry. This is a
past observation, not a statement of what the peer or other members hold now. It is kept
only while the port exists and is cleared when the node restarts.

**Confirm:** the message's text replaces the placeholder.

## The service is unreachable

**Meaning:** being in the room, the offer being listed, the proxy running, and the service
answering are separate facts.

**Check:**

- the service runs on the sharer's machine;
- the sharer trusts your fingerprint;
- `vox service list family` lists the service, with **your** address for it, and each line `✓`;
- your node is Ready, so the proxy runs (`vox up`), or your `vox forward` still runs;
- your tool uses that proxy or forward.

Use the address your own `vox service list` prints, or the canonical one: another member's
readable address uses their names.

**Fix:** fix what the check names. `tunnel refused or cut — the host refused "ssh" — it has not
trusted this identity, or offers nothing there, or its service did not answer` names three causes.
Check each with the sharer. If the service itself refuses your login, look at the service, not at
Vox, and keep SSH's host-key check on.

**Confirm:** the service answers through Vox and its own login works.

## Peers cannot find me after a network change

When the machine's addresses or default route change, the daemon notices within seconds. It asks
the router for port mappings again, publishes the node's new addresses, and dials its peers and
anchors again. Its log says so in one line:

```text
vox: the network changed: addresses came: 10.9.1.7; went: 10.9.0.1; IPv4 default route 10.9.0.254 → 10.9.1.254; this node now advertises /ip4/10.9.1.7/udp/55525, /ip4/127.0.0.1/udp/55525, and republished 0 room(s) to its board and its anchors
```

**Check:** if a peer still cannot reach you after a minute:

- `vox status --json`: is `network_changed` the change you expect? `null` means the daemon saw no
  change of routable address or default route.
- `vox status`, under `gateway`: did a router grant a mapping? Behind NAT with no mapping, a peer
  also behind NAT reaches you only through an anchor.
- `vox status` on both sides: is the peer `connected`, and `direct` or relayed?
- A VPN, a firewall or a captive portal can block UDP.

**Fix:** sign in to the captive portal, allow UDP, or give both sides an anchor they can reach.

**Confirm:** the peer shows `connected`, and a new message arrives.

## The file is unavailable or fails verification

**Meaning:** a share's message can outlive its serving. A pull can also fail for missing trust. A
hash mismatch means the bytes received are not the ones announced.

**Check:**

- `the offer of report.txt is gone: robertGPT no longer serves it`: the sharer stopped. Their
  `vox share list family` does not list it.
- `the offer of report.txt cannot be collected now`, with a reason: the sharer cannot be reached.
- `already exists; vox room get never overwrites a file`: pick another `--out` path.
- A share your node did not pull by itself is addressed to someone else, or comes from a node not
  in your keyring ([where a shared file lands](files.md#where-a-shared-file-lands)).

**Fix:** ask the sharer to share the file again, then pull again. Never open a `.part` file.

**Confirm:** Vox names the saved file and says it `matches its announced SHA-256`.

## The agent does not respond

**Meaning:** no answer can mean no running session, the wrong node, a missing hook, missing
trust, or a message that arrives at the next turn.

**Check:** for an agent whose node is `claude-mac`, in the room `family`:

```sh
vox agent doctor --node claude-mac --room family
vox room read family --node claude-mac
```

Run them on the agent's machine. From `robertgpt`, `vox room ping family claude-mac --node robertgpt`
asks the agent's daemon which sessions it holds. If the agent's node cannot read the question, fix trust or
connectivity first. A session in a repository with no room works in none
([the room a session works in](sessions.md#the-room-a-session-works-in)).

**Fix:** follow the doctor's `fix:` lines. Reload the harness after a settings change. OpenCode
needs both its server and current TUI client integrations; a server alone cannot admit attention
to a closed client. Claude needs the complete generated native-attention hook configuration.
Codex reads messages at its next normal turn, even urgent ones; do not try to wake it through a
second harness or synthetic turn. Check whether this receiver's room is paused before reposting.

With Drive, select the actual open Session and inspect `vox room session --attention`, keeping
the node/room/Session from its complete read command. A next-turn or paused reason is queued,
not delivered. Unknown acceptance is not permission to retry a notice. Delivered means context
was released; Answering needs an observed turn, and Answered needs a correlated room answer.
A source removed by retention cannot be recovered by repeating the wake.

**Confirm:** the actual harness shows the attributed question, and its correlated reply appears
in the room. Model relevance and a reply are not guaranteed by delivery.

## A claim is uncertain or coordination is refused

**Meaning:** exit 5 means the claim is posted but not every member agrees yet. Exit 3 means the
members run different versions of Vox. Exit 1 means another session holds the item.

**Check:** read the reason Vox prints, and `vox room board family --node claude-mac` for this agent.

**Fix:** restore the named member's connectivity, align versions, or coordinate with the holder.
To retry the same operation, keep its `--op` ID.

**Confirm:** a claim exits 0, or you leave the work to its holder.
