# Vox UX research (input to the v0.4.0 UX ADR and the macOS app ADR)

Research pass of 2026-10-03, read from `v030/rearch-tui` 355f6ffa. Nothing here is built or decided; the decider's answers to its open questions are in [v040-ux-interview-decisions.md](v040-ux-interview-decisions.md), and where they differ, the answers win.


VOX — UX RESEARCH

Keyring · Rooms · Services — one experience

What Vox can borrow,\
and what it must not.
==============================================

A study of Signal, Slack, Discord, Matrix, Briar, Keybase, Syncthing, Tailscale, GPG key managers and terminal clients, measured against Vox's model of rooms, nodes, trust and services. Input to the UX ADR and the macOS app ADR. Nothing here is built or decided.

**2026-10-03**\
Research pass 2 of 2\
Read from `v030/rearch-tui` 355f6ffa\
20 open questions for the decider

Before you read

## Four things to know first

- **Accent: ice blue is recommended** over copper or red. It is Enlightenment's own focus glow. Copper and red both land on the same 256-colour index (167) as the danger colour, and copper falls back to the same 16-colour slot as warnings.
- **Two ADRs conflict with your model.** ADR-014 (macOS) and ADR-015 (TUI) still describe consent prompts, a separate "verified" state, Block, a pseudonym per room and shared-root device sync. Question 2 asks whether to drop them.
- **ADR-020 contradicts itself:** 3.10 says to show who read a message; 4.9a says a node cannot see reads. Question 6 settles it.
- **Some top-10 ideas need a small yes from you.** A declared service kind (question 13); a file share held by the daemon and possibly a thumbnail inside the message (questions 14–15). None of them adds a concept to the model.

How ideas are marked: Fits can be said fully in rooms, nodes, trust and services. Needs a decision adds a concept or changes an ADR. Breaks the model must not be built; see [Must not borrow](#never).

1 · Ranked by value to the decider

## Top 10

<table class="top10">
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th>#</th>
<th>Idea</th>
<th>What it means</th>
<th>Fit</th>
</tr>
</thead>
<tbody>
<tr>
<td class="n">01</td>
<td><strong>Trust lives where you chat</strong></td>
<td>Every author shows as your alias if trusted, else a fingerprint chip (art plus <code>K2M9·Q7RT</code>) marked NOT IN YOUR KEYRING. A glyph on every row and in the member pane: <code>⇄</code> mutual, <code>→</code> you trust them, <code>·</code> neither. Trust, compare and remove are one key from the timeline. The keyring is a screen of the same app.</td>
<td>Fits</td>
</tr>
<tr>
<td class="n">02</td>
<td><strong>A copy box on every shared service</strong></td>
<td>Ready commands in the viewer's own aliases: <code>ssh rob@nas-ssh.nas.family.vox</code>, a <code>vox forward</code> pair, an <code>~/.ssh/config</code> block, a browser URL. A "needs" line under each (vox up, node attached, nas trusts you, nas online). OSC 52 copy, and the text is always printed too.</td>
<td>Fits<br />
Kind: Q13</td>
</tr>
<tr>
<td class="n">03</td>
<td><strong>One-step sharing</strong></td>
<td>Detects listening ports with process names and suggests a name. Previews the address and names who can and can't reach it. Loopback by default; warns about 0.0.0.0 and sensitive ports. One list and one stop for all your shares.</td>
<td>Fits</td>
</tr>
<tr>
<td class="n">04</td>
<td><strong>Attaching a file just works</strong></td>
<td>Drop, paste or <code>:attach</code>. Share, hash and announcement happen behind the scenes. Auto-pulls from trusted members within size rules. Images show inline (kitty → iTerm2 → sixel → half-blocks) only after the hash checks. Stops being served when the message expires.</td>
<td>Mostly<br />
Q14, Q15</td>
</tr>
<tr>
<td class="n">05</td>
<td><strong>Rooms as task spaces with a visible lifecycle</strong></td>
<td>Create gives an invite card and advice on sending the passphrase. Join shows a who-reads-whom checklist. Retention is always visible. Leave and end state what they will do before acting.</td>
<td>Fits</td>
</tr>
<tr>
<td class="n">06</td>
<td><strong>Unread levels and a jump key</strong></td>
<td>TO YOU (from <code>to</code>), new, and coordination traffic shown only as a count. <kbd>⌥a</kbd> jumps to the next room with something addressed to you.</td>
<td>Fits</td>
</tr>
<tr>
<td class="n">07</td>
<td><strong>Honest live state</strong></td>
<td>Each peer shows its path: <code>direct 9ms</code> or <code>relayed via nas 84ms</code>. Each sent row shows <code>◌ on this machine</code> or <code>◑ on 2 of 3 nodes</code>. Never "read".</td>
<td>Wording fits<br />
N of M: check</td>
</tr>
<tr>
<td class="n">08</td>
<td><strong>Fingerprints that are bearable to compare</strong></td>
<td>Scan or paste first. Groups of 4 plus art; an optional word form. Separate "match" and "doesn't match" verbs. Never pick-from-a-list.</td>
<td>Fits</td>
</tr>
<tr>
<td class="n">09</td>
<td><strong>Visible unlock state</strong></td>
<td>Status bar and menu bar show <code>rob ● attached · keyring open 23m</code>. gpg-agent's model, made visible; gpg-agent's own cache state is invisible.</td>
<td>Fits</td>
</tr>
<tr>
<td class="n">10</td>
<td><strong>The "Enlightenment for 2035" look</strong></td>
<td>Warm near-black and off-white; one ice glow accent used only for focus and "live"; trust shown by glyph and weight, never by the accent; native glass only on the macOS navigation layer.</td>
<td>Fits</td>
</tr>
</tbody>
</table>

**Runners-up**, all fitting: a "speaking as rob ▸" marker in the composer; one-level quote-reply on `re`; a timeline line when retention changes; mute a room for a set time; local search that says what it could not search.

2 · Keyring, rooms and services together

## One experience

### There are no contacts. The keyring replaces them.

ADR-001 and ADR-014 3.4: no contacts tier and no 1:1 path; a direct message is a two-member room. The keyring is the set of nodes *you* trust: one direction, by fingerprint, each with your own alias (ADR-020 §3). Trust decides whose sender keys you accept, who can read what you post, and who can reach your services in rooms you share (G-18). You reach anyone only through a room you share.

| Familiar pattern | In Vox |
|----|----|
| Add contact | `vox trust add <fp> --name ann`. Grants read and service reach in every shared room, now and later. It does not let you reach Ann; a room does that. |
| Contact list | `vox trust list` and the TUI Keyring screen. Answers "who I trust", not "who I can reach". |
| Contact card | A keyring card: alias, full fingerprint (grouped, art, QR), rooms shared, services they share with you, both trust directions. |
| Display name set by the person | Impossible. Names are only your aliases; an untrusted node has no name. It can *say* who it is in text, and Vox never turns that into a name. |
| Start a chat | Create a two-member room and invite. |
| Block | `vox trust remove`, and leave the room if needed. G-21 removes per-room opt-outs; ADR-015 7.3 still plans a Block (Q2). |
| "X joined Signal" | Nothing; there is no directory. The nearest thing is "K2M9… joined family" inside a room. |
| Safety number changed | Cannot happen. One identity per device: a new key is a new node, and it is not in your keyring. |
| Verified badge | Being in your keyring (unless Q1 adds a second state). |
| Contact sync, discovery, usernames | Breaks the model |

### Rooms and services are Vox-native

#### A room

- lives only on its members' nodes, made per task;
- members come and go;
- leave deletes it on that node; end deletes it on every node (RL-8);
- has an id, an alias per member, a link plus a separately sent passphrase, retention set by the creator or an admin, and forward-only history.

#### A service

- is shared *by* a node *with* a room;
- is reached as service.node.room.vox in the viewer's own aliases;
- loses its live sessions at once when withdrawn or when the member is untrusted (ADR-017 §10).

### What maps from the closest analogues

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th>Product</th>
<th>Maps</th>
<th>Must not</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Syncthing</strong><br />
the closest</td>
<td>Device ID ≈ fingerprint; "Add Remote Device" on both sides ≈ mutual trust; a folder shared with chosen devices ≈ a service shared with a room; offer prompts that name who and what; "Disconnected (Inactive), Last Seen".</td>
<td>Introducers (transitive; they re-add removed devices); auto-accept.</td>
</tr>
<tr>
<td><strong>Tailscale</strong></td>
<td>MagicDNS ≈ .vox names; full names for shared machines ≈ viewer-alias addresses; quarantine by default ≈ reach only through trust; Serve's 4-line output (who, where, what, how to stop); "Access revoked"; "offline, last seen 2d ago".</td>
<td>Admin console, ACL files, accounts, a coordination server.</td>
</tr>
<tr>
<td><strong>ngrok, Cloudflare quick tunnel</strong></td>
<td>The one-line share; the <code>Forwarding X -&gt; Y</code> line; Cloudflare's guest list that "never leaves your machine".</td>
<td>Public by default; hostnames that change each run; values buried in log lines.</td>
</tr>
<tr>
<td><strong>ZeroTier</strong></td>
<td>Plain status words (ACCESS_DENIED).</td>
<td>Admin authorisation per network.</td>
</tr>
<tr>
<td><strong>Keybase teams, KBFS</strong></td>
<td>Removal is one verb and key rotation is invisible (like G-19).</td>
<td>Roles, subteams, a server.</td>
</tr>
<tr>
<td><strong>Slack Connect</strong></td>
<td>Showing who belongs to which side.</td>
<td>Org ownership of a channel.</td>
</tr>
<tr>
<td><strong>Discord</strong></td>
<td>Nothing.</td>
<td>The eight-layer permission matrix.</td>
</tr>
</tbody>
</table>

### Rules for the combined design

1.  **One noun per thing, everywhere:** room, node, keyring, service, address. Never "channel" or "contact". The TUI title still says "Channels" and should change.
2.  **Every name is a lens over a fingerprint.** Your alias, or else the fingerprint chip: in the timeline, member pane, service addresses, copy commands, notifications and search.
3.  **Trust is acted on where it matters:** the first message from an untrusted node, a join, a service you can't reach because the sharer doesn't trust you, a file that won't auto-fetch. All use the same t trust and v compare.
4.  **Every consequence is stated in words before the act.** Trusting names the rooms and services it covers; untrusting names what stops, what was already read, and which live sessions are cut.
5.  **Amber means it needs you. Everything else stays quiet.** The accent glow means only focus or "live".

2.4 · Proposed output · lines starting with \# are notes

## The flows, as you would see them

F1First run

\$ vox\
VOX — NEW NODE\
This node lives only on this machine. Lose the machine, make a new node;\
the people who trust you remove the old one. There is no recovery.\
Name for this node (local only): rob\
Passphrase (optional, asked once when the node starts): ••••••\
Node rob ready.   Next: send your fingerprint to the people you'll talk to  →  vox id

F2Swap fingerprints · stdout stays pipe-safe; the rest goes to stderr on a terminal

\$ vox id\
7QF4M2PAK2M9Q7RT…                       \# stdout: the 52 chars, one line\
NODE rob · fingerprint (send this; it is not secret)\
  7QF4 M2PA K2M9 Q7RT X3BD 9HNE WQ4C ZT7L 2MV8 KD5S PA6R 3JGY ND\
  \[fingerprint art\]   \[QR: vox id --qr\]\
  Compare by scanning or pasting, not by eye: vox trust add reads both.

F3Trust · the direction is said at the act (G-13)

\$ vox trust add 7QF4M2PA…ND --name ann\
TRUST ann (7QF4·M2PA)\
  ann reads what you post in every room you share — now 2 (family, taxes-2026), and any later.\
  you read ann once ann trusts you too.\
  ann can reach the services you share in those rooms: nas-ssh (family).\
  Keyring changes need your passphrase after 30 min idle: open for 23 more min.

In the TUI, t on an untrusted author runs the same flow, preferring a paste or a scan. `vox trust add` should accept only a whole fingerprint: short IDs were the PGP disaster (Evil32).

F4Create a room for a task

\$ vox room create taxes-2026\
ROOM taxes-2026 · created · retention forever · you are its creator\
INVITE  vox://4H…   (copied)              \[QR: vox room invite taxes-2026 --qr\]\
  Send the link one way (a text). Say the passphrase another way (a call).\
  Passphrase: none set — anyone with the link can join, but reads nothing until trusted.

F5Join, with a who-reads-whom checklist

\$ vox connect vox://4H… --name taxes\
JOINED taxes · 2 members\
  ann  ⇄  you trust ann · ann trusts you — you read each other\
  bea  →  you trust bea · bea hasn't trusted you yet — you can't read bea\
  K2M9·Q7RT  ·  not in your keyring — it can't read you; you don't read it\
hint: vox trust add K2M9Q7RT… --name \<name\>   (compare first: vox trust show K2M9 --qr)

F6First message from an untrusted node (TUI)

18:11  K2M9·Q7RT  ·  hi, it's Carl's new laptop\
       ▲ NOT IN YOUR KEYRING — Vox does not know who this is   \[v\] compare  \[t\] trust  \[?\]

v opens scan, paste, or read the groups aloud, then "match" or "doesn't match". "Doesn't match" says: "Don't trust it. Ask Carl for his fingerprint again, in person or by phone."

F7Share a service (the sharer)

\$ vox serve                                    \# no args: offer what's running\
LISTENING ON THIS MACHINE\
  1  22    sshd           127.0.0.1, ::1        suggest: ssh\
  2  8080  python3        0.0.0.0  ▲ also open on your LAN, outside Vox\
  3  32400 Plex Media Srv 0.0.0.0  ▲\
  4  5432  postgres       127.0.0.1  ▲ database port — share only if you mean it\
pick: 1   name \[ssh\]: nas-ssh   room \[family\]: ⏎\
SHARE nas-ssh → 127.0.0.1:22 in family\
  members reach it as   nas-ssh.\<your alias\>.\<their alias for family\>.vox\
  can reach (you trust them):   ann, bea\
  cannot (not in your keyring): K2M9·Q7RT\
  confirm? \[y/N\] y\
SHARED nas-ssh in family · stop: vox service remove family nas-ssh

The scripted form stays `vox serve nas-ssh=22` and prints the same can-reach block. `vox service list --mine` lists your shares across rooms. Removing a share cuts live sessions and says so: "cut 1 live session (ann, ssh, 14 min)". Detection is local: `lsof -iTCP -sTCP:LISTEN` on macOS, `ss -ltnp` on Linux.

F8Reach a service (a member)

\$ vox service list family\
SHARED IN family\
  nas-ssh  tcp  by nas  ● online direct 9ms   you can reach it\
  plex     tcp  by bea  ○ offline, seen 2h     bea is offline — try later\
\$ vox service use nas-ssh.nas.family          \# proposed helper; prints the copy box\
USE nas-ssh  (ssh, guessed from the name)\
  \[1\] ssh rob@nas-ssh.nas.family.vox\
        needs: vox up ● · node attached ✓ · nas trusts you ✓ · nas online ✓\
  \[2\] vox forward nas-ssh.nas.family.vox 127.0.0.1:2222\
      ssh -p 2222 rob@localhost\
  \[3\] ~/.ssh/config  (after the Host \*.vox block vox up prints, once)\
      Host nas\
        HostName nas-ssh.nas.family.vox\
        User rob

- **What's missing turns red, with the fix:** "vox up ✕ — run vox up (or have the daemon keep it up, Q16)".
- **"nas trusts you" is computed locally:** you can read nas's messages only if nas released its key to you.
- **Commands adapt to the kind:** ssh → ssh, mosh, rsync -e ssh, scp; web → `http://web.nas.family.vox` through the proxy, or a `vox forward` pair and `open http://localhost:8080`; udp → a UDP forward, plus a WireGuard `Endpoint =` line when the name says wg. Kind is guessed from the name today; a declared kind is Q13.
- **Copying:** only the command goes to stdout with `--form ssh`, so agents can capture it; it is also sent with OSC 52 and always printed; "\[copied\]" shows only when the sequence was really sent; the clipboard is never read.

F9Share a file or image

- Drop or paste a file in the TUI, or `:attach ~/Pictures/IMG_2041.jpg`.
- Confirm: "Share IMG_2041.jpg (3.1 MB) with family? Available while this node runs, until the message expires. \[⏎\]"
- Behind it: hash, a room-bound share, then the announcement (name, size, SHA-256, plus a BlurHash and dimensions).
- Members who trust you auto-pull it within their size rules and see it inline once verified. Everyone else sees a card.

F10Untrust

\$ vox trust remove bea\
REMOVE bea (9HNE·WQ4C) from your keyring?\
  bea stops reading what you post next, in 2 rooms (family, taxes-2026). bea keeps what she read.\
  you stop reading bea.\
  bea loses reach now to: nas-ssh (family) — cuts 1 live session.\
  type bea to confirm, then your passphrase (keyring window expired): …\
DONE · new sender key in 2 rooms · 1 session cut (bea was told: "access withdrawn by rob")

F11Tear down

\$ vox room leave taxes-2026\
LEAVE taxes-2026: deletes the room from this node once another member hears it.\
  your shares in it stop now: none. Your trust in its members is unchanged.\
\$ vox room end taxes-2026          \# creator/admin only\
END taxes-2026 FOR EVERYONE: every member's node deletes it. Services shared in it stop.

3 · GPG Keychain, Kleopatra, Seahorse, OpenKeychain, sq, Keybase, age, gpg-agent

## Keyring and trust management

#### Two trust axes confuse people

PGPkeys showed separate Validity and Trust columns; Whitten & Tygar (1999) warned the two words mean different things in everyday speech. GPGTools still explains that ownertrust "will not affect the validity". Kleopatra's row colours mix compliance with certification. **For Vox: exactly one concept, "in my keyring".**

#### Seahorse speaks in the first person

"I have verified that this key belongs to who it says it does." Vox should do the same: "ann reads what you post…".

#### OpenKeychain's local "Confirm key"

Two buttons of equal weight, "✓ PHRASES MATCH" and "✗ DOESN'T MATCH". A QR of the full fingerprint only. An explicit "remember" option with durations, added after silent passphrase caching confused users.

#### Sequoia sq 1.0

Local links from an implicit trust root, plus petnames; an (UNAUTHENTICATED) tag next to the name; refusals that print the exact next command. The path view explains why a key is trusted; Vox's version is one line: "in your keyring since …". `--temporary` trust that decays is Q17.

#### gpg-agent and pinentry

Sliding 600 s cache, 7200 s max, and no way to see whether a key is cached short of `gpg-connect-agent 'keyinfo --list'`. pinentry-mac's "Save in Keychain" silently bypasses the TTL. Headless signing fails with "Inappropriate ioctl for device". **For Vox:** always show "keyring open 23m", name the 30-minute window in the prompt, fail in plain words with no terminal, and Keychain storage is Q18.

#### Comparing fingerprints (studies)

Dechand et al. 2016 (1,047 participants), attacks missed: hex 10.4%, numeric 6.3%, words 5.8%, sentences 3.0%. Tan et al. 2017 under habituation: sentences 6%, randomart 10%, hex 21%, numbers 35%, compare-and-select 72%. Their advice: scan with a camera. **For Vox:** scan or paste first; groups of 4 plus art; never pick-from-a-list; a word form is Q19.

**What users get wrong elsewhere:** encrypting to the wrong key (7 of 12 in Whitten & Tygar; 7 of 10 pairs in Ruoti 2015); short key IDs; never making a revocation certificate; key expiry; 2019 keyserver poisoning; ticking "I have verified" without comparing. Vox avoids most by construction: no keyservers, no expiry, no publication. It must still guard against short IDs and rubber-stamp checkboxes. Revocation is already automatic: `vox trust remove` rotates keys (G-19).

### Mapped to Vox

| Where | Proposal |
|----|----|
| `vox id` | Fingerprint alone on stdout. On a terminal: groups, art, `--qr`, and "send this; it is not secret". |
| `vox trust add` | Whole fingerprint or QR payload only; asks for the alias if `--name` is missing (built); states scope and direction (F3); prints a hint with no args. |
| `vox trust list` | NAME · FINGERPRINT (short + art) · ROOMS SHARED · YOU READ · READS YOU · SHARES TO YOU; `--json` for agents. |
| `vox trust show <name>` | New, small: full fingerprint, QR and words, for comparing again. |
| `vox trust remove` | Shows consequences, asks you to type the alias, reports the sessions cut (F10). |
| `vox trust rename` | Built. Keep it saying "grants nothing". |
| TUI member pane | The `⇄ → ·` glyph, the built label words ("trusted · reads you"), path and latency, t v x. |
| TUI Keyring screen k | The trust-list table plus a card for the selected node. |
| Status bar, menu bar | `rob ● attached · keyring open 23m`; after the window: "keyring closed — trust changes ask for passphrase". |

4 · Reaching and sharing

## Services

### Patterns to adopt

- **Output answers who, where, what and how to stop.** Tailscale Serve: "Available within your tailnet … Press Ctrl+C to exit".
- **Print the command the other person types.** macOS Remote Login shows `ssh steve@10.1.2.3`; GitHub's clone box has HTTPS / SSH / CLI tabs; ngrok prints `Forwarding X -> Y`.
- **Only the copyable thing on stdout.** Vercel: "stdout is always the Deployment URL".
- **Show the missing piece in place, with its fix.** GitHub's "You don't have any public SSH keys…" inside the SSH tab; ZeroTier's ACCESS_DENIED.
- **Generate ssh config; don't touch DNS.** Teleport, Cloudflare and VS Code all do. `vox up` already prints a `Host *.vox` block and deliberately doesn't write `~/.ssh/config` (tunnel_cli.rs). Keep that: offer the block for copying; verify with `ssh -G nas`.
- **OSC 52 copy with a printed fallback.** It can fail silently (tmux's `set-clipboard`, iTerm2's setting). lazygit falls back from tmux to OSC 52. Never read the clipboard.
- **Name the revocation:** Tailscale says "Access revoked"; ADR-017 10.2 already has `vox up` say access was withdrawn and there is nothing to retry.
- **Copy the name, not the IP** (Tailscale issues \#15131, \#16147).

### Sharer safety

- `python -m http.server` and Docker `-p` bind every interface, and Docker bypasses ufw, so the share flow should name what is already open on the LAN outside Vox.
- VS Code's silent auto-forwarding drew complaints ("Over 20 ports have been automatically forwarded"). Detection only offers; it never shares by itself.
- Vox has one audience, the trusted members of that room, so name them every time.

**Do not copy:** public links, admin ACL files, per-service grants (withdrawn in ADR-017), Syncthing introducers, Discord's permission matrix.

5 · Automatic, pull model, honest

## Files, images and media

1.  **Sending.** Drop, paste, `:attach` or the macOS share sheet, then one confirm. The node hashes the file, starts the room-bound share (the content hash already sets the port and tag, ADR-020 11.6) and posts the announcement: name, size, SHA-256, MIME type, and for images a BlurHash plus dimensions. The daemon holds the share until the message expires, the sharer stops it, or the node detaches; the card says which. Today `vox share` runs in the foreground; changing that is Q14.
2.  **Receiving.** Auto-pull only from members in *your* keyring, within local rules: images up to 10 MB pull automatically, other files ask, with a per-room override. Others get a card and nothing is fetched: "not fetched: not in your keyring".
3.  **Honest availability.** "bea ○ offline — not available yet; fetches when bea is back". Also "offer withdrawn" and "expired" (ADR-020 11.8).
4.  **Integrity and placement.** Download to a hidden `.part`, checked per chunk and whole (ADR-020 11.4–11.5); rename only when the hash matches. Show "✓ sha256 9f2c…e01a verified · saved ~/Downloads/vox/family/IMG_2041.jpg". Never overwrite; add " (1)" (built). Resume interrupted pulls; progress counts verified bytes.
5.  **Inline images in the TUI.** ratatui-image's query-based picker: kitty (and Ghostty), iTerm2 (WezTerm, Warp), sixel (foot, xterm, Windows Terminal 1.22+), then half-blocks. kitty Unicode placeholders under tmux; a config override as iamb has; thumbnails sized to cells over SSH; the BlurHash as half-blocks before the pull, which works while the sharer is offline. An image shows only after its hash passes.
6.  **macOS.** Quick Look on verified files, drag in and out, a "Share to Vox room" extension, a Services menu item.
7.  **Retention.** When the message expires, the sharer stops serving and receivers delete their copy and thumbnail (Keybase's "deleting the body kills the file", applied to the pull model). Say that a copy you moved elsewhere is yours.
8.  **Large files, folders, several rooms.** Folders become one deterministic tar (built); two rooms means two announcements but one hash pass; no size cap (10 MB caps push people to outside links).
9.  **An in-message thumbnail ≤ 16 KB** would show while the sharer is offline, but ADR-020 11.1 keeps file bytes out of the log: Q15. A ~30-character BlurHash fits today.

**Avoid:** server attachments with silent expiry (Signal's 45 days, Slack's 90-day hiding); trusting the sender's thumbnail; heavy recompression; view-once or screenshot claims.

6 · Condensed from the first pass

## Chat areas

#### Onboarding

State there is no recovery (as Briar and Threema do). One word for the identity (Q3). The first screen is the J-1 checklist. Backup first, or dropped (Q4).

#### Invites

Advice on sending the passphrase; QR and text together; join failures in plain sentences that never guess the cause (J-17). No approval, knocking or username directory. Link expiry is Q5.

#### Room list

Three unread levels; ⌥a and ^k to jump. Mute for a set time with direct rows breaking through. A notify level per room. Counts must never lie (Element's stuck-unread bugs).

#### Threads

One-level quote-reply on `re`; Enter jumps to the original. No "also send to channel", no thread pane, no required topics.

#### Mentions

Tab-complete aliases; write the whole fingerprint to `to`. Colour from the fingerprint hash, always paired with text. Lookalike aliases get a fingerprint suffix (Matrix does this "to prevent spoofing").

#### Delivery

"◌ only on this machine"; "◑ on N of M nodes" only if computable (RL-4.7's `seen` hints it is). No "read", no typing indicators (Q6). Path and latency shown.

#### Retention

A timeline line: "Rob set messages to disappear after 1 week. Older messages were removed from this machine." ⏱ in the header. Honest copy: "A changed Vox, or a screenshot, can keep them."

#### Search

Local operators: from:, in:, to:me, before:. A footer says what was not searched. The index is pruned with the rows.

#### Several nodes on one machine

"rob ▸" in the composer, in that node's colour; per-node "to you" counts. Posting as an agent's node is Q7 (the Red Cross 2011 tweet is the warning).

#### Agents

Your alias is the badge: suggest "claude·mbp (agent)" at trust time (ADR-020 10.2). Proven name at full strength; claimed context dimmed. Coordination folds into one line. Never a bot flag or a sender-chosen name.

#### Errors

Three kinds: waiting (grey), blocked by trust (amber, with an action), broken (vermilion, with cause and action). "\[locked — not shared with you\]" becomes "\[not shared with you: ann hasn't trusted you\]".

#### TUI conventions

Hotlist, read marker, day separators, `[late]`; a smart filter for here/left; a multi-line composer that keeps a paste together; trust verbs like iamb's `:verify mismatch`. Keep the TUI first-class.

Calls (v0.4.0): drop-in rather than ringing, shown as "ann is in a call · \[j\]oin". That is Q10.

7 · Enlightenment, redone for 2035

## Look and feel

### Rules, first

1.  **Real information, shown beautifully, never decoration:** live latency; the path (direct, or relayed via whom); fingerprints as art; crypto state stated exactly ("hybrid X25519+ML-KEM-768 · Ed25519+ML-DSA"); bytes verified.
2.  **No hacker clichés:** no code rain, no "ACCESS GRANTED", no fake hex scroll, no glitch, above all never on security state. Mastery, not cosplay.
3.  **Instant response.** The next frame renders after every keypress; animation never blocks input; the TUI animates at most 3 frames (~50 ms); motion turns off over SSH, on slow links, with NO_MOTION or Reduce Motion.
4.  **One luminous accent**, meaning only "focus" or "live", never trust, danger or decoration. Enlightenment's grammar: focus is the glow.
5.  **The glow is earned:** it brightens only on a real event (a peer connects, a key arrives, a transfer verifies, a share goes live).
6.  **Typographic precision:** mono for data in aligned columns with tabular numbers; uppercase letter-spaced eyebrows (VOX — FAMILY); hairlines, not boxes; three greys of text.
7.  **Density with hierarchy**, as in btop, k9s and lazygit. ? shows the keys that apply right now.
8.  **Honesty over theatre.** Security in words; no decorative padlocks. The state that matters is whether a node is in your keyring.
9.  **Small delights for experts:** a soft glow when a peer connects; fingerprint art you learn to recognise; at most one first-launch intro, the mark assembling from your own fingerprint's facets, under 2 s, skippable, never shown again.
10. **Accessible by construction:** never colour alone (a glyph plus a word for every state); NO_COLOR, a 16-colour fallback and a linear screen-reader view; Increase Contrast, Reduce Transparency, Reduce Motion; WCAG AA minimum, AAA for body text.

### The north star

#### What Enlightenment was

E16 (1999) and E17 (2012) on EFL and Edje. Dark, polished panels with a blue-white focus glow (the EFL theme's `:selected` is \#3399FF at alpha 25/128/192, with a warm `#FFDCA0` light-glow). Compositing early; a shelf with gadgets; themes as data; Edje's spring and Bézier transitions. Rasterman himself retired the "gold bling".

#### What Vox keeps

**Focus glow**: a 1 px luminous edge plus a soft halo in the app; a heavy accent rule on the focused TUI pane. **Polished dark depth**: layered warm surfaces, a 1 px specular top highlight. **Fluid motion**: critically damped springs of 160–220 ms, no bounce, every cue tied to a real event. **Glass** on the navigation layer only. **Theme as data**: one token file feeds the TUI and the Swift asset catalogue. **Shelf → status bar and menu bar extra.**

#### What Vox drops

Bevels, metal, gold, noise, bounce, and chrome built to show off the engine.

#### Fused with your reference

hf2q's warm near-black and off-white, the mono eyebrow over a heavy, tightly kerned grotesk, a sharp faceted mark, generous space and hairlines, plus one layer of gloss. The demoscene line governs it: "impossibly much from very little."

### Palette

Contrast is the WCAG ratio against \#0c0d0f. "256" is the nearest xterm index; "16" is the fallback slot. This page is drawn in it.

| Token | Hex | Contrast | 256 | 16 |
|----|----|----|----|----|
| bg.base | \#0c0d0f | — | 233 | — |
| bg.raised | \#131417 | — | — | — |
| bg.panel | \#16171a | — | 234 | — |
| bg.overlay | \#1c1d21 | — | — | — |
| line.hair | \#26272b | 1.3, decorative | 235 | bright black |
| text.primary | \#f0ece4 | 16.5 | 255 | — |
| text.secondary | \#a8a299 | 7.7 | 247 | — |
| text.muted | \#85807a | 5.0 | 244 | bright black |
| attention ▲ | \#f2b33d | 10.5 | 215 | yellow |
| danger ✕ | \#ff5f3a | 6.4 | 203 | bright red |
| waiting ◌ | text.secondary | 7.7 | — | — |

**Trusted** is text.primary in bold with ⇄ or ◆; **not trusted** is text.secondary with · or ◇ and the words "not in keyring". Trust is shown by glyph and weight, never by hue, which keeps it colour-blind safe and away from the accent. Amber and vermilion can look alike to deuteranopes, so ▲ and ✕ and the words carry the difference. On macOS, draw content on \#0c0d0f, not the system \#1e1e1e.

### Accent options

#### Glowline · Ice

Enlightenment's own glow, cooled and made precise. Maps cleanly to cyan; clear of amber and vermilion (the Okabe-Ito-safe pair); passes AAA.

\#5ec8ff · hover \#8fdbff · deep \#2fa8f0 · 10.4:1 · 256:81 · 16: bright cyan

#### Ember · Copper

Your reference: warm and editorial. Sits near the attention amber; shares 256 index 167 with red; falls back to yellow in 16 colours. Keep it as a brand warm for the mark, not in the UI.

\#d2693a · hover \#e8875a · deep \#b4552b · 5.4:1 (AA) · 256:167

#### Redline · Signal red

Confident, but it shouts, and it collides directly with danger.

\#e5484d · hover \#ff6b6f · deep \#c43a3f · 5.0:1 · 256:167 · 16: red

### Type, glyphs, art and the mark

#### Type

**App:** body SF Pro Text; headings and empty states Inter Display 800–900 at −2% tracking, bundled (SIL OFL 1.1); mono SF Mono via `monospacedSystemFont` (not bundled; SF may not be embedded off Apple platforms). Alternatives: Söhne (Klim, paid) or Geist Sans/Mono (OFL).\
**TUI:** the user's terminal font; docs recommend JetBrains Mono, Geist Mono or Commit Mono (OFL). Don't ship Berkeley Mono: its licence restricts embedding.

#### Glyphs (Unicode → ASCII)

⇄ \<\> mutual · → -\> you trust · · . not in keyring · ✕ x removed · ● ◐ ○ / \* ~ o online, partial, offline · ◌ ◑ / . : this machine, some nodes · ▲ ✕ / ! X attention, broken · ✓ ok · ⏱ ttl · ▤ ▣ / \[f\] \[i\] file, image

Nerd Font icons optional. No decorative locks.

#### Fingerprint art

A 5×5 facet mosaic of split triangles driven by the fingerprint bytes, in the mark's grammar: light faces text.primary, dark faces bg.overlay, one accent facet only on your own node. Octant or half-block characters, falling back to ssh-style randomart. Recognition only: grouped text plus scan or paste always sits beside it.

#### The Vox mark

A faceted V of five sharp planes, like a cut gem seen from above; the arms are blades narrowing to the vertex. At the vertex a small triangle is cut out, with one glint in the accent: *vox lux*, "voice of light". Off-white planes on warm black, no outline, no animal. The node mosaics use the same triangles, so the brand and every identity share one grammar. (The header mark on this page is a sketch of it.)

### TUI mockups

┃, TO YOU and focused borders are ice; ▲ lines are amber; `[late]` is muted.

ARoom list

 VOX — ROOMS                                  rob ● attached · keyring open 23m · 3 nodes on this machine\
 ─────────────────────────────────────────────────────────────────────────────────────────────────────────\
 ┃ family          ⇄3/3  ● direct 9ms ▁▂▁▃     ⏱ forever     2 TO YOU\
   taxes-2026      →1/2  ● relayed nas 84ms     ⏱ 1 week      new\
   build-vox       ⇄5/5  ● direct 3ms           ⏱ forever     · 41 coordination\
   nas             ⇄1/1  ○ seen 2h ago          ⏱ forever\
 ─────────────────────────────────────────────────────────────────────────────────────────────────────────\
 SHARED TO YOU   nas-ssh.nas.family.vox  ·  web.nas.family.vox  ·  plex.bea.family.vox ○\
 MY SHARES       nas-ssh → 127.0.0.1:22 in family (2 can reach)\
 ─────────────────────────────────────────────────────────────────────────────────────────────────────────\
 ⏎ open  ⌥a next to you  ^k jump  k keyring  s services  n new  j join  ? keys

BA room with members and trust

 VOX — FAMILY                          ⏱ forever · 4 members · you read 3 of 3 · as rob ▸\
 ─────────────────────────────────────────────────────────────┬──────────────────────────────────\
 ── TUE 3 OCT ─────────────────────────────────────────────── │ MEMBERS\
 18:02  ann    ⇄  dinner at 7?                                │ ⇄ ann        trusted · reads you\
 18:04  bea    ⇄  ↪ ann: dinner at 7?                         │    ● direct 9ms\
                  yes, bringing dessert                       │ ⇄ bea        trusted · reads you\
 18:05  you       sounds good                         ◑ 2/3   │    ● relayed via nas 84ms\
 ── unread ────────────────────────────────────────────────── │ → nas        trusted · can't read\
 18:11  K2M9·Q7RT ·  hi, it's Carl's new laptop               │    you yet (key on its way)\
        ▲ NOT IN YOUR KEYRING   \[v\] compare  \[t\] trust  \[?\]   │ · K2M9·Q7RT  ▚▞▚ not in keyring\
 18:12  ann    ⇄  \[late\] sent 18:06 · arrived 18:12           │    \[v\] compare  \[t\] trust\
                  gate code is in the nas share               │\
 ─────────────────────────────────────────────────────────────┴──────────────────────────────────\
 rob ▸ █                                                          ◌ stays on this machine until sent\
 ⏎ send  r reply  t trust  v compare  s services  ⇥ members  ⌥a next  esc back

CService pane with copy commands

 VOX — FAMILY — SERVICES                               as rob ▸ · vox up ● 127.0.0.1:1080\
 ──────────────────────────────────────────────────────────────────────────────────────────\
 SHARED IN THIS ROOM\
 ┃ nas-ssh   tcp  by nas   ● direct 9ms     you can reach it · nas trusts you\
   web       tcp  by nas   ● direct 9ms     you can reach it\
   plex      tcp  by bea   ○ seen 2h ago    bea is offline — try later\
   dns       udp  by you   → 127.0.0.1:53   ann, bea can reach · K2M9·Q7RT cannot\
 ──────────────────────────────────────────────────────────────────────────────────────────\
 USE nas-ssh                                     \[1\] ssh   \[2\] forward   \[3\] ssh config\
   ssh rob@nas-ssh.nas.family.vox                                         ⏎ copied ✓\
   needs  vox up ✓   node attached ✓   nas trusts you ✓   nas online ✓\
 ──────────────────────────────────────────────────────────────────────────────────────────\
 ⏎ copy  1-3 form  a share a service  x stop sharing (yours)  esc back

DA file share with an inline image

 18:20  bea    ⇄  ┌────────────────────────────┐\
                  │▀▀▄▄▀▀▀▄▄▄▀▀▀▀▄▄▄▀▀▄▄▀▀▀▄▄▄▀│   ← kitty/iTerm2/sixel image here;\
                  │▄▀▀▀▄▄▄▀▀▀▀▄▄▀▀▀▄▄▄▀▀▀▄▄▀▀▀│     half-blocks elsewhere\
                  └────────────────────────────┘\
                  ▣ IMG_2041.jpg · 3.1 MB · 4032×3024\
                  ✓ sha256 9f2c…e01a verified · ~/Downloads/vox/family/IMG_2041.jpg\
 18:21  nas    ⇄  ▤ backup-2026-10.tar · 41.2 GB · nas ● direct\
                  ▕██████████████▌            ▏ 52% verified · 18.4 MB/s · resumes · \[p\] pause\
 18:22  K2M9·Q7RT · ▤ invoice.pdf · 220 KB · not fetched: not in your keyring   \[t\] trust first\
 18:23  ann    ⇄  ▣ cake.mov · 88 MB · ann ○ offline — not available yet; fetches when ann is back

EKeyring

 VOX — KEYRING                           rob · 7QF4·M2PA · keyring open 23m, then passphrase\
 ─────────────────────────────────────────────────────────────────────────────────────────────\
 NAME                 FINGERPRINT        ROOMS  YOU READ  READS YOU  SHARES TO YOU\
 ┃ ann       ▚▞▚      A1B2·C3D4          3      ✓         ✓          —\
   bea       ▞▚▞      9HNE·WQ4C          2      ✓         ✓          plex\
   nas       ▚▚▞      ZT7L·2MV8          2      ✓         ✓          nas-ssh, web\
   claude·mbp (agent) KD5S·PA6R          1      ✓         ✓          —\
 ─────────────────────────────────────────────────────────────────────────────────────────────\
 ann        ▚▞▚▞▚     A1B2 C3D4 E5F6 G7H8 J9K0 L1M2 N3P4 Q5R6 S7T8 U9V0 W1X2 Y3Z4 56\
            ▞▚▞▚▞     rooms: family · taxes-2026 · build-vox\
            ▚▞▚▞▚     path: ● direct 9ms · crypto: X25519+ML-KEM · Ed25519+ML-DSA\
 ⏎ card  a add (paste/scan)  q QR  c copy  r rename  x remove…  esc back

7.9 · Input to ADR-014, which is still unsettled

## Native macOS

- **Window:** three columns. Rooms on an `NSVisualEffectView` sidebar material (or Liquid Glass on macOS 26); the timeline on opaque \#0c0d0f; an inspector with the member or keyring card and the services list with copy buttons.
- **Materials:** no glass in the content layer (per the HIG). `glassEffect(.regular.tint(ice))` only on the primary action. Hierarchical foreground styles; a custom foreground colour kills vibrancy.
- **Menu bar extra** (`.window` style, opt-in per the HIG): node state and attach with passphrase; the keyring window; rooms with TO YOU counts; "Shared to me" with copy buttons; my shares with stop; tunnels; Check connection. Tailscale's 2025 split: menu for state, window for lists.
- **Command palette** ⌘K. Shortcuts: ⌘1–9 rooms, ⌘J next item to you, ⌘⇧C copy the service command, ⌘I my fingerprint, ⌘N new room, ⌘⇧J join, ⌘O attach.
- **Menus:** File (New Room, Join Room…, Attach File…, Share Service…); Room (Invite…, Retention…, Leave, End for Everyone…); Node (Attach/Detach, Show My Fingerprint); Keyring (Trust…, Compare…, Rename, Remove…).
- **Notifications:** grouped by room, previews hidden by default (ADR-014 9.2), inline reply; Time Sensitive only for urgent rows addressed to you.
- **Files:** Quick Look on verified files, a share extension, drag and drop, a Services menu item.
- **Accessibility:** VoiceOver reads state in words; respect Reduce Transparency, Reduce Motion and Increase Contrast.
- **Learn from:** Raycast (native glass popovers, an instant palette); Arc (a calm sidebar, identity per space); Linear (a three-input LCH theme, Inter Display, keyboard-first); Things ("each animation is purposeful"); Ghostty (AppKit/SwiftUI over a C-ABI core, exactly Vox's UniFFI shape). Craft and CleanShot were not researched.
- **Never Electron or Tauri** (ADR-014 1.2): the 1Password 8 backlash, and the 2025 Electron bug that lagged all of macOS 26.

8 · Breaks the model

## Must not borrow

1.  Linked devices, multi-device sync, cross-signing (ADR-014 3.6 already conflicts).
2.  TOFU or any automatic trust (ADR-020 3.9).
3.  Key transparency or keyservers.
4.  Web of trust, introducers, social proofs.
5.  Contacts, directories, usernames, "X joined".
6.  Bot, app or AI type flags.
7.  Names or avatars chosen by the sender.
8.  Per-room admission, knocking, approvals.
9.  Secrets inside links.
10. "Read" shown as fact.
11. APNs, third-party push, cloud backup.
12. Store-and-forward servers.
13. Room types.
14. Per-sender timers, "keep in chat", screenshot claims.
15. Nested threads, "also send to channel".
16. Permission matrices and roles.
17. Public share links.
18. Validity and owner-trust as two axes, or numeric trust amounts.
19. Compare-and-select checks, or short key IDs.
20. Electron or Tauri.
21. Hacker clichés.

9 · For the interview

## Open questions for the decider

1.  Is "in my keyring" the only trust state, or is there also "verified"?
    - A: `ann` vs `K2M9·Q7RT`. B: `ann ✓` (scanned in person) vs `ann` (pasted). Recommended: A.
2.  Should ADR-014 and ADR-015 drop consent prompts, Block, the per-room pseudonym and shared-root device sync, to match the keyring-only, one-device-one-node model? ("Block bea" becomes "Remove bea from your keyring".)
3.  One word for the identity: "fingerprint" (the CLI today) or "safety code" (ADR-014)?
4.  Backup: A, none ("lose the machine, make a new node"); or B, required before first use (ADR-015 5.4)?
5.  Should an invite link ever expire? For example `vox room invite taxes --for 1d`.
6.  What appears under your own message? A: `◑ on 2 of 3 nodes`, if honest to compute. B: "read by ann". C: nothing. Recommended: A, else C. This also settles ADR-020 3.10 vs 4.9a.
7.  Can the person post as an agent's node from the TUI (`:node claude-code-mbp`, then "stop")? Refuse, warn, or allow?
8.  May the UI say "K2M9… joined. ann trusts it."? It is information, not trust.
9.  Is a shared folder an ordinary service, or a built-in room folder (a new concept)?
10. Calls: show "ann is in a call · \[j\]oin" in the room, or only 1:1?
11. macOS: does your node keep running when the app quits (`--keep` on by default)? Is the menu bar icon opt-in?
12. Are mute and notify levels set per room, for the person's own view only?
13. May a share declare a kind (ssh, http, wg), so members get the right commands? A new field on the 0x0018 share statement; today the kind would be guessed from the name.
14. Should the daemon hold file shares until the message expires, instead of a foreground `vox share` with `--count`/`--for`?
15. May a thumbnail of 16 KB or less travel inside the encrypted message? ADR-020 11.1 says file bytes never enter the log.
16. Should the daemon keep the .vox proxy (`vox up`) running, so `ssh nas-ssh.nas.family.vox` always works?
17. Expiring trust for a guest, like `vox trust add … --for 1w`? A new concept.
18. May the macOS Keychain hold a node's passphrase? pinentry-mac's equivalent defeats its own TTL.
19. Should fingerprints have a spoken word form (PGP word list or sentences), or stay groups of 4 plus QR only?
20. Which accent: Ice (recommended), Copper or Signal red?

10 · Evidence

## Sources

**Strong:** GnuPG, GPGTools, Gpg4win, Seahorse, OpenKeychain, Sequoia, Keybase and Syncthing docs; Tailscale, Cloudflare, VS Code, Docker and Apple docs; the kitty and iTerm2 specs; the Dechand, Tan, Whitten & Tygar and Ruoti papers. **Thin:** Signal and WhatsApp settings (pages returned 403), ngrok v3 output, kitty's clipboard default, Raycast details, Berkeley Mono licence terms, Craft, CleanShot, AirDrop, Hak5. The research ran out of its shared web-search budget near the end.

#### Keyring

gpgtools.tenderapp.com/kb/faq/what-is-ownertrust-trust-levels-explained · gpgtools.tenderapp.com/kb/how-to/trusting-keys-and-why-this-signature-is-not-to-be-trusted · gpgtools.tenderapp.com/kb/faq/password-management · gnupg.com/kb/faq-user.html · gpg4win.org/doc/en/gpg4win-compendium_16.html · wiki.gnome.org/Apps/Seahorse/TrustModel · help.gnome.org/users/seahorse/stable/pgp-sign.html.en · github.com/open-keychain/open-keychain/wiki/QR-Codes · openkeychain.org/openkeychain-3-8 · sequoia-pgp.org/blog/2024/12/16/202412-sq-1.0/ · man.cx/sq-pki-link-add(1) · archive.fosdem.org/2025 (sq slides) · keybase.io/blog/keybase-new-key-model · github.com/FiloSottile/age · jedisct1.github.io/minisign · latacora.com/blog/2019/07/16/the-pgp-problem/ · gnupg.org/documentation/manuals/gnupg/Agent-Options.html · usenix.org/conference/usenixsecurity16/technical-sessions/presentation/dechand · joshktan.com/papers/chi17.pdf · people.eecs.berkeley.edu/~tygar/papers/Why_Johnny_Cant_Encrypt/USENIX.pdf · arxiv.org/pdf/1510.08555 · evil32.com · gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f · openssh.org/txt/release-5.1 · dirk-loss.de/sshvis/drunken_bishop.pdf

#### Services

tailscale.com/kb/1312/serve · tailscale.com/kb/1223/funnel · tailscale.com/kb/1084/sharing · tailscale.com/kb/1081/magicdns · tailscale.com/kb/1193/tailscale-ssh · tailscale.com/blog/windowed-macos-ui-beta · ngrok.com/docs/agent/web-inspection-interface/ · developers.cloudflare.com (trycloudflare; ssh-cloudflared-authentication) · blog.cloudflare.com/protected-quick-tunnels/ · goteleport.com/docs/enroll-resources/server-access/openssh/openssh-agentless/ · man.openbsd.org/ssh · code.visualstudio.com/docs/remote/ssh · code.visualstudio.com/docs/debugtest/port-forwarding · docs.github.com (cloning-a-repository) · vercel.com/docs/cli/deploy · docs.docker.com/engine/network/port-publishing/ · docs.python.org/3/library/http.server.html · support.apple.com/guide/mac-help/mchlp1066/mac · github.com/tmux/tmux/wiki/Clipboard · github.com/jesseduffield/lazygit/pull/5816 · docs.syncthing.net/users/config.html · docs.syncthing.net/users/introducer.html · docs.zerotier.com/cli · keybase.io/blog/introducing-keybase-teams · docs.discord.com/developers/topics/permissions

#### Files

signal.org/blog/backup-improvements/ · core.telegram.org/api/files · matrix-spec end_to_end_encryption.md · github.com/matrix-org/matrix-spec-proposals/pull/2448 · github.com/woltapp/blurhash · book.keybase.io/docs/chat/crypto · github.com/schollz/croc · github.com/localsend/protocol · support.apple.com/en-us/119857 · docs.onionshare.org/2.6/en/features.html · docs.syncthing.net/users/syncing.html · sw.kovidgoyal.net/kitty/graphics-protocol/ · iterm2.com/documentation-images.html · arewesixelyet.com · yazi-rs.github.io/docs/image-preview/ · github.com/benjajaja/ratatui-image · iamb.chat/configure.html · hpjansson.org/chafa/

#### Look and feel

enlightenment.org/about-enlightenment · enlightenment.org/develop/legacy/program_guide/edje_pg · EFL themes colorclasses.edc (github Enlightenment/efl) · tech.slashdot.org/story/12/10/31/1434212 · osnews.com/story/18886 · pouet.net/prod.php?which=30244 · fgiesen.wordpress.com/2012/04/08/metaprogramming-for-madmen/ · iquilezles.org/articles/function2009/function2009.pdf · github.com/charmbracelet/lipgloss · k9scli.io/topics/skins/ · github.com/aristocratos/btop · pentagram.com/work/oxide · linear.app/now/how-we-redesigned-the-linear-ui · raycast.com/blog/a-technical-deep-dive-into-the-new-raycast · warp.dev/blog/how-we-designed-themes-for-the-terminal-a-peek-into-our-process · ghostty.org/docs/about · developer.apple.com (NSVisualEffectView, Material, glassEffect, HIG materials, MenuBarExtra, fonts) · rsms.me/inter · klim.co.nz/retail-fonts/soehne · commitmono.com · github.com/githubnext/monaspace · github.com/termstandard/colors · no-color.org · jfly.uni-koeln.de/color · w3.org/TR/WCAG22

#### Vox (read-only)

Branch v030/rearch-tui at 355f6ffa: ADR-001, 005, 007, 014, 015, 017, 020, 023, 026; PRD-001; cli.rs, ui.rs, tunnel_cli.rs. First-pass sources (Signal, Element, Briar, Threema, Slack, Zulip, weechat, irssi, iamb, the Apple HIG) still apply.

Research only. Nothing in this report is built or decided; it is input to the decider's interview, the UX ADR and the rewrite of ADR-014.

