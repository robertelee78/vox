# Vox UX interview: the decider's answers (2026-10-03 PDT)

Answers to the open questions in [v040-ux-research.md](v040-ux-research.md). Input to the v0.4.0 UX ADR; where an answer supersedes an ADR line, the ADR is to be amended.


- **Q1 Trust states:** ONE state, "in my keyring". No separate "verified".
- **Q2 ADR-014/015 cleanup:** not a blind drop. Drop what Vox doesn't support, and REDO the rest in Vox terms. Block -> untrust (remove from your keyring). Room creator or admin can rename the room. Etc.
- **Q3 Identity word:** "fingerprint". Adding a fingerprint to my keyring lets me set an alias, and change it later. Messaging @alias auto-translates to the fingerprint at the comms/transport layer.
- **Q6 Under a sent message:** "read by ann" (B).
  - Read receipts: ALWAYS ON. Every node sends a small signed read record in the room when the message is actually seen. No opt-out. (New; supersedes ADR-020 4.9a "a node cannot see reads"; ADR-020 3.10 stands.)
  - Agent nodes: "read" = when its hook drains the message into the agent's turn. No agent/human distinction (no typed entity).
- **Room name:** SHARED NAME ONLY. The creator or an admin sets one room name everyone sees; per-member room aliases go away. (Supersedes NR-17a "local name lives only in its sealed manifest" and the alias part of service.node.room.vox for the room segment — to confirm.)
- **Room name clash:** REFUSE to join a second room whose shared name you already have.
- **Q4 Backup:** NONE. Lose the machine, make a new node.
- **Q5 Terminology correction:** there is NO "invite link". There is a ROOM LINK and a PASSPHRASE. A room link never expires; it stops working only when the room is ended by its creator or an admin. (Fix every "invite" wording: `vox room invite` output, ADRs, TUI.)
- **Q7 Post as another node from the TUI:** REFUSE. The TUI posts only as the node it was opened with.
- **Link verb:** rename `vox room invite` -> `vox room link`; `invite` removed.
- **Q8 Show who in the room trusts a newcomer ("K2M9… joined. ann trusts it."):** YES.
- **Q13 Service kind:** NOT manual, and NO fuzzy heuristics from port number or the service name. "Can't we be smarter?" -> proposal pending (protocol probe).
- **Q11 macOS:** quitting the app DETACHES the node (like the TUI).
- **Q13 resolved:** kind detected automatically, recorded in the share. If the service runs on the SAME system, use the listening process (lsof/ss: command name, e.g. sshd) and probing; if it's on ANOTHER system (e.g. sharing 192.168.1.20:22), probe it on the wire (SSH banner, HTTP response, TLS handshake, DNS answer). Unidentified -> plain tcp/udp with generic forward commands.
- **Q14 File serving:** the DAEMON serves an attached file until the message expires (or the sharer stops it). No foreground process needed.
- **Q15 Thumbnail <= 16 KB inside the encrypted message:** YES (supersedes ADR-020 11.1 for thumbnails). PLUS normal messaging-app URL previews (link cards). (Who fetches the preview: pending.)
- **Q9 Folder:** just a share, pulled on demand from the sharer; ideally the puller can rsync-style sync it (incremental, resumable, only changed files).
- **Q16:** The daemon keeps the .vox proxy running (what `vox up` does today) while a node is attached.
- **URL cards:** the SENDER's node fetches the page once and puts the card in the encrypted message; readers never contact the site.
- **Q10 Calls (v0.4.0):** BOTH drop-in ("ann is in a call · [j]oin") AND ringing; ringing is not optional (always rings).
- **Q17 Expiring trust:** NO.
- **Q18 macOS Keychain may store a node's passphrase:** YES, opt-in per node.

## Notes for the ADR-014 (macOS app) rewrite (2026-10-04)

From an outside review, agreed by the decider for v0.4.0:
- **The app is a Swift client of the daemon's control socket**, like every other client under ADR-026. It is not an in-process node over UniFFI, so ADR-014's UniFFI sections (1, 11.1) go; whether `crates/vox-ffi` keeps any use is decided in the rewrite.
- **A small privileged helper, registered with `SMAppService` as a launchd daemon** and approved once in System Settings, creates the tunnel interface and passes its descriptor to the user-level daemon. It never sees keys or room data. It replaces the hand-started `sudo vox lan helper`.
- **The user-level `vox daemon` is a login item** registered with `SMAppService`, so it runs before the app opens; quitting the app detaches its node (Q11).
- **Offscreen screenshots of every window from demo data** for docs and release notes, never from a real data root. They show the look; they are not product proof. Localization (the reference does 8 languages) is not planned yet.

## Note for the TUI and macOS ADRs: a record of what the node decided (2026-10-04, not decided)

From an outside review, noting a pattern; whether Vox keeps such a record is the decider's call.
- **The gap:** Vox says why at the moment it refuses (a join, a forward, a trust change, a circuit), but if no one was watching, the reason is gone except in the daemon's log text.
- **The reference:** Bromure's Security Timeline (`/opt/bromure/Sources/AgentCoding/SecurityTimeline.swift`, `SecurityTimelineView.swift`). Every decision its engines make is one event: time, engine, condition (what it saw), decision (what it did), and a kind of allowed, blocked or info, which colours the row. Events are always recorded, appended to one JSONL file per day in the app's support folder, pruned after 90 days, reloaded at launch, and shown as one chronological table.
- **How it would map to Vox without a new concept:** the daemon already emits these decisions as node events (`JoinFailed`, refusals with their reasons, connection notes), and writes them to `.daemon/log` when no client is subscribed. The Vox version is that same stream kept as structured events, per node, under the data root (`.daemon/decisions/<date>.jsonl`), with a "what happened" view in the TUI and the app, and `vox status` naming the latest refusals.
- **Constraints if adopted:**
  - It MUST hold no message text, passphrase, key or token. It names who (fingerprint or alias) and what was decided, never content, so a message's retention leaves nothing behind in it.
  - It is local only, never sent anywhere.
  - Its retention is the decider's call, e.g. 90 days.
