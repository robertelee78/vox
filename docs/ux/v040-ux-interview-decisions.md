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
Q16 The daemon keeps the .vox proxy running (what `vox up` does today) while a node is attached.
- **URL cards:** the SENDER's node fetches the page once and puts the card in the encrypted message; readers never contact the site.
- **Q10 Calls (v0.4.0):** BOTH drop-in ("ann is in a call · [j]oin") AND ringing; ringing is not optional (always rings).
- **Q17 Expiring trust:** NO.
- **Q18 macOS Keychain may store a node's passphrase:** YES, opt-in per node.
