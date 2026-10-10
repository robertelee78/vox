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

## Parked ideas from the 2026-10-04 review (not decided)

- **Benchmark records.** Each timing or throughput run (R40, R41, R42 and the rest) appends one record outside the repo (e.g. `~/vox-coord/perf/`): commit, binary sha256, method, and every sample including failed ones, after Bromure's per-run benchmark records. Today the numbers live only in issue comments and run logs, so a regression cannot be told from noise. Proof-side only; nothing in the product. A candidate v0.3.1 story, the decider's call.

## Product Q&A for v0.4.0 (2026-10-05)

- **Release scope.** v0.4.0 is the macOS app plus the fixes already queued for it. v0.4.1 is v0.4.0's bug fixes. v0.4.2 is post-quantum post-compromise security for pairwise key delivery (ADR-030). v0.5.0 is the iOS app plus calls (the decider, 2026-10-09: the iOS app moved from v0.4.1 to v0.5.0). Call keys must follow ADR-030 D-1 until ADR-030 is reopened for that payload.
- **Every interview decision ships in v0.4.0 with the app**: read receipts always on, one shared room name, the daemon serving an attached file until the message expires, a thumbnail inside the message, link cards fetched by the sender, automatic service-kind detection.
- **Room part of a service address.** The room's shared name is the room part of `service.node.room.vox`, so an address means the same thing on every member's machine and can be pasted between people.
- **Decision record: adopted.** Each node keeps a local record of what it decided (who and what, never message content), kept **14 days**, never sent anywhere. `vox status` names the latest refusals; the app and the TUI show it as a timeline.
- **Accent: ice blue**, for focus and "live" only (the research's reasoning: copper and red collide with the danger and warning colours in a terminal).
- **Install and update.** Vox.app is signed and notarized. On macOS the one-line `install.sh` installs Vox.app as well as `vox`. `vox update`, and the app's own update offer, update both together as one version.
- **Several nodes on one Mac.** The app acts as one node, yours, like the TUI. Agents' nodes appear as members of the rooms you share with them; you never post as an agent.
- **Files and folders are for temporary hand-offs, not code.** Agents keep code in sync through GitHub. A file or folder shared in a room is a message: the daemon serves it until the message expires or the sharer stops it; receivers delete their copies at expiry. A folder pulled again fetches only new or changed files (a file list with hashes) and resumes if cut off. One-way: the sharer's folder is the source; no live or two-way sync. In v0.4.0.
- **A share is addressed like any message.** `vox share ROOM PATH --to NODE [--urgent] -m NOTE`: the note and the addressee travel in the share itself, never as a separate follow-up. The addressee's hook gives its agent the note and the local path; `--urgent` wakes it, as for any addressed urgent message.
- **Who pulls automatically.** A node pulls a share addressed to it, or addressed to no one, from members in its keyring. A share addressed to another node shows as a card; anyone may still pull it with `vox room get`.
- **Where pulled files land.** `<data root>/nodes/<node>/files/<room>/`, per node and per room; people may also save a copy to ~/Downloads.
- **The sharer sees who pulled it.** The share card says "pulled by agent-2", beside the message's "read by" receipts.
- **Date.** The decider wants v0.4.0 as soon as possible ("today or tomorrow"); the date is set from the task-level plan after the UX ADR and the ADR-014 rewrite.

## ADR-028 open questions, answered (2026-10-05)

- **Addresses are communicated as fingerprints, every part.** The canonical address is `<service id>.<node fingerprint>.<room id>.vox`: the service part is a stable ID of the share (from its share statement), the node part the node's fingerprint, the room part the room's ID. Copy actions, pasted text, messages and agent hooks carry this form, so it resolves the same on every member's machine. Each client renders it human-readable by each part's own rule (service name; the viewer's alias for the node; the room's shared name) and accepts the readable form typed locally, translating it back.
- **A rename that clashes on one node.** On that node only, the rooms involved lose the readable name and are shown by their room IDs until the clash is gone.
- **Read records** are visible only to members the reader trusts (sealed like messages).

## Passphrases and trust offers (2026-10-06)

Input to ADR-028 §2a.

- **Every node has a passphrase**, an agent's node as well as a person's. It is used only to start a session as the node (attach) and to change its keyring. This replaces the 2026-10-02 rulings that agent nodes have no passphrase or take one from an environment variable, and that passphrases are optional.
- **The same rules for every node.** "We have no typed entity of agent/human -- same rules apply to both."
- **Attaching does not open the keyring window.** Only a passphrase typed for a keyring change opens it; the 30-minute window applies to every node.
- **Typed outside the agent's session.** The Claude, Codex or OpenCode session gives the operator a command to run from a command line outside that session, where the passphrase is typed.
- **No trust file.** Trust is offered when a node joins a room: its fingerprint is offered to the members already there, each may trust it, and accepting offers that member's fingerprint back. One symmetric pair at a time.
- **Accepting asks "read, or read + drive?"**, with read the default.
- **An unanswered offer waits** under needs you until accepted, dismissed (silently) or the joiner leaves.
- **No forced fingerprint comparison.** "It's expected that the user who is accepting the fingerprint knows how to do validation that they required for their threat model."

## Sessions (2026-10-05 and 2026-10-06)

Input to ADR-029. Sessions are in v0.4.0.

- **Two jobs, kept apart.** ctm mirrors one session to a place the person can drive 1:1 from anywhere; agent comms is n sessions, on any harness and computer, collaborating on one repository. "I kind of want both ... session level, and repo level groupings."
- **One room per repository** is the central place where every node with a session on it talks. Inside it, a **Session** per harness session, like a Telegram forum topic: a sidebar of Sessions beside the room's own conversation ("General") and everything merged ("All").
- **A Session appears automatically** for every interactive harness session; headless runs get none; `resume` keeps it.
- **Retention.** A Session's content follows the room's retention and is never deleted because the session ended; an ended Session is only moved out of the way.
- **Drive is a capability on trust**, not a separate trust: one keyring entry per node, with "may read me" and "may drive my sessions". Capabilities apply in every room shared, limited by room membership: "she might not be in all the rooms."
- **Only nodes with drive see inside a Session.** Others see only that it exists.
- **First version of driving:** see activity with Details, see replies and turn ends, type in, interrupt or stop, approve or reject tool calls, answer its questions, send slash commands, send files or images, receive files. Not mute.
- **Talking is not driving.** Another session may ask one specific session something ("the project 4 session should have a way to ask a question of the project 5 agent separately from the project 6 agent, even though it's the same node"). Waking a session is talking: "it's not driving ... it's 'yo, let's chat'."
- **Every agent message carries its session id and session name** (the harness's /rename), filled in automatically.
- **The room a session works in** comes from a per-machine file like `~/.ssh/config`: `/path/to/repo` → room link + passphrase, readable by every node on the machine. Only the exact start path matters ("I never start a new session directly from a work tree"); the room stays the same for the session's life, whatever branch, worktree or other repository's files it touches. With no entry, the operator tells it which room. A manual change moves the session; "I don't plan to do that."
- **Setup** detects the installed harnesses and creates one node per harness, plus an optional node for the person on macOS or iOS, and prints each node's fingerprint with facts about the node.
- **Clients:** the TUI and the macOS app, kept in sync; the iOS app is not designed yet.

## Lanes removed; ctm rules confirmed (2026-10-06)

- **No lanes.** "I don't know what a lane is. I want to kill the lane. I want rooms, nodes, sessions. Lanes was never asked for." ADR-028 W-3 is removed, with the built TUI lanes view and the app's planned one.
- **A sub-agent's activity belongs to its parent's Session**, as in ctm.
- **A message to a session that has ended is refused**, and the sender told.
- **No self-contradicting documents.** Every issue bound to an amended ADR is to point at the current text.
