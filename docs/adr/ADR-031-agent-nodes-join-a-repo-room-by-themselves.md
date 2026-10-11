# ADR-031: Agent Nodes Join a Repo's Room by Themselves

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.5, except SA-8, SA-9, SA-12.2, SA-12.3, SA-13, RN-1 and RN-2,
which are accepted for v0.4.4 (the decider's release split, 2026-10-10, night: v0.4.4 holds the
fixes that let nodes join a room and work correctly, and the rest moves to v0.4.5). Accepted from the
decider's Q&A, 2026-10-10, his answers to this ADR's open questions the same evening, his
story-plan answers that night (LT-8, a Mac over ssh, one format step), and his Session history
decisions and answers that night (SA-7–SA-13). Nothing in this ADR is built.
**Date**: 2026-10-10
**Deciders**: Robert E. Lee
**Tags**: agents, onboarding, hooks, keyring, trust, drive, sessions, macos
**Related**: ADR-001, ADR-005, ADR-007, ADR-010, ADR-014, ADR-020, ADR-026, ADR-028, ADR-029, ADR-033, ADR-034
**Inputs**: the decider's product Q&A of 2026-10-10 (Q1–Q8, Q16a, Q18) and his answers to the
open questions (local trust without the keyring passphrase, its cost, existing pairs, the CLI
verbs, sealing Session records now; every other first choice "ok"); the onboarding
evaluation of 2026-10-10 (three evaluators and a CLI measurement pass on v0.4.3's room-polish
build); issues #677 (person-confirmed trust) and #681 (the app manages the agent nodes on this
Mac).

## Context

On 2026-10-10 the decider upgraded to v0.4.3, opened a repository and started Codex. Nothing said
anything about nodes or rooms: Codex had the Vox skill but no Vox hook and no node, and the skill
did not trigger. The decider: "It is currently fairly painful even with the existing skill to
onboard a new harness node and have it join a room and be trusted by the existing nodes in that
room and have it trust the existing nodes in that room -- too many times I have to do commands at
the command line that don't always work based on what is pasted to me". The evaluation counted,
for one new agent on one Mac, 8–13 terminal commands, 5–9 pastes, 3–6 passphrases and 2–3 steps on
another Mac; 14 of the 18 places that hand the operator a command broke when pasted into zsh or
bash; and about nine words named two states of a node.

This ADR makes an agent's node come into a repository's room with no terminal on a Mac with
Vox.app, and with one printed command elsewhere. It adds one rule of automatic trust between the
nodes of one machine, and amends the trust, setup, hook and Session lines it overrules.

**Terms.** *This machine's nodes* are the nodes of one daemon, that is, of one data root
(ADR-026 D-1). *The person's node* is the node Vox.app acts as (ADR-028 E-4). *News* is what an
agent's hook puts into the agent's next turn (ADR-020 6.6). *A Mac with Vox.app* is a Mac where
Vox.app is installed and the agent's session runs at that Mac; a session reached over ssh is on a
machine with no Vox.app, and is told the terminal way (NC-4, RM-4, CW-6). The decider, 2026-10-10:
a Mac reached over ssh is treated as a box with no app.

## Requirements

### 1. A light hook in every harness, from install

- **HK-1.** `install.sh`, `vox update` and Vox.app's first run MUST wire a light hook into every
  harness found on the machine (Claude Code, Codex, OpenCode) that has no Vox hook, and MUST say
  which configuration files they changed. The decider: "because sometimes this same thing is on a
  box with no app".
- **HK-2.** The light hook MUST act as no node (ADR-020 2.1 holds: a hook never falls back to
  another node). It MUST NOT start the daemon, MUST exit 0 whatever happens, and MUST add at most
  one line to a turn.
- **HK-3.** At the first turn of a session whose harness has no node on this machine, the light
  hook MUST tell the agent, once per session, that this harness has no Vox node and what comes
  next: on a Mac with Vox.app, that Vox offers Set Up and that the agent may start it (NC-1);
  elsewhere, the exact command for the operator (NC-4).
- **HK-4.** Vox.app MUST notice a harness with no node (a light-hook session registering, or a
  harness found with none) and offer **Set Up** once per harness, with **Not Now**. Not Now MUST
  be recorded for that harness on this machine, and the light hook MUST then stay silent for it
  until the person sets it up from the app.
- **HK-5.** Setting a node up MUST replace the light hook with the node's hook
  (`vox agent hook --node <name>`, ADR-026 N-6), and MUST do whatever else the harness needs before
  that hook runs (for Codex, trusting the hook), with no separate step for the operator.

### 2. Who creates the node

- **NC-1.** An agent MAY start making its own node, with `vox agent setup <harness>`. The decider:
  the harness may create its node itself "so long as the passphrase setting goes to the vox app (if
  on macos), otherwise, it should tell the operator what command to run".
- **NC-2.** On a Mac with Vox.app, the verb MUST hand the request to the app (opening it when it is
  not running) and return at once, saying that Vox has asked the person. The app MUST show its own
  window naming the harness, the directory and the node's name, and offer a passphrase or none
  (ADR-028 K-11's sentence for none). The app MUST make the node (ADR-026 C-5: the client writes
  its files), make it Ready and remember it (CW-2). The passphrase MUST NOT pass through the
  agent's process, its environment, its terminal, its turn or any reply to it.
- **NC-3.** The hook MUST tell the agent the outcome at its next turn, in one sentence: the node is
  made and Ready, the person declined, or the person has not answered yet.
- **NC-4.** Where there is no Vox.app (Linux, or a Mac without it), the agent MUST NOT make the
  node. The hook MUST give the operator `vox agent setup <harness>` to run in a terminal of their
  own, which asks for the passphrase there.
- **NC-5.** A node's suggested name MUST be `<harness>-<host>` with the machine's own host name,
  case-folded and made a valid node name (ADR-026 N-1a), never an opaque id.
- **NC-6.** `vox agent setup` replaces `vox agent connect`; no client, hook or document MAY say
  "connect" for it (CW-1).

### 3. Trust between the nodes of one machine

The decider (verbatim): "I never operate an agent's node from the macos app. I think as a new
node, when that node is on this same system, joins a room the node I'm using the macos app with is
in, my node, and all nodes on this system should automatically trust (read) that new node, and
that new node should trust (read) all other nodes that are on this same system. It should also
allow drive access for the node I'm using from the macOS app."

- **LT-1.** Whenever a node of this machine, other than the person's node, is a member of a room
  that the person's node is also a member of, the daemon MUST see to it, with no click and no
  passphrase, that:
  1. every other node of this machine has that node in its keyring with **read**;
  2. that node has every other node of this machine in its keyring with **read**;
  3. that node has the person's node in its keyring with **read + drive** (ADR-028 K-14).
- **LT-2.** Where there is no person's node (no Vox.app, or none chosen), LT-1 MUST NOT apply:
  this machine's nodes trust each other the normal way, and no node gets drive automatically.
- **LT-3.** An LT entry MUST be written by the daemon, from facts it holds itself (both nodes are
  its own, and the node shares a room with the person's node); no request from any process MAY
  cause or widen one. LT-1 is the person's standing rule, applied by the daemon, only to nodes of
  this machine, with drive going only to the person's own node; it is therefore exempt from the
  keyring passphrase (the decider, 2026-10-10): an LT entry MUST NOT ask for the identity
  passphrase and MUST NOT open the keyring window (ADR-028 K-12). A node that is Locked when its
  entry is due MUST get it when it is next Ready.
- **LT-4.** An LT entry's alias MUST be the node's name on this machine (ADR-028 K-3, with K-4's
  suffix on a clash).
- **LT-5.** Every LT entry MUST be recorded in each node's decision record (ADR-028 D-1). No line is
  posted in the room for an automatic trust: the decider, 2026-10-10, "Can skip it. It's not
  needed."
- **LT-6.** Removing an LT entry (ADR-028 K-6) MUST stop LT from adding that pair again, until the
  person adds it back by hand.
- **LT-7.** Nothing is automatic for nodes on other machines. The decider: "for now", they trust
  the normal way. A newcomer from another machine MUST appear in the room's members panel as a new
  member with **Trust** and **Dismiss** (the decider, Q18: "as a new member, not pending"); the
  offer MUST NOT be shown in General.
- **LT-8. With #677: no widening from an agent's session.** Every widening of trust or drive other
  than LT-1 (`vox trust add`, `vox trust drive` and any other verb that adds a trust or a
  capability) MUST be refused when it runs inside an agent's session, as that session's Vox hook
  marks it, whatever the passphrase and the keyring window say. The refusal MUST be one sentence
  saying that the person must run it in a terminal of their own or in Vox.app. The identity
  passphrase and its 30-minute window (ADR-028 K-12, KP-1) stay as they are for a person's own
  terminal and the app. No operating-system account check (Touch ID, the account password) is
  used: the decider, 2026-10-10, "nodes are tied to pub/priv keys which is orthogonal to host level
  account auth". LT-1 is not such a widening: it is the person's standing rule, applied by the
  daemon, and grants drive only to the person's own node.
- **LT-9. Existing pairs.** LT-1 MUST apply to pairs of this machine's nodes that already share a
  room with the person's node when a release with this ADR first starts, not only to new joins.
  The daemon MUST write their entries at that start (or when each node is next Ready). A pair whose removal by hand is in either node's decision record
  (ADR-028 D-1, "a trust added or removed") MUST be treated as removed under LT-6 and left alone.
  The release's notes MUST say that existing local pairs are trusted on upgrade.

### 4. A repository with no room

- **RM-1.** On a Mac with Vox.app, a session in a directory the room map does not name (ADR-029
  RB-5a) MUST open a dialog in the app, not a banner, naming the harness and the repository, with
  **Create Room "<name>"** (the repository's directory name made a valid room name, ADR-028 R-2),
  **Choose a Room…** (a room the person's node holds, or a pasted link) and **Not This Repo**. The
  decider: "should cause dialog in the app if present".
- **RM-2.** Create Room MUST create the room as the person's node, with a passphrase typed in the
  dialog or none, bind the directory in the room map (ADR-029 RB-6), and put every session waiting
  in that directory in the room. It MUST NOT ask for the identity passphrase (KP-1).
- **RM-3.** A room passphrase given to bind a directory MUST be checked by a real join before the
  map is written; a wrong one MUST be refused with a sentence that names the passphrase.
- **RM-4.** Where there is no Vox.app, the hook's one sentence (ADR-029 RB-5) MUST give both ways:
  the command that creates a room for this repository and binds it, and pasting an existing room's
  link. The decider: "The harness should tell the operator how to create a room, or paste url for
  existing room."
- **RM-5.** There MUST be one ask per repository (the main repository of a worktree, as ADR-029
  RB-2 finds it), not one per folder.
- **RM-6.** A session that works in no room MUST NOT be given another room's news as its own.

### 5. Ready or Locked

- **CW-1.** Each node on this machine MUST be shown as **Ready** (attached) or **Locked** (needs its
  passphrase). No client, hook, notice or manual page MAY name these states or their changes with
  any other word: not attach, detach, keep, connect, sign out or start over. The old verbs that
  CW-7 keeps working are the one exception, and only in what they print.
- **CW-2.** **Unlock…** MUST be the one action on a Locked node. It MUST ask for the passphrase and
  always remember the node (ADR-028 K-10: the Keychain on a Mac), with no choice to offer.
- **CW-3.** After a daemon restart, an update or a reboot, every remembered node MUST come back
  Ready by itself, the person's node included, whatever any "keep running" setting says.
- **CW-4.** **Forget** MUST be in the node's menu. It MUST lock the node and forget what brings it
  back (its stored passphrase and its remembered state); the node, its rooms and its messages MUST
  stay on disk.
- **CW-5.** A node made with no passphrase MUST never be shown Locked.
- **CW-6.** A hook that finds its node Locked MUST say "Open Vox to unlock <node>" on a Mac with
  Vox.app, and `vox node unlock <node>` (CW-7) elsewhere, as K-13 requires.
- **CW-7. The verbs.** At a terminal the verbs MUST be `vox node unlock <name>`, which does what
  Unlock… does (CW-2), and `vox node lock <name>`, which locks the node and forgets what brings it
  back, as Forget does (CW-4), so it stays Locked across restarts until unlocked. The decider:
  "yes" to the rename. `vox node attach` and `vox node detach` MUST keep working, do what `unlock`
  and `lock` do, and print the new verb, for example "`vox node attach` is now `vox node unlock`".
  `attach --keep` MUST be accepted and have no further effect, since `unlock` always remembers.
  Every other place that prints a command (PC-1) MUST print the new verbs.

### 6. When the keyring passphrase is asked for

- **KP-1.** Only a keyring change (trust add, remove, rename, a capability change) MUST ask for the
  identity passphrase, with the 30-minute window (ADR-028 K-12). Anything else, creating, joining,
  binding or leaving a room included, MUST NOT ask for it or wait on it. The decider's correction:
  the ask and the window "only applies to things that change the keyring -- otherwise it shouldn't
  need passphrase for things like creating a room".
- **KP-2.** In the app, a keyring change MUST ask right then, in a sheet naming the change ("Trusting
  ben needs your keyring passphrase"). The passphrase MUST NOT be stored (ADR-028 K-13).

### 7. What the person sees when an agent joins

- **JL-1.** When an agent's node joins a room and its session starts working there, the person's
  client MUST show one line in General, for example "codex (on this Mac) joined repo-to-cve and is
  working in /opt/repo-to-cve". The join line MUST
  be derived from the join and the session's claimed directory (ADR-020 2.3); it MUST NOT add an
  entry type.
- **JL-2.** The agent's Session MUST open as a tab (ADR-033 LY-1) for each member it grants drive.
- **JL-3.** A join MUST NOT post a notification.
- **JL-4.** The agent MUST be told at its next turn that its node joined, in which room, and who
  reads it and whom it reads, for example "joined repo-to-cve; reads and is read by your nodes on
  this Mac; ben does not read it yet".

### 8. Session access needs drive

- **SA-1.** A member that a node does not trust with drive MUST NOT see any of that node's
  Sessions: no tab, no label, no opening or end line, no entry. Read trust covers the room's chat
  only. The decider: "there's no such thing. Read without drive is limited to the main room chat
  stuff. I have no session access to a node that I can't drive."
- **SA-2.** The daemon MUST answer a request for a room's Sessions only with the asker's own
  Sessions and those of nodes that trust the asker with drive. (Today `Request::Sessions` answers
  every Session on the log to any member.)
- **SA-3.** A Session's opening and end records MUST be sealed under its Session key (ADR-029 SC-2),
  so a member without drive cannot read them from its own copy of the log. This MUST ship in
  v0.4.5 (the decider's "do it now" was for v0.4.4; his release split moved it).
- **SA-5. Upgrade.** Sealing these records is a format change (ADR-026 F-3): v0.4.5 MUST raise the
  data root's format and MUST upgrade, automatically and before anything else is written, every
  data root a release since v0.4.0 wrote. Every room, every Session and every entry an earlier
  release wrote MUST open and read in full after the upgrade, and an open Session MUST continue;
  nothing MAY be lost. Records an earlier release wrote unsealed stay as they were written in every
  member's copy of the log; from the upgrade on, the daemon MUST NOT serve them to a member without
  drive (SA-2), and the release's notes MUST say that earlier opening and end records stay readable
  in a copy a member already holds. This is one format step with ADR-032 AN-14: v0.4.5 MUST raise
  the format once, with one upgrade and one proof (SA-6) for both.
- **SA-6. Proof of the upgrade.** The upgrade MUST be proved by real use, on a data root and rooms
  the shipped v0.4.4 binary wrote, with Sessions open and ended, opened by the v0.4.5 binary
  (extending `a_data_root_of_the_previous_release_opens_with_nothing_lost`, ADR-026 F-3), with a
  mutant that turns it red on its own assertion (ADR-018 §7).
- **SA-4.** A member without drive addresses the node (ADR-029 TA-4); the composer MUST NOT offer
  that node's Sessions.

The decider's Session history decisions (2026-10-10, night), after the frame-length root cause
(ADR-034 Context): "agents will often have MUCH MUCH MUCH longer sessions". A Session's steps are
the entries ADR-029 SC-1 lists: tool calls, replies, turn ends, approvals, questions and answers,
and file records. A Session's opening and end records are not steps: every member with drive
learns that a Session exists, and can drive it, whenever it joined (the lead's call, 2026-10-10,
on a point the decider left open).


- **SA-7. Session steps live only with drive.** A Session's steps MUST be sent, synced, relayed and
  stored only to and on the session's own node and the members that node trusts with drive. A
  member without drive MUST NOT receive them, not even sealed, and no member MAY relay them to one.
  The decider: "Session steps are kept only on members with drive (the only ones who can read
  them)." The room's own messages are not affected: a member without drive MUST be able to hold,
  verify and sync the room's log complete without any Session step, so nothing a member without
  drive holds MAY need a Session step to verify or to sync. At the upgrade to the release that
  brings SA-7, a member without drive MUST delete the steps it holds. A member that loses drive
  later MUST keep what it already read and MUST receive nothing newer (ADR-029 SC-2b holds). The
  decider: "yes" to both.
- **SA-8. Forward from the join.** A node that joins a room MUST get a Session's steps only from
  the later of its join and its gaining drive, going forward. No node MAY send it, and it MUST NOT
  fetch, a step written before then, whatever its trust. The decider: "A node that joins syncs a
  Session only from the point it joined, going forward — no backfill of Session history."
- **SA-9. A retention for Session steps.** A room MUST have a retention for its Session steps,
  apart from its message retention (ADR-010 AR-28). Its default MUST be 7 days or the room's message
  retention, whichever is shorter, where forever is longer than any duration. Steps MUST never
  outlive the room's messages: the retention in force is always the shorter of the one set and the
  message retention. It MUST be set with `vox room retention <room> --steps <dur>`, for example
  `--steps 7d`. The 7-day default MUST apply plainly to rooms an earlier release created, from the
  first start of the release that brings SA-9; no older step is kept for them. The decider: "lol
  I'm the only user dude, we're still pre-alpha"; "yes" to steps never outliving messages and to
  `--steps 7d`. The decider: "a room
  has its own retention for Session steps; default = 7 days or the room's message retention,
  whichever is shorter; the creator/admin may set it." Only the room's creator, or an admin it
  delegated with `vox room admin`, MAY set it (ADR-007 G-5), through `vox room retention` as the
  message retention is set, with no identity passphrase (ADR-028 K-11). A member's own lower
  retention (ADR-010 AR-29) and the shorter-wins rule (AR-30) MUST apply to Session steps as they
  do to messages. `vox status --json` and the app's room settings MUST show it beside the message
  retention. An ended Session's steps age by it (ADR-029 SE-5 as amended).
- **SA-10. Peers of earlier releases.** SA-7 and SA-8 change what peers send each other. A node of
  the release that brings them MUST keep syncing the room's messages with a peer of an earlier
  release (ADR-034 UP-2), and nothing it sends MAY poison that peer's room. A member of an earlier
  release without drive receives no Session steps from a node with SA-7. What a member of an earlier
  release with drive sees of a Session written by such a node, and what such a node does with steps
  an earlier release still writes into the room's log, is to be measured with the shipped earlier
  binary before SA-7 is built, and the release's notes MUST say it in one sentence.
- **SA-11. The format step.** Whatever the store needs to hold steps apart from the room's log
  (SA-7) is part of v0.4.5's one format step (SA-5): one raise of the format, one upgrade and one
  proof (SA-6) with SA-3 and ADR-032 AN-14. After the upgrade, every step a member with drive held
  and its retention still keeps MUST read in full, and an open Session MUST continue. SA-8 and
  SA-9 ship in v0.4.4, before that step, and do not wait for it: where SA-9 needs a field the data
  root lacks (the Session-step retention in the room's policy, ADR-007), v0.4.4 MUST carry its own
  small upgrade for it, with nothing else in it.
- **SA-12. Proof.** SA-7, SA-8 and SA-9 MUST each be proved by real use of the shipped binary
  (ADR-018 §9), extending the drive journey where it fits, with a mutant that turns each proof red
  on its own assertion, labelled PRODUCT (ADR-018 §7):
  1. SA-7: in a room of three nodes, where the session's node trusts one member with drive and one
     with read only, a test-side peer acting as the read-only member (apparatus, ADR-018) asks both
     other nodes for the Session's steps and MUST get none, while the room's messages reach it.
     Mutant: serve steps to every member.
  2. SA-8: a member given drive that joins after a Session has written steps MUST see, in its
     Session tab and with `vox room session`, only the steps written after it joined, and a
     test-side request for earlier steps MUST get none. Mutant: backfill from the start.
  3. SA-9: in a room whose Session-step retention is set shorter than its message retention, a
     Session's steps MUST be gone from every member with drive once that retention passes, while
     the room's messages of the same age remain; and a new room MUST report a 7-day Session-step
     retention. Mutant: steps age by the message retention.
- **SA-13. Saying "step".** The manual, the app, the TUI and every verb's help MUST explain a step
  in plain words, as one thing an agent did in its Session: a message, a command it ran, a file it
  edited. They MUST NOT use "step" without that meaning, and MUST NOT name it otherwise. The
  decider asked what a step is: it is to be explained plainly where the person meets it.

### 9. Renaming a node

- **RN-1.** Renaming a node MUST update every place on this machine that names it: each harness's
  hook (`--node`), the remembered state, the Keychain item, the app's chosen node, and the LT aliases
  that still equal the old name. It MUST say what it changed, and name any file it could not
  change with the line to fix it.
- **RN-2.** A hook whose `--node` names no node on this machine MUST say so in one line at the
  session's first turn, with the fix.

### 10. Commands handed to the operator

- **PC-1.** Every command Vox hands the operator (CLI output, a hook's text, the app's Copy, the
  skill, the manual) MUST run as printed when pasted into zsh or bash: every argument quoted for
  the shell, no placeholders, `--node` filled in.
- **PC-2.** Every input that takes a fingerprint MUST accept both the bare form and the grouped
  form (ADR-028 K-1).

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-020 2.1; ADR-026 N-6 | The skill pack's setup, or the operator at a terminal, creates the agent's node | The agent MAY start it; on a Mac the app makes it, with the passphrase in the app's window; elsewhere the operator runs `vox agent setup` (NC-1–NC-4) |
| ADR-020 3.3, 3.7 | Every release is caused by a keyring entry made by one of two entry points | Also by LT-1's entries between the nodes of one machine |
| ADR-020 10.1 | No identity vouches or stands for others in granting read | Unchanged: LT-1 follows from both nodes being this daemon's, not from any node's word (LT-3) |
| ADR-028 E-2 | Words include attach and detach | Ready, Locked, Unlock…, Forget; not attach, detach, keep, connect, sign out, start over (CW-1) |
| ADR-028 E-4 | Sign Out detaches and forgets the node | Forget, in the node's menu (CW-4); the client still acts as one node; LT entries are the daemon's |
| ADR-028 K-10 | The app's attach stores the passphrase unless turned off | Unlock… always remembers (CW-2); every remembered node returns Ready (CW-3) |
| ADR-028 K-13 | The hook shows a terminal command for every step | On a Mac with the app: "Open Vox to unlock", and setup in the app's window (CW-6, NC-2) |
| ADR-028 K-15, K-18; W-2 | A join offers trust under needs you, at the top of the room's General | Not offered between this machine's nodes (LT-1); from another machine, a new member with Trust and Dismiss in the members panel (LT-7) |
| ADR-028 W-1 | Nodes on this machine shown attached or detached | Ready or Locked (CW-1) |
| ADR-029 SC-3 | Every member sees that a Session exists | Only members with drive see it (SA-1, SA-3) |
| ADR-029 CL-2, CL-3 | General, All and a list of Sessions; members without drive see Session entries | Tabs only for Sessions the member can drive; no All (SA-1; ADR-033 LY-1) |
| ADR-029 TA-1; ADR-028 W-4 | Any member with read MAY address a session | Only a member that can see the Session (SA-4) |
| ADR-029 RB-5, RB-5a | A banner with Choose a room… and Not this repo; the hook offers a link or a no | A dialog that can also create the room; the hook also gives the create command; one ask per repository (RM-1–RM-5) |
| ADR-020 6.5 | The hook drains every room its node holds | Not into a session that works in no room (RM-6) |
| ADR-014 M-6, M-21 | Keep Running decides whether the node stays attached; Node menu Attach, Detach | Every remembered node returns Ready (CW-3); Node menu Unlock…, Forget (CW-2, CW-4) |
| #681 | Drive stays at the terminal | The person's node gets drive over this machine's agent nodes automatically (LT-1.3) |
| ADR-028 K-12 | Every keyring change asks for the identity passphrase, with the 30-minute window | Except LT-1's entries, the person's standing rule applied by the daemon (LT-3) |
| #677 | A widening is confirmed by the person (a Touch ID or password check was considered) | Refused inside an agent's session as its hook marks it; the passphrase and its window stay; no OS account check (LT-8) |
| ADR-026 L-2; ADR-028 K-13 | `vox node attach <name> [--keep]`, `vox node detach <name>`; the hook shows the attach command | `vox node unlock <name>`, `vox node lock <name>`; the old verbs work and print the new ones (CW-7) |
| ADR-026 F-3 | Format as of v0.4.3 | Sealed Session opening and end records raise the format, with an upgrade from every release since v0.4.0 (SA-5, SA-6) |
| ADR-029 SC-1, SC-2 | A Session's steps are entries of the room's log, sealed, and every member holds them | Steps are sent, synced and stored only on the session's node and members with drive; members without drive never receive them (SA-7) |
| ADR-029 SC-2a | A member reads a Session from the key's release onward; earlier sealed steps are in its copy of the log | A joining node gets steps only from the later of its join and its gaining drive; no backfill (SA-8) |
| ADR-029 SE-5; ADR-010 AR-27, AR-28 | A Session's content follows the room's message retention, forever by default | Session steps have a retention of their own, by default 7 days or the message retention, whichever is shorter (SA-9) |
| ADR-007 G-5 (the policy update) | A policy update changes the room's one retention | It also carries the Session-step retention (SA-9), set with `--steps` |
| ADR-031 SA-3, SA-5, SA-6, SA-11 (as first written) | Ship in v0.4.4, with the Session-step retention in the one format step | Ship in v0.4.5; SA-8, SA-9, SA-13, RN-1, RN-2 ship in v0.4.4, SA-9 with its own small upgrade (the decider's release split, 2026-10-10) |

## Consequences

- On a Mac with Vox.app, bringing an agent into a repository's room takes Set Up, a passphrase or
  none, and starting the session. Another Mac's person still trusts it by hand.
- Any process that can run as this OS account and knows a room's link and passphrase can make a
  node, join that room and so be read by, and read, every node of this machine. The OS account is
  already the boundary for the daemon's socket (ADR-026 C-6); this rule widens what a process
  inside it gains without a person, and with no keyring passphrase. The decider accepted this
  cost (2026-10-10); each automatic trust is in each node's decision record (LT-5).
- A trust-widening verb run inside an agent's session is refused by the mark its hook sets (LT-8).
  An agent's process that drops that mark is not refused: LT-8 stops an agent's ordinary use of
  the verbs, and the OS account stays the boundary (ADR-026 C-6).
- On upgrade, this machine's nodes that already share a room with the person's node trust each
  other, and the person's node gains drive over them (LT-9).
- A member with read only no longer learns that a node has Sessions, or their names.
- The Session opening and end records change on the wire and on disk, so v0.4.5 is to carry an
  upgrade for data roots written by v0.4.0 or later, and its proof (SA-5, SA-6).
- Scripts and documents that use `vox node attach` or `detach` keep working, and are told the new
  verbs (CW-7).
- A member without drive no longer stores or relays any Session's steps, and a member that joins
  late does not get a Session's earlier steps (SA-7, SA-8). An agent's long Sessions cost disk and
  sync only on the members that can read them, and only for the Session-step retention (SA-9).
- A room's Session steps are kept 7 days by default, never longer than its messages, where they
  were kept as long as its messages; rooms made before v0.4.4 lose their steps older than 7 days
  at its first start (SA-9).

## Open questions

- **A member of an earlier release in the room.** What a v0.4.4 node does when it receives a sealed
  opening or end record (skips it, refuses the entry, or poisons the room) is not known. It is to be
  measured with the shipped v0.4.4 binary before SA-3 is built. Peers of different releases keep
  syncing (ADR-034 UP-2 refuses a version difference only between a client and its own daemon), so
  a v0.4.4 member can receive sealed records from a v0.4.5 member, and the answer is to be brought
  to the decider before SA-3 is built. Measuring compatibility between versions, so that peers of
  different releases are handled safely, is planned for v0.4.5.

## Related ADRs

Depends on ADR-020, ADR-026, ADR-028, ADR-029. Amends ADR-014 (M-6, M-21), ADR-020 (2.1, 3.3, 3.7,
6.5), ADR-026 (N-6, L-2, F-3), ADR-028 (E-2, E-4, K-10, K-12, K-13, K-15, K-18, W-1, W-2, W-4),
ADR-029 (SE-5, SC-1, SC-2, SC-2a, SC-3, CL-2, CL-3, TA-1, RB-5, RB-5a), ADR-010 (AR-27, AR-28) and
ADR-007 (G-5's policy update). Cited: ADR-001, ADR-005, ADR-033, ADR-034.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
