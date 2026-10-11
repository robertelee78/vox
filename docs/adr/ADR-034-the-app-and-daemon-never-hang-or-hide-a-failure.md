# ADR-034: The App and the Daemon Never Hang or Hide a Failure

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.4 (the decider's Q&A, 2026-10-10, and his answers to this ADR's
open questions, the same evening). Nothing in this ADR is built.
**Date**: 2026-10-10
**Deciders**: Robert E. Lee
**Tags**: daemon, app, ffi, ipc, update, storage, health, logs, progress
**Related**: ADR-008, ADR-010, ADR-014, ADR-016, ADR-018, ADR-025, ADR-026, ADR-028, ADR-029
**Inputs**: the decider's live session of 2026-10-10, his daemon log, and three root-cause
analyses of that day: the stuck room create, the poisoned room, and the IPC frame length. The
decider's ruling on them: fold the fixes into v0.4.4 with the redesign, with no separate fix
release. His answer on version refusal: refuse only on a real incompatibility, never on a version
difference alone (UP-2); every other first choice "ok".

## Context

On 2026-10-10 the decider pressed Create on a New Room sheet with a passphrase. The sheet then
showed an empty passphrase field, "No passphrase: anyone with the link can join." and a disabled
Create, and stayed so for more than four minutes, with no progress and no error. Three defects lay
under it:

- `vox update` replaced the app with 0.4.3 and left the 0.4.2 daemon running. The decider: "vox
  update replaced the app with 0.4.3, but the 0.4.2 daemon kept running <-- failure in our update
  process."
- A room's Session entries (2,331 of them) made an 837 KB reply to `SessionEntries`, over the
  256 KiB frame limit. The client failed without draining the reply, the app kept the desynced
  connection, and every later call, the create included, failed or waited without bound on the
  connection's lock.
- A store write failed during a disk-full episode, and the room was marked poisoned in memory,
  which nothing cleared but a restart. Its syncs then failed every few seconds, the log grew without
  bound and without timestamps or node names, and the agent's Session entries were dropped, while
  `vox status` said "healthy: nothing needs attention". The post said "an internal error — a bug in
  vox".

Later, Services showed a "Share a service" spinner that never resolved. And the app could not be
quit: the decider found no Quit ⌘Q in its menus ("command-q should be able to quit vox"; "but no
command-q option"; ⌘W closes the window). In the code, `applicationShouldTerminate` (VoxApp.swift)
returns `.terminateLater` while the app holds a node and
waits for `model.quit()` with no bound, so on a wedged connection quitting never ends either. Why
the menu item is missing is to be found when it is fixed. This ADR states, as requirements, what
each of these broke.

## Requirements

### 1. Updates

- **UP-1.** `vox update` and the app's update MUST stop the running daemon and start the new
  version's daemon as part of the update, so every remembered node comes back Ready (ADR-031 CW-3),
  and MUST say so in one sentence, naming any held session (ADR-026 L-7) the restart ended.
- **UP-2.** A client (the app, the TUI, every verb) MUST refuse a daemon only on a real
  incompatibility, found by negotiation: `Hello` (ADR-026 C-4) MUST carry the IPC protocol
  versions and the capabilities each side has, beside the version. The client MUST refuse when the
  two share no protocol version, and MUST refuse an action whose capability the daemon lacks, that
  action only. It MUST NOT refuse on a version difference alone. A refusal MUST be one plain
  sentence naming what is incompatible and the action that fixes it ("Vox's daemon (0.4.2) cannot
  page Session entries, which this app needs: restart the daemon"); the app MUST offer that action
  as a button. A `Hello` with no protocol list (from v0.4.3 or earlier) MUST be read as protocol 1
  with the capabilities of the version it names. The decider: "Ok starting point, but we might not
  always want to be so brittle."
- **UP-3.** When the client's and the daemon's versions differ, `vox status` and the app's status
  MUST name both, whether or not anything is refused.

### 2. No unbounded wait

- **WT-1.** Every request the app makes through `vox-ffi` MUST end within a stated bound, with its
  answer or with a sentence (ADR-028 E-7). No call MAY wait without bound on a lock, a connection or
  the daemon.
- **WT-2.** A connection that fails a transport step, or whose frames no longer line up, MUST be
  dropped and a new one opened. It MUST NOT be used again.
- **WT-3.** No error MAY be swallowed: every failure MUST reach the person who asked, as E-7's
  sentence, where the action was taken (ADR-014 M-7).
- **WT-4.** While the daemon cannot be reached, the app MUST show each node's state and the room's
  peers as unknown, never as last known, and MUST clear "the daemon stopped" once it is back.

### 3. Replies fit their frame

- **FR-1.** Every reply that lists things MUST be paged or bounded so that one reply always fits one
  frame: Session entries (by a cursor, and per Session), Sessions, snapshot lists, notices,
  decisions, members and shares. Every caller (the app, the TUI, `vox room session` and the rest)
  MUST page.
- **FR-2.** A reply that would exceed the frame limit MUST be sent as a plain error naming what was
  too large. The daemon MUST NOT write a frame over the limit.
- **FR-3.** A client that reads a frame over the limit, or one it cannot parse, MUST drop the
  connection (WT-2); it MUST NOT read the next reply from it.

### 4. A room that cannot save

- **SR-1.** A room whose store write failed MUST recover by itself once writes succeed again: it MUST
  retry with backoff and reopen its store, with no restart and no command.
- **SR-2.** While it cannot save, `vox status`, the room list in the TUI and the app, and the app's
  room MUST say so plainly, with the cause from the operating system, for example "repo-to-cve
  cannot save: the disk is full. It recovers by itself when space is freed." It MUST NOT be called
  a bug in Vox.
- **SR-3.** It MUST say when the room recovered.
- **SR-4.** A Session's entries MUST be held, not dropped, while its room cannot save, and written
  when it recovers. When the hold reaches its bound, Vox MUST say which entries were lost.
- **SR-5.** The fault MUST keep the operating system's error text.

### 5. Health is true

- **HL-1.** `vox status` and the app MUST NOT say healthy while a room cannot save (SR-2) or a peer's
  syncs all fail.
- **HL-2.** A peer whose every sync fails over a window MUST be shown as "sync failing", with the
  reason, and its syncs MUST back off (ADR-025), not repeat every few seconds.

### 6. Logs

- **LG-1.** The daemon's log MUST be bounded in size, and a line repeated many times MUST be written
  once with its count.
- **LG-2.** Every line MUST carry a UTC timestamp and the node it is about, and a room's id when it is
  about a room.
- **LG-3.** `vox status` and the app MUST name the log's path.

### 7. Every action ends

- **PR-1.** Every action in the app MUST show progress while it runs and MUST end with an outcome:
  what it did, or E-7's sentence. A control MUST NOT stay disabled without saying why.
- **PR-2.** No spinner MAY run without a bound; at the bound it MUST give way to a sentence. Sharing a
  service MUST list what can be shared, or say why it cannot.
- **PR-3.** The New Room sheet MUST keep what the person typed until the create ends, MUST show the
  create in progress, and MUST NOT say "No passphrase" for a room created with one.

### 8. Quitting

- **QT-1.** The app's Vox menu MUST hold **Quit Vox** with ⌘Q, and the proof MUST find it in the
  running app's menu bar by its words and its shortcut.
- **QT-2.** Quit Vox and ⌘Q MUST always quit the app promptly, whatever state the daemon, the node
  or the connection is in. `applicationShouldTerminate` MUST NOT await `model.quit()` without a
  bound: letting go of the node (ADR-028 A-4) MUST take at most a few seconds and MUST NOT block
  quitting; at the bound the app MUST quit anyway.
- **QT-3.** When letting go of the node did not finish within the bound, the app MUST say so at its
  next start, in one sentence naming the node and its state as the daemon reports it then.
- **QT-4. Proof.** A step of the app's proof (ADR-014 M-31, extending the first-run journey's quit
  step) MUST press ⌘Q on the running app with its daemon connection wedged, and MUST assert that the
  app's process has exited within the bound. Its mutant MUST restore the unbounded wait on
  `model.quit()` and MUST turn that step red on its own assertion, labelled PRODUCT.

### 9. Proof

- **PF-1.** Each claim above MUST be proved by real use of the shipped binary or the shipped app
  (ADR-018 §9), each with a mutant that turns its proof red on its own assertion, labelled PRODUCT
  (ADR-018 §10.10). A proof extends an existing journey where one fits (ADR-018 §10.7): the large
  room read for FR-1–FR-3, at the real frame limit, through both the CLI and the app's client.
- **PF-2.** A proof that needs a full disk MUST stage it in userspace, with no `sudo`. Where it
  cannot, it MUST print `OPTIONAL PROOF NOT RUN` (ADR-018 §10.2).

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-014 M-29 | The update asks the person to restart the app and the daemon | The update restarts the daemon itself (UP-1); a client refuses a daemon only on a real incompatibility (UP-2) |
| ADR-014 M-21 | The menus as listed, with no Quit named | The Vox menu holds Quit Vox ⌘Q (QT-1) |
| ADR-028 A-4 | Quitting detaches the node, with no bound | Letting go of the node is bounded and never blocks quitting (QT-2, QT-3) |
| ADR-026 C-4 | `Hello` reports the daemon's version | `Hello` also carries protocol versions and capabilities; a client refuses only when no protocol is shared or an action's capability is missing, never on version alone (UP-2); both versions are named when they differ (UP-3) |

## Consequences

- An update ends the held sessions (`vox serve`, `vox forward` and the like) running on the old
  daemon, and says so.
- Readers of long lists make more round trips.
- Quitting never waits on the daemon; a node the app could not let go of in time is reported at the
  next start.
- A client and a daemon of different versions keep working together wherever they share a protocol
  and the capabilities an action needs; the person sees both versions named.
- A room that ran out of disk loses nothing written after space returns, and the person is told
  what happened.

## Related ADRs

Depends on ADR-014, ADR-018, ADR-026, ADR-028. Amends ADR-014 (M-21, M-29), ADR-026 (C-4) and
ADR-028 (A-4). Cited: ADR-008, ADR-010, ADR-016, ADR-025, ADR-029, ADR-031.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
