# ADR-034: The App and the Daemon Never Hang or Hide a Failure

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.4 (the decider's Q&A, 2026-10-10, and his answers to this ADR's
open questions, the same evening; UP-2 and UP-3 revised with his story-plan answers that night;
FR-4–FR-6 from his ruling on the frame-length root cause that night; FR-7–FR-10 and WT-5 from the
fix's audit of every list reply, codified at his word that night). Nothing in this ADR is
built.
**Date**: 2026-10-10
**Deciders**: Robert E. Lee
**Tags**: daemon, app, ffi, ipc, update, storage, health, logs, progress
**Related**: ADR-008, ADR-010, ADR-014, ADR-016, ADR-018, ADR-025, ADR-026, ADR-028, ADR-029
**Inputs**: the decider's live session of 2026-10-10, his daemon log, and three root-cause
analyses of that day: the stuck room create, the poisoned room, and the IPC frame length. The
decider's ruling on them: fold the fixes into v0.4.4 with the redesign, with no separate fix
release. His answer on version refusal, revised that night: "for now I'm ok being simple -- if not
matching, don't attempt -- but later (0.4.5 maybe) we'll need a way to measure when we're
compatible and be less brittle" (UP-2); every other first choice "ok".

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
- **UP-2.** A client of a daemon (the app, the TUI, every verb and every hook) MUST refuse its own
  daemon when their versions differ, and MUST NOT attempt any other request on that connection.
  The decider: "if not matching, don't attempt". The refusal MUST be one plain sentence naming both
  versions and the action that fixes it ("Vox's daemon is 0.4.2 and this app is 0.4.4: restart the
  daemon"); the app MUST offer that action as a button. This applies only between a client and its
  own daemon: peers of different versions MUST be left as they are, and no node MAY refuse to sync,
  relay or send a room's entries to a peer because its version differs (the decider, 2026-10-10).
  Measuring when two versions are compatible, between a client and its daemon and between peers,
  is planned for v0.4.5 and is not part of this ADR.
- **UP-3.** When a client's and its daemon's versions differ, `vox status` and the app's status MUST
  name both versions.

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
- **WT-5. Reopened, not detached.** When a client drops a broken connection (WT-2, FR-3) and opens
  a new one, the node it acts as MUST stay Ready (ADR-031 CW-1): reopening a connection MUST NOT
  lock, detach or let go of the node, and the person MUST NOT be asked for anything.

### 3. Replies fit their frame

- **FR-1.** Every reply that lists things MUST be paged or bounded so that one reply always fits one
  frame: Session entries (by a cursor, and per Session), Sessions, snapshot lists, notices,
  decisions, members and shares. Every caller (the app, the TUI, `vox room session` and the rest)
  MUST page.
- **FR-2.** A reply that would exceed the frame limit MUST be sent as a plain error naming what was
  too large. The daemon MUST NOT write a frame over the limit.
- **FR-3.** A client that reads a frame over the limit, or one it cannot parse, MUST drop the
  connection (WT-2); it MUST NOT read the next reply from it.

The decider on the frame-length root cause (2026-10-10): "this feels like a footgun", "this isn't
even a long session wtf", "agents will often have MUCH MUCH MUCH longer sessions". Paging that only
fits a frame is not enough: a history may be any length.

- **FR-4. Never a whole history.** No client (the app, the TUI, any verb or hook) MAY fetch a whole
  Session or a whole room history. The app and the TUI MUST show the newest page and load an older
  page only when the person scrolls up to it. A verb that prints a history (`vox room session`
  and the like) MUST print one bounded page by default and say how to get the older ones.
- **FR-5. Pages from an index.** The daemon MUST serve each page from an index, by Session and by
  position, at a cost that does not grow with the history's length: it MUST NOT read, decrypt or
  decode a whole history to answer for one page. The memory the daemon uses to answer a page, and
  the memory the app uses to show a Session or a room, MUST be bounded by the pages shown, not by
  the history's length.
- **FR-6. Proof at scale.** FR-4 and FR-5 MUST be proved by real use of the shipped binary and the
  app's client on a Session of 100,000 entries: opening it MUST show the newest page within a
  stated time bound, each older page down to the first MUST load within a stated time bound, and
  the daemon's and the app's resident memory MUST stay under a stated bound throughout. The bounds MUST be written in the proof. Its mutant MUST make the
  client fetch the whole history and MUST turn the proof red on its own assertion, labelled
  PRODUCT.

The fix's audit of every list reply (framefix, 2026-10-10, night) found these unbounded: the
Sessions list (no count bound, and a member's session name and harness unchecked, so a row may be
64 KiB), Decisions (the app asks for `u64::MAX`; over the frame at about 800 events), the services
shared with a node, Unread (1,000 rows of up to 64 KiB each), a room's Order, and the room
snapshot's per-member lists (`read_by`, about 128 bytes × members², and `trusted_by`, about
members², over 128 KiB at about 63 members). Members and the share list fit. The decider: "I know
we're working on hot fixes -- but this needs to be codified into ADRs, projects/tasks, etc".

- **FR-7. Every list is paged.** Every reply that lists things and that the app, the TUI or a verb
  takes MUST be paged, with a cursor and a "more" mark, and every caller MUST follow it, at least:
  1. the Sessions list (`Sessions`);
  2. a Session's entries (`SessionEntries` and its page form);
  3. Decisions;
  4. Unread;
  5. the services shared with a node (`Services`);
  6. a room's Order;
  7. the room snapshot's per-member lists (`read_by`, `trusted_by`), which MUST be paged or taken
     out of the snapshot into their own paged request.

  A page MUST be bounded both in rows and in bytes, so that one page fits one frame even when a row
  an earlier release wrote is longer than FR-9's bound.
- **FR-8. Never truncated in silence.** No reply MAY drop rows without saying so. Where a reply is
  capped, it MUST say how many rows it left out, and every client MUST show it, for example "120
  older not shown".
- **FR-9. Bounded fields.** Every free-text field a member writes that ends up in a list row (a
  Session's name and harness, and every other such field) MUST have a length bound. A write over
  it MUST be refused, where it is written, with one plain sentence naming the field and its bound;
  it MUST NOT be cut short in silence. The bounds MUST be stated in the manual.
- **FR-10. An oversized reply is an error, not a desync.** FR-2's error MUST name the request
  whose reply was too large, and the connection MUST stay usable for the next request.

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
| ADR-014 M-29 | The update asks the person to restart the app and the daemon | The update restarts the daemon itself (UP-1); a client refuses a daemon of another version (UP-2) |
| ADR-014 M-21 | The menus as listed, with no Quit named | The Vox menu holds Quit Vox ⌘Q (QT-1) |
| ADR-028 A-4 | Quitting detaches the node, with no bound | Letting go of the node is bounded and never blocks quitting (QT-2) |
| ADR-034 FR-1, FR-2 (as first written) | Lists are paged or bounded; an oversized reply is an error naming what was too large | Every list the clients take is paged with a cursor and a "more" mark, by rows and bytes (FR-7); a cap says what it left out (FR-8); member-written list fields are bounded and refused over it (FR-9); the error names the request and the connection stays usable (FR-10); a reopened connection keeps the node Ready (WT-5) |
| ADR-034 FR-1 (as first written) | Lists are paged so a reply fits one frame | Also: no client fetches a whole history; the newest page first, older on scroll; pages from an index; proven at 100,000 entries (FR-4–FR-6) |
| ADR-026 C-4 | `Hello` reports the daemon's version | A client refuses its daemon when their versions differ and attempts nothing else (UP-2); both versions are named (UP-3); peers are unchanged |

## Consequences

- An update ends the held sessions (`vox serve`, `vox forward` and the like) running on the old
  daemon, and says so.
- Readers of long lists make more round trips, and a history opens at its newest page whatever its
  length (FR-4, FR-5).
- FR-7–FR-10 change only the protocol between a client and its own daemon, which UP-2 holds to
  one version, so peers of other releases are unaffected by them. FR-9 refuses only what this node
  writes; a longer field a peer of an earlier release wrote still arrives (an open question below).
- Quitting never waits on the daemon; a node the app could not let go of in time is reported at the
  next start.
- A client and a daemon of different versions do not work together until the daemon is restarted
  on the client's version, and the person is told which to restart.
- Peers of different releases keep syncing as before; nothing in this ADR refuses a peer for its
  version. Measuring compatibility between versions is planned for v0.4.5.
- A room that ran out of disk loses nothing written after space returns, and the person is told
  what happened.

## Open questions

- **FR-9's bounds.** The length bound for each member-written field (a Session's name, its
  harness and the rest) is not yet stated. What a node shows of a longer field that a peer of an
  earlier release wrote, cut with a mark or shown whole within FR-7's byte bound, is also open.
- **FR-6's bounds and weight.** The time and memory bounds are not yet stated by the decider, and a
  100,000-entry proof is heavy: whether it blocks the release or is an optional proof (the cargo
  feature `optional-proofs`, ADR-018) is the decider's call. Whether a room of 100,000 messages is
  proved the same way as a Session of 100,000 entries is also his.

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
