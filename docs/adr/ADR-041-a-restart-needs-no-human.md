# ADR-041: A Restart or Update Brings the Daemon and Its Nodes Back by Itself

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
  of 2026-11-13 ("post review can accept them too"), after the sixth independent review by
  GPT-6.1-Sol found it ready for acceptance (`adr-041-sol-review-6.md`). This is design
  acceptance only: implementation, acceptance and delivery are recorded on the source-bound
  issues, separately from decision status, and the receipts the review lists as owed stay owed.
  Revision 6, after five earlier independent reviews
  (`adr-041-sol-review.md`, twenty findings, "needs redesign";
  `adr-041-sol-review-2.md`, fourteen findings, "needs revision";
  `adr-041-sol-review-3.md`, seven findings, "needs revision";
  `adr-041-sol-review-4.md`, four findings, "needs revision";
  `adr-041-sol-review-5.md`, two findings, "needs revision") and the decider's answers
  of 2026-11-13 (ledger rows 43–47). **Accepted 2026-11-13 after the sixth review**; revision 7
  completed proof specifications found missing when the ADR was cut into tasks
  (`v0431-tasks-ADR-041-sol-review.md`); revision 8 carries the cross-ADR asks
  (`adr-cross-asks.md`, target ADR-041), the correction batch
  (`adr-correction-batches.md`), the decider's answer on root inside the test VM (ledger
  row 69), and ledger row 64's lost-receipt notes; revision 9 is two wording corrections after
  ADR-050 r11 passed its review (`adr-041-pending-r9.md`); re-checked by the same
  reviewer. Revisions 7–9 change no design decision and none of the decider's answers; the
  requirements they touch are marked **(r7)**, **(r8)** and **(r9)**. The decider's rulings this ADR carries are listed under that heading with
  their source; everything else is this ADR's proposal from plan F (fix-list items 39–48, 81).
  Nothing here is built: each requirement is to land with its proof. The former open questions
  are now "The decider's
  answers (2026-11-13)". Requirements changed in revision 5 are marked **(changed r5)**, earlier
  revisions **(changed r4)**, **(changed r3)**, **(changed)**. The file keeps its name; the
  title changed at revision 5 (ledger row 47).
- **Date**: 2026-11-12
- **Deciders**: Robert E. Lee
- **Tags**: daemon, restart, update, passphrase, keyring, sessions, coordination, profile, updater
- **Related**: ADR-014, ADR-018, ADR-021, ADR-026, ADR-028, ADR-029, ADR-031, ADR-034, ADR-038,
  ADR-040, ADR-042, ADR-043, ADR-044, ADR-045, ADR-047, ADR-050

## What this ADR sets out to do, and the rulings it carries

**This ADR's goal, not a ruling.** Earlier revisions put "a restart needs no human" at the top as
the decider's rule. It was the v0.4.31 plan's summary of plan F, and the decider said of it on
2026-11-13: "I don't know what this requirement is I don't know that I specified this
requirement" (ledger row 47). What he did hit, on Nov 11 and 12, is the Context below: after a
restart every OMP conversation had to be re-attached by hand (C2), a Linux node needed its
passphrase typed again (C1), and nothing brought the Mac's daemon back for two minutes when it
died (C4). This ADR's goal, in its own words, is that **a restart or an update brings the daemon
and its nodes back by itself**, wherever a remembered store can hold the node's secret and a
service manager is enrolled for the root, and that **a client and its daemon, and workers in a
room, agree by contract version, not package version** (C6, C7), and that **a daemon serves the
directory it opened, never a path or a name** (C8, C10). The last two were likewise the plan's
phrasing; neither has a quote from him, so neither is attributed to him here.

**The decider's rulings this ADR carries**, each with its source:

1. 2026-11-13, ledger row 43 (Q1): a Linux node after a reboot comes back from a systemd
   credential sealed to the TPM where systemd ≥ 258 and a TPM exist, otherwise from a passphrase
   file as today; not "one unlock per boot". (RS-3)
2. 2026-11-13, row 44 (Q2): claims made on v0.4.30 are kept across the update. (RS-10)
3. 2026-11-13, row 45 (Q3): the start-over command exists, is named `vox factory-reset`, and
   requires an approval follow-up before it acts. (RS-15)
4. 2026-11-13, row 46 (Q4): when the enrolled manager knows the job and refuses to start it, the
   client starts a daemon itself and `vox status` says `unsupervised`; one daemon per root still
   holds and the manager's refusal is named. (RS-5)
5. 2026-11-13, row 47 (Q5): a root with no enrolled manager (beast, IO today) gets its daemon
   back at the next client, shown as `unsupervised`; no managed service is required there. (RS-5)
6. 2026-11-13, row 18: all machines move to 0.4.31 together; no mixed-version support. (RS-2's
   cutover arm, RS-12)
7. 2026-11-13, row 32: the whole release gate, in-tree arms included, runs inside the VMs; every
   proof here is staged in the macOS guest or the Linux VM. (every proof)
8. 2026-10-21, ADR-038 FX-34, "that's ok as long as I can actually unlock them": Vox never writes
   a passphrase file on its own; a file is the person's choice. (RS-1, RS-3)
9. 2026-11-12, AGENTS.md: no agent changes the Vox version or restarts a daemon on his machines
   without his explicit go. (Unchanged rulings)

His words on Nov 12, after a day of this: "I need a Vox that actually works."

## The design in one paragraph

Revision 1 proposed that a restart replaces the daemon in place (`execve` of the new binary by the
running process, with the node passphrases handed across the exec); the first review showed that
hand-over unsound and revision 2 dropped it. The secret lives outside the process (the login
Keychain on macOS, the kernel's per-user persistent keyring on Linux, RS-1), so **the daemon
process is disposable**: a restart or an update is a stop and a start. One lease,
`<data root>.control/restart`, is held only by the process about to take the daemon's lock, from
just before that attempt until its remembered nodes are terminal; nobody tries the lock without
it, and nobody who finds it held tries the lock (Terms). A daemon a client started re-checks,
under the lease, whether a manager is enrolled for the root and yields to it (RS-2), so a stale
client start never takes a managed root; where the enrolled manager refuses to start its job, the
client's daemon serves `unsupervised` until the manager's own daemon arrives and takes the root
over by a product stop (RS-5, the decider's Q4). Where a manager is enrolled, a restart is one
request to it (`launchctl kickstart -k`, `systemctl --user restart`), announced beforehand in the
control directory so the stop reads as planned (RS-7); where a client-started daemon serves a
managed root (the operator's Mac today), the manager's daemon is started and takes the root over
itself; where none is enrolled, the replacement daemon is started first and does the stop itself
(RS-2). Enrollment is control plane, written by whatever can see the job is registered (RS-5). A
manager's daemon comes back after any death because every stop that is not a product request is
a foreign one, answered with an exit status the manager restarts (RS-5). The one update from
v0.4.30 stops its protocol-11 daemon the way v0.4.30 did, by SIGTERM, and that arm leaves at
v0.4.32 (RS-2). `vox factory-reset` moves the data root aside under the same lease, with a
journal in the control directory that records the root's identity, after an explicit
confirmation (RS-15). What remains of "hand over" is the updater judging the process itself
(RS-16).
## Context

On Nov 11 and 12 the operator ran v0.4.26 to v0.4.30 on four machines: his Mac, beast (Ubuntu
26.04), IO and vince's. Every restart and every update of a daemon needed a person. This section
gives each problem as he saw it, then its cause at tag v0.4.30 (commit 8d71ab337), with a status:

- **KNOWN**: reproduced on a release binary, or read directly off his machines; the run directory
  or evidence file is named.
- **INFERRED**: fits the evidence; not reproduced.
- **UNKNOWN**: not explained; the experiment that settles it is named.

Paths below are under `crates/vox-tui/src/` unless they say otherwise. Evidence files under `mac/`,
`beast/`, `io/` and `cleanup/` were in `/private/tmp/vox-rca/`; run directories `run-*` were
RcaSessions' (`/tmp/rca-RcaSessions/`) unless named. **Every receipt under `/tmp` or
`/private/tmp` cited in this ADR was lost in the reboot of 2026-11-13 (ledger row 64); each
figure is recorded in the report that cites it (`rca-RcaSessions.md`,
`rca-RcaStore.md`, `rca-RcaAppQuit.md`, `rca-RcaTrust.md`,
`plan-F.md`, `adr-041-revision.md`) and is to be re-run as the fleet baseline
(ADR-045 FG-9).** Sample output below uses documentation paths; no real address, port or home
path of the operator's appears outside sample output.

### C1. beast is Locked after every restart (item 39)

**What he saw.** After `vox daemon --restart`, after `vox update`, and after a daemon death, beast
showed:

```
node omp-beast  Locked
Unlock with vox node unlock omp-beast
```

Every OMP conversation on beast was unavailable until someone typed the passphrase. In run `c1`
(the release binary in a Linux container, a node unlocked by typing, as on beast) recovery took
92 s with a person at the keyboard; without one it never comes. Unlocking by typing on Linux
prints (`client.rs:962-965`):

```
vox: node omp-beast is not remembered: after the daemon restarts, unlock it again with `vox node unlock omp-beast`
```

**Cause (KNOWN; code, and `beast/facts.txt`: beast's `.daemon/attach` is 0 bytes).**

- Off macOS, `keychain::store` and `keychain::read` always fail with `NOT_HERE`; only `forget`
  succeeds (`keychain.rs:155-182`). `node_unlock` gives a typed, piped or
  `VOX_IDENTITY_PASSPHRASE` passphrase no keep source off macOS (`client.rs:866-873`); only
  `--passphrase-file` is remembered.
- A restart, an update and a rollback all run `restart_checked` (`update/restart.rs:348-561`):
  read `.daemon/attach` (371-384), SIGTERM the old daemon (516), start a new one (527), wait for
  the kept nodes (605-652). The new daemon attaches only from attach-file sources
  (`host.rs:4550-4597`). Nothing passes the unlocked key or the passphrase from the dying daemon
  to the next. The secret dies with the process.
- Why it is so: ADR-028 K-10 was written for the macOS Keychain, and ADR-038 FX-34 ruled that
  Linux remembers nothing "for now" (the decider, 2026-10-21: "that's ok as long as I can actually
  unlock them"). ADR-026 D-1 and S-2 make a restart "stop, then start", with no hand-over step.

**Why no proof caught it.** `the_daemon_and_its_nodes_proof.rs:552`
(`a_kept_node_and_its_room_come_back_after_a_restart`) removes the passphrase file before the
restart on macOS only (`:751-753`): on Linux the plaintext file stays, so "comes back with nobody
typing" was never proved there. `a_passphrase_is_asked_for_or_refused_at_once_proof.rs`
(`a_locked_node_is_unlocked_without_a_persistent_file`, described at `:25-37`) asserts that on
Linux the node is Locked again after a daemon start: it asserts the defect.

### C2. A restart tells every conversation to create a node (item 40)

**What he saw.** About 40 ms after any daemon restart (37 ms in run `a4`), every OMP conversation
showed (`crates/vox-tui/assets/omp-extension.ts:444`):

```
Vox: node omp-work is unavailable. If it has not been created, run `vox node create -- omp-work`; otherwise run `vox node unlock -- omp-work` in a terminal. If the daemon is not answering, restart it. Creating a node makes a new identity.
```

During an update it also showed `Vox update mismatch; update Vox and restart the daemon`
(`omp-extension.ts:440`), telling him to do what was already being done. Each Session in the room
got `OMP observation stopped: the native bridge connection closed; pending control outcomes are
unknown` (Mac log at every restart; beast 10–14 per restart). Nothing ever said it recovered. The
conversations were not dead: they recovered by themselves 2.3 s after the restart in `a4` and
2.8–3.3 s across an update in `b1`/`b2`; on his Mac, where restarts took 12–29 s, up to about a
minute. He restarted each conversation by hand because of the text.

**Cause (KNOWN; runs `a4`, `b1`, `b2`, `c1`, `d1` on the release binaries with the real
extension).** When its daemon subscription ends, `vox agent omp-watch` emits
`{"type":"unavailable","reason":"unavailable"}` at once, before any probe (`omp_watch.rs:274`). It
emits the same frame for "node not attached" and "no daemon" (`omp_watch.rs:319`). The extension
turns the first such frame into the advice above (`omp-extension.ts:437-445`). One word stands for
three states: the daemon is restarting, the node is Locked, the node is missing. On the daemon
side, `omp_mirror.rs:1001-1023` posts "observation stopped" into the Session whenever the bridge
drops, planned or not.

**Why no proof caught it.** No proof drives the real `omp-extension.ts`: none spawns
`vox agent omp-watch`. RcaSessions had to build a host shim to see it.

### C3. A hook starts a second daemon during the restart (item 41)

**What he saw.** A prompt typed while the daemon restarts makes the hook start its own
`vox daemon --as-detached --listen 0.0.0.0:0`. The planned replacement then finds the lock taken,
or restarts it again: two outages, two "observation stopped" per Session. Run `d1`: the first
prompt's `--attention-register` started its own daemon 0.4 s into the window. Run `h2`: five
daemon generations in 23 s.

**Cause (KNOWN; code and runs `d1`, `h2`).** `ensure_daemon_for_hook` (`daemon_client.rs:96-137`)
spawns `current_exe()` (`:127`) when it cannot open the control socket. (A socket that accepts and
does not greet within 500 ms, `HOOK_WITHIN` at `:22`, is answered `Unanswered` at `:109` and
spawns nothing.) The only "one daemon" guard is the lock taken inside the spawned daemon
(`daemon.rs:410-415`, ADR-026 D-1). `restart_checked` orders stop, wait until gone (`restart.rs:518`),
start (`:527`): for the whole stop (0.5–3 s measured, up to 30 s allowed) the lock is free, the
socket is gone, and nothing on disk says a replacement is coming. ADR-026 S-2 ("a client … that
finds no daemon MUST start `vox daemon --detach`") was written for a cold start and never
qualified by "unless one is being replaced".

### C4. The Mac's daemon stopped and nobody brought it back for two minutes (item 47, and a finding off the list)

**What he saw.** Nov 12, 20:28:50.556Z: the Mac's daemon logged `shutting down on SIGTERM`, then
`stopped by SIGTERM` at 20:28:53.813Z. Nothing served until `control socket …` at 20:30:50.684Z;
`robert-work is Ready` at 20:30:51.2Z, `omp-work is Ready` at 20:31:21.7Z. A doctor taken at
20:30:50Z said "no vox daemon is running" (`mac/doctor-omp-work-203050Z.txt`). IO could not reach
the Mac from 20:30:11Z to 20:30:52Z (`io/daemon-210921Z.log:1-32`). Every conversation saw C2's
text.

**What stopped it: sender UNKNOWN; a product path INFERRED unlikely.** The stopped daemon was pid
38806, `~/.local/bin/vox daemon --as-detached --listen 0.0.0.0:0 --data-dir ~/Library/Application
Support/vox`, started 20:19:48Z, parent pid 1 (`cleanup/daemons-detail.txt`). Every product code
path that sends a daemon SIGTERM is `restart.rs:516` (restart, update, rollback, and the app's
Restart Daemon, which runs `vox daemon --restart`: `apps/macos/Vox/AppModel.swift:220-231`),
`restart.rs:278` (the macOS bundle hand-off) and `uninstall.rs:374`. The first two start a
replacement in the same process within seconds, and the app's or the bundle's replacement would
carry the bundle path (`apps/macos/Vox/Daemon.swift:194-196`); a 117 s hole followed by a
PATH-`vox` replacement fits none of them. They are not excluded: `restart_checked` has a window
between its SIGTERM and its start (`restart.rs:516-527`) in which the restarter itself can die or
be killed (the app's command watchdog kills the command, `Daemon.swift:221-264`), and a later
hook would then start the PATH helper exactly as seen. The daemon's own exits (idle, root gone, a
`Stop` request) log "stopped", not "shutting down on SIGTERM" (`daemon.rs:727`), so the stop was a
signal; whose is unrecorded: the log line names only the signal (`daemon.rs:727`). Experiment
`sig` (plan F, a 20-line `SA_SIGINFO` program) showed that macOS delivers the sender's pid and uid
with `kill -TERM`. No experiment can name the Nov 12 sender after the fact; RS-6 makes the next
one name itself, and RS-5 makes the gap not depend on who sent it.

**What brought it back, and why 120 s (KNOWN what; INFERRED who).** The replacement, pid 67845,
started 20:30:50Z as `~/.local/bin/vox daemon --as-detached --listen 0.0.0.0:0 …` with cwd
`/opt/vox` (`cleanup/daemons-detail.txt`, `daemons-now.txt`). `~/.local/bin/vox` is a symlink to
the bundle's helper, and a client-started daemon carries the path its client was invoked by
(`daemon_client.rs:127,186`; plan F experiment `exe`). So a client that ran `vox` by PATH from
`/opt/vox` started it, through `ensure_daemon_for_hook` or `ensure_daemon` with
`listen = DEFAULT_LISTEN = 0.0.0.0:0` (`client.rs:38`). The OMP extension's hook
(`omp-extension.ts:323`) for a conversation in `/opt/vox` is the likely client; a terminal in
`/opt/vox` fits the same shape. The 120 s was the time to that client's next request. No timer of
120 s exists in the extension, the hooks or the daemon. The product has no owner of "bring the
daemon back": the login item's `KeepAlive` is `{SuccessfulExit: false}`
(`apps/macos/Bundle/LaunchAgents/us.vox.daemon.plist:18-22`) and a clean SIGTERM stop exits 0, so
even a login-item daemon would have stayed stopped.

**The finding off the list (KNOWN that it happened; why the job exits is UNKNOWN).** The Mac's
app config says `login-item: keep`, yet the daemon of record was a hook-started `--as-detached`
daemon from at least 20:19:48Z, and again at 22:12:02Z (pid 30063, same shape). The read-only
inspection was run on Nov 13 with his go (ledger row 21): the job `gui/502/us.vox.daemon` exists,
is enabled and managed by ServiceManagement (`vox daemon --no-node --login-item`, parent bundle
us.vox.app 1.4.14), its state is "not running", it has run 15 times, its last exit code is 0 and
its semaphore is `successful exit => 0`; the serving daemon is pid 54418, ppid 1,
`~/.local/bin/vox daemon --as-detached …`, hook-started 02:16:47Z; no
`~/Library/Logs/Vox/login-item.log` exists. So the login item is started, exits 0 while a
detached daemon serves, and nothing owns the serving daemon. Why it exits 0 instead of waiting
(`daemon.rs:180-208`) is UNKNOWN; `refused_for_good` is ruled out (it would have written the
log). The settling experiment runs in the macOS guest, never on his Mac: bootstrap the 0.4.30
bundle's job with a detached daemon serving and read the job's stderr. beast, the same day: no
vox unit of any kind, user or system; its daemon is pid 1940300, ppid 1, `vox daemon
--as-detached`, in `user.slice/user-1000.slice/session-2824.scope` (a login-session scope, kept
alive by `Linger=yes`); kernel user keyring `_uid.1000` present; systemd 259. Earlier notes that
said beast's daemon ran "under systemd" were wrong.

### C5. Registrations of dead conversations are never removed (item 42)

**What he saw.** At every restart beast's log has `OMP Session <id> observation stopped: the
native bridge connection could not be opened` for 7 sessions whose OMP was long gone (24 such
lines, `beast/daemon-current.log:680,1432,1666,1697-1698`, …). `.daemon/omp-instances` held 36
directories (`beast/facts.txt`). `vox agent doctor` on the Mac listed 8 sessions as "its wake
endpoint is gone" (`mac/doctor-omp-work-203050Z.txt`). `vox room sessions` shows phantoms.

**Cause (KNOWN; code and the evidence above).** A registration (`wake.rs:393` `Session`, file
`nodes/<node>/sessions/<id>`) is removed only by `forget` (`wake.rs:1352`) on the extension's
orderly shutdown with `cleanupCertain` (`omp-extension.ts:468-479`). The fence directory
`.daemon/omp-instances/<instance>` likewise (`omp_fence.rs:181-209`; "lock inodes are retained
unless the extension proves cleanup is safe", `:211`). A killed OMP, a crash or a sleep that ends
the bridge leaves both forever. At start the daemon follows every registration
(`host.rs:2084-2218` `open_registered`) and posts "observation stopped" when the bridge is gone,
never marking the registration dead. ADR-026 L-5 deferred the sweep that would remove them.

### C6. Claims vanish after an update; an old worker freezes everyone (item 43)

**What he saw.** After `vox update`, `vox room board` showed nothing claimed. A session on a
machine not yet updated froze every claim in the room ("coordination refused … runs vox 0.4.29")
until it happened to announce again (`01a1cbec…` at 16:54:22Z). A claim made on 0.4.29 never came
back.

**Cause (KNOWN; code and runs `b1`, `b3`).** `coord.rs:880` stamps every coordinating post with
`data.vox`, the package version. `stamp_of` compares by exact string equality
(`crates/vox-agentcomms/src/version.rs:123-131`). The fold applies only ops whose stamp equals its
own package version; every other op becomes `Outcome::OtherVersion` (`claim.rs:375-385`). The
version table refuses when any participant's latest counted record carries another stamp
(`version.rs:190-244`). Run `b1`: board before the update `unit-before`; after it only
`unit-after`. Run `b3`: `board after drains: nothing is claimed`. ADR-021 §5 chose this for "one
operator who … upgrades them together" (`version.rs:1-16`). `git diff v0.4.26 v0.4.30 --
crates/vox-agentcomms` is empty: the fold rules never changed across the versions that refused each
other.

**Why no proof caught it.** `work_version_proof.rs` proves the refusal works, which is the defect.

### C7. A restarted conversation is silent until it claims (item 44)

**What he saw.** After an update, a conversation restarted with a new session id announced its
version only when it claimed. Until then every peer refused, for minutes, or for ever if it never
claimed.

**Cause (KNOWN; code and run `b3`).** The drain hook announces only a session that announced
before (`agent_hook.rs:4031`; `coord.rs:350` `announced_before` requires a counted record of that
exact session id). A verb announces only when it coordinates (`coord.rs:1043-1046`). ADR-021 5.4
says it: "The drain hook and idle clients do not announce." `work_version_proof.rs:497-514`
("b-silent") asserts that silence as intended.

### C8. "Start over" left an old daemon writing into the new profile (item 45)

**What he saw.** On Nov 11 at 00:57 local he started his profile over while a daemon was running.
The new omp-work worked for 100 minutes. From 11:09:46Z every daemon start said:

```
vox daemon: could not make remembered node omp-work Ready: node omp-work: could not unlock its identity: an internal error — a bug in vox, not something you did
```

and the app's Unlock said `vox: could not unlock the identity: node: vault identity does not match
the store`.

**Cause (KNOWN; rca-RcaStore reproduced it in `/tmp/rca-RcaStore/repro2/` on the v0.4.26 release
binary (receipt lost in the reboot of 2026-11-13; figure recorded in `rca-RcaStore.md`;
to be re-run as the fleet baseline); `profile.rs`, `store.rs` and `leave_save.rs` are
byte-identical at v0.4.30).** Four
defects:

- The login-item daemon polls `take_account` by path every 250 ms (`daemon.rs:180-208`);
  `try_lock` opens and creates `.daemon/lock` by path (`crates/vox-core/src/node/paths.rs:320-346`).
  A replaced root has a free lock, so a second daemon served the new root while the old one (pid
  57505) kept running on the old inodes.
- The old daemon's only "root gone" guard is `!account.daemon_dir().exists()` by path
  (`daemon.rs:318-321`). The new daemon recreated `.daemon/` within the same second.
- The store keeps its absolute path (`crates/vox-core/src/node/store.rs:585`). `rewrite_fresh`
  writes `<path>.rewrite` and renames it over `<path>` (`store.rs:792-794,876`). A retained leave's
  purge calls it (`crates/vox-core/src/node/actor/leave_save.rs:348`). So the old daemon's purge
  replaced the new omp-work's 1 MB store with a 2.1 GB store of the previous identity. Other
  writers land by path too: `room_pause.rs:233` (pause locks), `decisions/`, `files/`, `pulls/`.
- `Profile::open_noting` trusts whatever `store.redb` sits beside `vault.cbor`
  (`crates/vox-core/src/node/profile.rs:269-300`; it reads the store's fingerprint at `:282`). The
  mismatch is found only at unlock (`profile.rs:311-314`) and reported as "an internal error".

Why: identity by path is the original design (ADR-026 D-1: "an exclusive lock on `<data
root>/.daemon/lock`"); nobody wrote the rule "a daemon serves the directory it opened, not the
name".

### C9. The updater said the app "did not quit within 30 seconds" (item 46)

**What he saw.** Three `vox update` runs on Nov 11 (macOS 27.2 26B5091g) each failed:

```
vox: application handoff for /Applications/Vox.app failed: … application pid 84218 did not quit within 30 seconds (-2700); previous installation and startup intent restored
```

Each left a new Vox instance running. The fourth, with the app quit by hand, succeeded
(rca-RcaAppQuit). The 30 s poll and its error are the 0.4.28 engine's, the one those updates
ran; it is not a reproduced v0.4.30 failure.

**Cause: which of two readings is UNKNOWN; the faulty verdict is KNOWN.** The updater's stop
(`update/bundle.rs:3925-4008` at v0.4.30) asks AppKit to terminate the app, then polls
`app.isTerminated` and `NSRunningApplication` for 10 s (`:3975-3988`), then `forceTerminate`,
then SIGKILL (`:3992-3993`, added in v0.4.30 on the same source), and throws when its observer
still says the app is there. Every liveness answer comes from LaunchServices; none from the
kernel. His app closed its WindowServer connection at most 2.9 s after each quit
(`mac/unified-pids-1450.log`), and the engine's own fresh inspection at +37 s found no app.
TextEdit under the same script on the same Mac stopped in 0.30 s (`mac/textedit-probe-28.out`).
Reading A: the process outlived its windows by at least 27 s (v0.4.30's SIGKILL would end it and
the update would succeed, saying "stopped"). Reading B: it exited at +2.9 s and that `osascript`
never learned it (v0.4.30 would throw after its SIGKILL of a gone pid). Settles it:
`bash /private/tmp/vox-rca/vox-quit-probe.sh` on his Mac, with his go (it quits his app once;
the script and the `mac/` evidence it reads were lost in the reboot of 2026-11-13, so the probe
is to be re-created from `rca-RcaAppQuit.md` before it is offered).
RS-16 does not wait for it: it is right under both readings.

### C10. A conversation kept running as a different identity after a rebuild (item 48)

**What he saw.** After the Nov 11 start-over (new omp-work identity `lp3juw…`), conversations
opened before it (Main's own, from Oct 28, among the registered ids in
`mac/daemon-current-200453Z.log:2486-2492`) went on draining, claiming and being woken as the new
identity. Their Sessions, claims and cursors from the old identity were gone, and nothing told
him.

**Cause (KNOWN; code and his registered sessions).** A conversation is bound to a node name: every
hook runs `vox agent hook --node omp-work` (`omp-extension.ts:323`), and the registration
(`wake.rs:393`) records no identity. The one identity pin, the watcher's fence (`omp_watch.rs:62-64`,
`omp_fence.rs:265-282`), is per watcher process: the next OMP restart makes a new watcher that pins
the new identity and registers the old conversation on it.

### What these have in common

Three rules were missing:

1. **Nothing owns "the daemon is being replaced".** A restart is a stop and a start; the secret,
   the lock and the socket all die in between, and any client may fill the gap (C1–C4).
2. **Versions are compared as package strings.** Two builds with identical rules refuse each other
   (C6, C7).
3. **Identity is a path or a name.** A daemon writes into whatever folder now has its old path; a
   conversation acts as whatever node now has its old name (C8, C10).


## Terms

- **Daemon of record**: the daemon that holds `<data root>/.daemon/lock` now.
- **Control directory**: `<data root>.control`, a sibling of the data root named from its path
  (on a default Mac `~/Library/Application Support/vox.control`; on Linux
  `~/.local/share/vox.control`; for `--data-dir /tmp/x/data`, `/tmp/x/data.control`). It holds
  the restart lease, the manager enrollment and the reset journal, and is never moved, copied or
  reset: `vox factory-reset` renames `<data root>` and leaves it where it is. It is not the config dir,
  which on a default Mac *is* the data root (`paths.rs:837-858`: both default to
  `~/Library/Application Support/vox`), so nothing that must survive a reset may live there.
- **Manager**: launchd running the app's login item (`us.vox.daemon`, ADR-014 M-8) on a Mac, or
  systemd running a user unit on Linux whose main process is the daemon. A root's manager is
  **enrolled** in `<control dir>/manager` (RS-5); `restart.rs:770-794` (`how_started`) still
  says how a running pid was started.
- **Restart lease**: `<control dir>/restart`, an `flock`ed file with one rule: **a process takes
  the lease immediately before it tries to take `.daemon/lock`, and no process tries the lock
  without holding the lease.** A daemon holds it from just before its lock attempt until its
  kept nodes are terminal, then releases it; a waiting daemon (ADR-014 M-9) takes it for each
  attempt and releases it when the attempt fails; `vox factory-reset` takes it because it takes the lock
  itself (RS-15). A process that finds the lease held by another never tries the lock: a daemon
  started by a client exits saying another is starting, a waiting daemon waits, a client or hook
  waits for the socket (RS-5), the OMP watcher reports `starting` (RS-7). A lock dies with its
  process, so nothing stale survives a crash; what a crash leaves undone is stated per step in
  RS-2 and RS-15. Nothing is inherited across a spawn (`daemon.rs:95-101` closes inherited
  descriptors): every holder takes it itself.
- **Product stop**: `DaemonRequest::Stop { reason }` over the authenticated control socket
  (`daemonipc.rs:442` today, without a reason). A signal is never a product stop (RS-5). The one
  exception is the cutover from v0.4.30, whose daemon speaks protocol 11: RS-2 names it.
- **Remembered store**: where Vox keeps a node's passphrase so a new daemon, whatever its pid, can
  make the node Ready with nobody typing: the login Keychain on macOS; on Linux the kernel's
  per-user persistent keyring (RS-1). It is never a file Vox writes.
- **Registration**: a conversation's file under `nodes/<node>/sessions/<id>` (`wake.rs:393`).
- **Fence instance**: one OMP watcher's directory under `.daemon/omp-instances/`; its `lifetime`
  file is locked by the watcher process (`omp_fence.rs:244-245`), not by OMP itself.
- **Wake endpoint**: the socket the extension serves for one conversation (`Session.endpoint`,
  `wake.rs:398`); it belongs to the OMP process.
- **Claim-protocol level**: one integer that names the claim fold's rules. It changes only when the
  rules change. It is not the package version.
- **Control-protocol number**: the integer a client and its daemon compare at hello
  (`crates/vox-core/src/node/ipc.rs:83`, `PROTOCOL_VERSION`, 11 at v0.4.30; 12 after this
  release, RS-12).
- **Incarnation**: the instant a daemon process started, carried in its hello.
- **Terminal node state**: Ready; Locked (needs its passphrase, or its remembered source is gone);
  rewriting its store (ADR-047 SO-10, reported, not Ready); missing. Attaching is not terminal.

## Requirements

### 1. Nodes come back Ready with nobody typing

- **RS-1. Linux remembers a node in the kernel keyring (changed r4; r7; r8).** On Linux, `vox node unlock`
  with a passphrase typed, piped, or taken from `VOX_IDENTITY_PASSPHRASE` MUST store that
  passphrase in the kernel's per-user persistent keyring, never on disk, and MUST say "remembered"
  only after the key is stored and the keep record is saved. A daemon restart, an update and a
  daemon crash MUST then make the node Ready with nobody typing, for as long as the key is in the
  keyring. Where the kernel refuses, or the keyring's configured expiry is too short to keep,
  unlock MUST say so, MUST say what that costs, and MUST NOT promise a restart it cannot keep.
  `vox node lock` MUST remove the key.
  - *Why:* item 39 (C1).
  - *Changes:* `keychain.rs`'s Linux arm is to use the persistent keyring
    (`persistent-keyring(7)`, `keyctl_get_persistent(3)`, `add_key(2)` type `user`):
    - Every call first runs `keyctl_get_persistent(getuid(), KEY_SPEC_PROCESS_KEYRING)`, which
      creates the uid's persistent keyring if absent, links it into this process's keyring, and
      resets its expiry. The link is per process, so each fresh program (a new daemon, every
      `vox node unlock`) does it before it searches, adds or unlinks.
    - `store` adds `us.vox.node:<account>` to the persistent keyring with permissions
      `0x3f030000` (all rights for a possessor, view and read for the uid, nothing for group or
      other), replacing an existing key of that description; `read` searches the persistent
      keyring by type and description; `forget` unlinks it. The order at unlock is today's
      (`host.rs:1570-1648`): the node is attached and verified, the store is written, then the
      keep record; a failed store leaves no keep record.
    - The daemon reads `/proc/sys/kernel/keys/persistent_keyring_expiry` (seconds; default
      259200) at start and before each refresh, and repeats `keyctl_get_persistent` every
      `min(expiry / 4, 12 h)` while any node it holds is remembered there. An expiry under 10
      minutes is "too short to keep": `store` refuses with the text below. After each refresh the
      daemon searches for every remembered node's key; a key that is gone (expired, revoked or
      unlinked by another process) is logged and the node is shown `Ready, no longer remembered
      (keyring: Required key not available); unlock it again to remember it` by `vox node list`.
      The daemon does not retain the passphrase, so it cannot re-store it.
    - The keep source in `.daemon/attach` stays `Keychain(<account>)`, so `host.rs:4550-4597` is
      unchanged on this path.
    - Errors name the syscall and the kernel's errno text as given, never a guessed one:
      `add_key: Operation not permitted` (seccomp `SCMP_ACT_ERRNO` with EPERM, Docker's
      default), `add_key: Function not implemented` (ENOSYS: podman's current default action, or
      a kernel without keyrings), `add_key: Disk quota exceeded` (the uid's key quota,
      `/proc/sys/kernel/keys/maxbytes`). Unlock is to print, when the key is stored:

    ```
    vox: node omp-beast is Ready and remembered in this computer's memory (the kernel keyring): restarts, updates and crashes need nothing typed. After the computer itself restarts, unlock it once.
    ```

    (The last sentence changes with Q1.) When the kernel refuses or the expiry is too short:

    ```
    vox: node omp-beast is Ready but not remembered: this system refuses the kernel keyring (add_key: Operation not permitted). After a daemon restart, an update or a crash, unlock it again, or name a passphrase file: vox node unlock omp-beast --passphrase-file <path>
    ```

    Docker's default seccomp profile lists none of `add_key`, `keyctl`, `request_key` (refused
    with EPERM); podman's (containers/common `pkg/seccomp/seccomp.json`, read 2026-11-12 at
    `main`) allows `keyctl` unconditionally and refuses `add_key` and `request_key` with its
    default action, ENOSYS. So the store fails in both with the line above, with the errno the
    kernel actually gave, while `keyctl_get_persistent` succeeds under podman. Vox does not
    substitute a file for a refused keyring: a passphrase file is the person's choice (ADR-038
    FX-34).
    The manual (`docs/manual/keyring.md`) MUST say: any process of the same user can read the
    key, as it can read a passphrase file, and so can root; the key is a reusable passphrase kept
    after the daemon that took it has exited and across logout, which today's typed unlock did
    not keep; it is memory, so it does not survive a reboot and is not on a stolen powered-off
    disk; a copy an attacker took cannot be recalled by `vox node lock`.
  - *Deleted:* the Linux `NOT_HERE` arm and its plaintext-file advice (`keychain.rs:155-182`,
    `cli.rs:1800`, `client.rs:816-821`, `docs/manual/keyring.md:34-38`); the "is not remembered:
    after the daemon restarts" reply (`client.rs:962-965`) as Linux's normal answer; the
    uncompiled draft in `/opt/vox-worktrees/fix-linux-remembered-passphrase` (superseded).
  - *Proof:* extend `a_passphrase_is_asked_for_or_refused_at_once_proof.rs`
    (`a_locked_node_is_unlocked_without_a_persistent_file`). On Linux, on a runner whose profile
    permits `add_key`/`keyctl` (the manifest says which): unlock from stdin (no file), assert the
    reply says "remembered"; `kill -KILL` the daemon (APPARATUS: a crash), reap it, assert no
    daemon; `vox daemon --detach` as at login (a fresh process: it must relink the persistent
    keyring itself); assert `vox node list` shows `omp-beast  Ready` within 30 s with nothing
    typed. A second case on the default podman profile asserts the refusal line with the kernel's
    errno. The policy and expiry cases run only inside the Linux test VM (the gate runs inside
    VMs, ledger row 32), where the apparatus is root for the sysctl alone and for nothing else.
    The decider, 2026-11-13 (ledger row 69, answering X041-13): "Yes, inside the test VM only.
    Never on the Mac or any of my machines." So: root inside the Linux test VM, never on the
    host; the driver reaches it in the VM's own namespace by `podman machine ssh` (the
    `podman-machine-default` VM, as ADR-044 RD-12's kernel arm does), never by `sudo` on the host
    or on any machine he owns; the proof refuses to run outside that VM (it checks the hostname
    the driver sets and prints `APPARATUS: not inside the Linux test VM` otherwise). Cases: (c)
    *too short to keep:*
    `sysctl kernel.keys.persistent_keyring_expiry=60`; unlock from stdin; assert the "not
    remembered" line naming the expiry; (d) *real expiry*, an optional proof (`optional-proofs`,
    eleven minutes of wall clock): `sysctl … =660`; unlock from stdin, assert "remembered";
    `kill -KILL` the daemon and reap it, so nothing refreshes; wait 700 s; `vox daemon --detach`;
    assert `vox node list` shows the RS-3 Locked line with the kernel's text. The daemon's own
    refresh is not a knob and the sysctl is the kernel's timer; no Vox variable stands in for
    either. It fails on v0.4.30 (Locked: RcaSessions run `c1` on the release asset; this
    proof's own red is not yet run). Its existing assertion that Linux is "Locked again" after a
    start is deleted: it asserts the defect. Mutant: the Linux arm of `keychain::read` returns an
    error → red, PRODUCT, quoting `vox node list`'s `Locked`. A runner that refuses `add_key` in
    the first case is an APPARATUS red and quotes the syscall and errno. Acceptance: F39-1.

- **RS-2. A restart or an update is finished by a process whose death cannot leave the root
  unserved (changed r5; r7).** `vox daemon --restart`, `vox update`, `vox update --rollback` and the
  app's Restart Daemon MUST bring up a daemon running the expected version so that:
  1. every node that was Ready is Ready again with nobody typing, from its remembered store, on
     macOS and on Linux, where it has one;
  2. from the moment the old daemon is asked to stop until the new one's remembered nodes reach a
     terminal state, the restart lease is held, and no client or hook starts a daemon (RS-5);
  3. `ps` shows at most one *serving* `vox daemon` per root at every moment (a replacement waiting
     on the lock is not serving);
  4. a daemon that launchd or systemd owned is that manager's process afterwards, and a root
     whose manager is enrolled is served by the manager's daemon afterwards even if a
     client-started `--as-detached` daemon served it before (item 81);
  5. the restart's report names how the daemon runs now and what each kept node reached:

     ```
     the vox daemon was restarted and runs vox 0.4.31 (pid 67845, launchd's login item); omp-work and robert-work are Ready
     ```

     or `… omp-work is rewriting its store (0.54 GB); it is Ready when that ends` (ADR-047 SO-10),
     exit 0; or `… omp-beast is Locked: its remembered passphrase is no longer in this computer's
     memory; unlock it once: vox node unlock omp-beast`, exit 1.
  - *Bounds (the clocks named):* the old daemon has 30 s to stop from the request (`STOP_WITHIN`,
    `restart.rs:29`); the new one has 15 s to greet from its start (`START_WITHIN`,
    `daemon_client.rs:18`) and 30 s from its greeting for the kept nodes to reach a terminal
    state (`REATTACH_WITHIN`, `restart.rs:31`). Measured on the release asset a restart is 0.5–3 s
    end to end (runs `a4`, `b1`, `b2`); the bounds are the worst the restarter waits before it
    reports a failure, not a promise of 15 s. A client that waits on the lease waits 15 s and then
    says "Vox is restarting; your rooms show from your next turn" (the hook) or `vox: the vox
    daemon is restarting (pid 67845 is bringing it up); try again in a moment` (a verb), exit 75;
    it never starts a daemon while the lease is held.
  - *Mechanism, by who owns the root.* The lease rule is the one in Terms: only the process about
    to take the lock holds it; the restarter never does. Two more pieces of control-directory
    state carry what a lease cannot across a manager's stop-and-start: the **enrollment**
    (`<control dir>/manager`, RS-5), which every daemon re-reads under the lease before it takes
    the lock, and the **planned-stop record** (`<control dir>/planned`: `{reason, by, began}`,
    written by a restarter or by `vox factory-reset` before it asks anything to stop, honoured
    for 60 s from `began`, removed by the daemon whose kept nodes reach a terminal state;
    stale-safe by age, since a dead writer cannot renew it).
    - **Managed root, the manager's daemon serving** (`<control dir>/manager` enrolled, RS-5):
      the restarter writes `planned {reason: restart}` and asks the manager for the whole
      restart in one request: `launchctl kickstart -k gui/<uid>/us.vox.daemon` or `systemctl
      --user restart <unit>`. The manager stops its job and starts it again whether or not the
      restarter lives (`launchctl(1)`: `-k` kills the running instance and restarts it; that
      launchd sends SIGTERM first and SIGKILLs at `ExitTimeOut` is [INFERENCE] from
      `launchd.plist(5)`, owed to the real-manager journey in the macOS guest, RS-5(e); the
      design needs neither a clean teardown nor that order). The old daemon, stopped by the
      manager's signal, reads `planned` and tells its subscribers `restarting` (RS-7). Between
      the old daemon's exit and the new one's lease the lease is free, and that is safe because
      of the admission rule below: nothing but the manager's own daemon serves a managed root.
      The restarter then waits for a hello with a new incarnation and the expected version, then
      for terminal node states, and reports.
    - **Managed root, a client-started daemon serving** (the operator's Mac, ledger row 21: the
      job is enabled and not running; a hook-started `--as-detached` daemon holds the root; or
      the `unsupervised` daemon of RS-5 after a manager refusal): the manager's daemon takes the
      root over itself, so the owner exists before anything stops and no restarter is needed
      after the request. The restarter writes `planned {reason: transfer}`, runs `launchctl
      kickstart gui/<uid>/us.vox.daemon` (no `-k`; `systemctl --user start <unit>`), and waits
      for the hello from the job's pid. **The takeover** (the manager's daemon, started by
      `kickstart`, by `RunAtLoad` at login, or by the manager recovering from an earlier refusal):
      under the lease it tries the lock; held → it classifies the holder, **by what the holder's
      protocol gives**: a protocol-12 hello says how it was started (`--as-detached`, a
      terminal, `unsupervised`, or a manager's job); a protocol-11 hello (v0.4.30: protocol,
      version, pid and nodes only, `daemonipc.rs:892-904`) gives only the pid, so the holder is
      classified by that pid, pinned by its kernel start time read before and after the hello
      (`proc_pidinfo`, `/proc/<pid>/stat`), from the process's own arguments (`--as-detached`
      present → client-started; absent → a terminal; `how_started`, `restart.rs:770-794`,
      `arguments`) and from the enrolled job's own record (`launchctl print gui/<uid>/
      us.vox.daemon` or `systemctl --user show -p MainPID` naming that pid → the manager's own
      earlier instance still stopping). Missing fields never mean "detached": a protocol-11 pid
      whose arguments cannot be read is treated as a terminal's and waited for. Then: a
      client-started or `unsupervised` holder → it keeps the lease, revalidates the pid and
      start time once more, sends `Stop { reason: ManagerTakeover }` (protocol 12) or SIGTERM to
      that pid (protocol 11, the cutover arm), and waits for the lock (`Handed::TakeOver`,
      `daemon.rs:211-241`), re-observing the holder on every attempt as the unmanaged arm does
      (a holder that is neither the one it stopped nor its own → it releases the lease and
      classifies again); the old daemon announces `restarting` to its subscribers (protocol 12)
      or just stops (protocol 11); the manager's daemon takes the lock within 250 ms of its
      exit, serves, attaches its kept nodes from the remembered store, releases the lease. A
      foreground daemon a person runs (`vox daemon --node X` in a terminal, no `--as-detached`,
      either protocol), or another manager daemon still stopping → it releases the lease and
      waits, as ADR-014 M-9 says today, logging `waiting: pid 1234 serves this folder from a
      terminal`. No window of two writers (the lock) and none of none that a client can fill:
      the lease is held by the manager's daemon from before the stop until its nodes are
      terminal. If `kickstart` fails or no job pid appears within 15 s, nothing is stopped: `the
      login item did not start (launchctl: <answer>); the daemon pid 54418 keeps serving,
      unsupervised`, exit 1, and `vox status` says the same.
    - **Unmanaged root** (no enrollment: beast and IO today, by the decider's Q5; hand-run and
      client-started daemons): the restarter writes `planned {reason: restart}` and starts the
      replacement first: `vox daemon --as-detached … --take-over <pid> <incarnation>`. The
      replacement takes the lease (held by another → it exits `a restart is already in
      progress`, and its restarter prints that, exit 1; the restarter never holds the lease, so
      it cannot reject its own child), re-observes the hello under the lease and confirms the
      pid and incarnation (a daemon that changed meanwhile → it exits `the daemon changed before
      it could be replaced`, and the restart reports that, exit 1), sends `Stop { reason:
      Restart }`, and waits for the lock (`Handed::TakeOver`, `daemon.rs:211-241`, which today
      only polls the lock). **In that wait it re-observes the holder on every attempt**: the lock
      taken by another process (the hello's pid is neither the one it stopped nor its own) → it
      exits `the daemon was replaced by pid <N> (started by <its command>) before this restart
      could serve; it keeps serving`, the restart reports that line, exit 1, and the new holder
      serves with its kept nodes from the remembered store (one outage, no loss). Otherwise it
      serves, attaches its kept nodes and releases the lease when they are terminal. If the old
      daemon does not stop within 30 s the replacement exits saying so and the old one keeps
      serving. The restarter is only a watcher: it waits for the new incarnation and reports.
    - **A daemon at start** (every owner, every path: cold start by a client, the manager's job,
      `--take-over`), in this order: (1) take the lease immediately before the lock attempt; held
      by another → a client-started daemon exits 0 saying `another daemon is starting for
      <root>` (its client waits for the socket as it does for a daemon it started), a waiting
      daemon waits and tries again in 250 ms; (2) **admission, under the lease**: read
      `<control dir>/manager`; if a manager is enrolled and this process is not that manager's
      (it was started `--as-detached` or from a terminal), confirm the job with the manager
      (`launchctl print`; `systemctl --user cat`): job known → do not take the lock; ask the
      manager to start it (idempotent) and exit 0 saying `a login item is enrolled for <root>;
      asked launchd to start it`, unless the client that spawned this daemon passed
      `--unsupervised "<manager's answer>"` because its own request was refused (RS-5, Q4(b)):
      then repeat the request once and watch for the job's pid for up to 15 s; the job started →
      exit 0 as above; still refused → go on, and serve `unsupervised` (the hello and `vox
      status` say so, with the manager's answer); job unknown to the manager → enrollment is
      broken (RS-5): go on, unsupervised, saying so; (3) try the lock: held by a serving daemon →
      a client-started daemon hands off as today (`Handed::Done`), the manager's daemon does the
      takeover above or waits, as the holder's kind says; free → take it, serve, attach the kept
      nodes, remove `planned` and release the lease when they are terminal. The stale-probe
      spawn (a client that probed before a restart began and spawns after) is therefore a daemon
      that finds the lease held and exits, or finds the new daemon's lock and hands off, or, on a
      managed root in the free interval of a manager restart, yields at (2) to the enrolled job
      and never serves. `start_daemon_bounded`'s `create_private_dir(daemon_dir)`
      (`daemon_client.rs:179-186`) moves into the daemon, after (1) and (2), so a client creates
      nothing under a root it may not serve (RS-15's recovery depends on this).
    - **The cutover from v0.4.30** (ruling: all machines move to 0.4.31 together, ledger row 18;
      no mixed-version support is owed, but this one update must finish): a daemon whose hello
      names protocol 11 cannot receive `Stop { reason }` (its decoder accepts the one-element
      `Stop` only, `daemonipc.rs:1695`, after a handshake its client would refuse at
      `daemonipc.rs:2270-2282`), and its hello has no incarnation. For such a daemon, and only
      such, the stop is v0.4.30's own: SIGTERM to the hello's pid, identity confirmed by the
      process's kernel start time read before and after the hello (`proc_pidinfo`,
      `/proc/<pid>/stat`), as `restart.rs:516` does today; a managed 0.4.30 daemon is restarted
      by `kickstart -k`/`systemctl restart`, which needs no frame. The replacement on an
      unmanaged root performs that SIGTERM itself in place of the product stop, under the lease.
      This arm is deleted at v0.4.32, when no 0.4.30 daemon can exist.
    - **The bundle update on macOS** (`bundle.rs:1129-1230`, `:4203-4230`): `stop_transaction`
      quits the app (RS-16) and no longer stops the daemon; `publish` exchanges the bundle while
      the old daemon keeps serving the old binary (its text pages stay mapped after the displaced
      tree is removed; `require_daemon_executable` accepts a path under the retired tree for that
      daemon). `transition_handoff` (`:4203-4230`) then runs, in this order: (1) enrollment
      (RS-5: the engine reads the app's `login-item: keep` and `launchctl print` of the job, and
      writes `<control dir>/manager` when the job is registered, before any restart owner is
      chosen; today's order, `restart_for_handoff` before `relaunch_app`, stays, so the app's
      own enrollment at launch is a second writer of the same line, never the first); (2) the
      restart step above, from the new helper, by the root's owner as just enrolled; (3)
      `relaunch_app` if the app was running. Journal phase `Stopped` becomes `AppStopped`;
      `transition_failed_journal` and the app at launch finish a pending daemon restart when the
      journal is past `Exchanged` with `daemon_complete` unset.
  - *Every kill point, what a client sees, who brings the daemon back:*

    | Killed | Managed root, manager's daemon serving | Managed root, client-started daemon serving | Unmanaged root |
    |---|---|---|---|
    | the restarter, before its request | nothing happened; the old daemon serves; a `planned` record it wrote expires in 60 s | same | same |
    | the restarter, after `kickstart` / after the replacement is spawned, before any stop | launchd/systemd finish the restart; a client sees no socket and the lease held by the new daemon (waits), or for the instant between a free lease: its own daemon yields at admission (2) to the enrolled job and asks the manager (idempotent) | the manager's daemon does the takeover itself; nothing depends on the restarter | the replacement holds the lease, stops the old daemon, serves; clients wait on the lease |
    | the restarter, after the stop was sent | the manager's job is already restarting | (no restarter stop exists in this arm) | the replacement finishes |
    | the old daemon (SIGKILL) during its stop | launchd restarts a job that died by signal (`SuccessfulExit: false`; systemd `Restart=on-failure`); clients wait | the manager's daemon, holding the lease, takes the lock at once | the replacement takes the lock |
    | a client's stale daemon spawns in the free interval between old exit and new lease | it takes the lease, finds the job enrolled and known at admission (2), asks the manager and exits; never serves | it finds the lease held by the manager's daemon and exits | there is no enrolled manager, so it is a legitimate cold start: it serves if the lock is free; the `--take-over` replacement, re-observing in its lock wait, finds another owner and reports `the daemon was replaced by pid N (started by …) before this restart could serve; it keeps serving`, exit 1; the stale daemon keeps serving with the kept nodes Ready from the remembered store (one outage, no loss) |
    | the new daemon (the manager's) before it greets | its manager starts it again (death by signal or exit 71); a client sees the lease gone and no socket → asks the manager | same | the next client starts one (RS-5; the decider's Q5); the restarter reports `the daemon did not return … within 15 s; its log is …`, exit 1. **The one window with no owner**: the process about to serve dies after the old one stopped |
    | the new daemon after it greets, before its nodes are terminal | its manager starts it again; nodes come from the remembered store | same | the next client starts one; until then the root is unserved and its nodes not Ready: the same window as the row above, through useful node service (Q5) |
    | the updater between `publish` and the restart step | the old daemon serves the old version; `vox status`/the app say "the daemon runs 0.4.30 and the installed vox is 0.4.31: Restart Daemon" (ADR-034 UP-3); the app at launch and the next `vox update` finish it; same-protocol requests are answered (RS-12), protocol-11 → 12 requests are refused naming both numbers until the restart step runs | same | same |
    | the updater between enrollment and the restart step | as the row above; enrollment is a line in the control dir, idempotent | same | — |
    | a hook, between any two steps | a hook is a client; it never holds the lease or the lock; its spawned daemon, if any, obeys the lease and admission rules | same | same |
  - *Changes:* `restart.rs` `restart_checked` (`:348-561`) becomes: observe hello → write
    `planned` → (managed, client-started serving) `kickstart`, wait for the manager's hello;
    (managed, manager's daemon serving) `kickstart -k`/`restart` → wait; (unmanaged) spawn
    `--take-over <pid> <incarnation>` → wait. `start_selected` (`:563-603`) is folded into that.
    `daemon.rs`: the lease before every lock attempt (`take_account` and the M-9 poll,
    `daemon.rs:180-208,407-415`), admission (2) with `--unsupervised`, the takeover,
    `--take-over`, `Stop { reason }`, `planned` read in the stop path and removed at terminal
    nodes; `create_private_dir(daemon_dir)` moves here from `daemon_client.rs:179-186`. The
    hello gains `incarnation`, `supervised: bool` with the manager's answer when false, how it
    was started, and each node's state (`NodeState`, `daemonipc.rs:138-148`, plus `Rewriting`
    and `NeedsPassphrase`); `wait_for_replacement` (`:605-652`) waits for a new incarnation and
    the expected version, then for terminal states, ending at once on Locked or Rewriting. The
    bundle transaction as above.
  - *Deleted:* the SIGTERM at `restart.rs:516` and `:278` as the stop for a protocol-12 daemon (a
    product stop is a request; the protocol-11 arm keeps it until v0.4.32); `stop_captured_daemon`'s
    daemon half; the `previous_pid` comparison in `wait_for_replacement`; revision 1's
    `Replace`/`--as-successor`/`--handover-fd`; revision 3's restarter-held lease; revision 4's
    restarter-sent stop in the transfer arm.
  - *Proof:* extend `the_daemon_and_its_nodes_proof.rs`
    (`a_kept_node_and_its_room_come_back_after_a_restart`), unmanaged root (the managed arms are
    RS-5's), in the Linux VM and the macOS guest: unlock by piped passphrase on every platform
    (no `--passphrase-file`, so the macOS-only guard at `:751-753` is deleted). (a) `vox daemon
    --restart` while the apparatus runs `vox room list` and `vox agent hook --omp-prepare` in a
    loop and keeps a client paused at the legal race point (a `vox room list` started, then
    SIGSTOPped by the apparatus after its socket probe and SIGCONTed after the stop began);
    assert no `vox room list` prints "no vox daemon is running", each in the window says
    "restarting" or answers after; the paused client, resumed, answers from the new daemon and
    its log shows that any daemon it started exited saying "another daemon is starting"; `vox
    node list` shows every node Ready within 30 s with nothing typed; the restart's line names
    the new pid. (b) Two `vox daemon --restart` at once: one reports the restart, the other `a
    restart is already in progress`, and one daemon serves after. (c) Kill the restarter
    (SIGKILL) 200 ms after it started the replacement: the new daemon serves within 15 s and a
    remote `vox room read` from a peer answers. (d) Cutover, with the v0.4.30 release asset as
    the running daemon (APPARATUS; ADR-045 FG-2 publishes it). (d1) *Old detached owner*, two arms
    kept apart because RS-4 establishes that a passphrase typed to a v0.4.30 daemon is lost at
    its stop: (d1-remembered) the node was unlocked on v0.4.30 with a source the candidate can
    read (macOS: the Keychain; Linux: `--passphrase-file`, the file source v0.4.30 keeps,
    `client.rs:866-873`); `vox daemon --restart` from the candidate; assert the restart's line
    names the replaced pid and `omp-beast is Ready`, exit 0, with nothing typed; (d1-typed, Linux)
    the node was unlocked on v0.4.30 by stdin; `vox daemon --restart` from the candidate; assert
    the restart's line names the replaced pid and `omp-beast is Locked: its remembered passphrase
    is no longer in this computer's memory …; unlock it once: vox node unlock omp-beast`, exit 1,
    and that `vox node list` says Locked; then `vox node unlock omp-beast` from stdin; assert
    "remembered" and Ready. (d2) *Old foreground owner*: the v0.4.30 asset run in the foreground
    (`vox daemon --node A`, no `--as-detached`) with a login-item job enrolled (the guest's
    scratch job): `launchctl kickstart` the job; assert within 20 s the job's daemon logs
    `waiting: pid N serves this folder from a terminal`, the foreground daemon still serves (its
    pid answers the socket) and nothing was signalled; Ctrl-C the foreground daemon; assert the
    job's daemon serves within 15 s. (d2-unreadable) the same, with the candidate's manager daemon
    built with `test-knobs` and `VOX_TEST_ARGS_UNREADABLE=<pid>` set to the foreground daemon's
    pid, which makes its argument read for that pid fail as `EPERM` would; the test build logs
    `test knob: arguments of pid N unreadable` and a run without that line is `APPARATUS: staging
    not achieved`; assert the job's daemon logs `waiting: pid N serves this folder (its command
    could not be read; treated as a terminal's)`, the foreground daemon's authenticated pid still
    answers the socket, and nothing was signalled. (e) *The Locked restart line* (RS-2 item 5):
    after RS-3's proof (a) has removed the key, `vox daemon --restart`; assert the line
    `omp-beast is Locked: its remembered passphrase is no longer in this computer's memory
    (keyring: <the kernel's text>); unlock it once: vox node unlock omp-beast`, exit 1, within
    the bounds and not after `REATTACH_WITHIN`. (f) *The bundle's order and an interrupted
    handoff*, in `update_proof.rs:938`'s macOS section (RS-12's and RS-16's file), in the guest,
    four acts: (f-a) *served before the restart step:* a `vox room list` loop from the old binary
    runs through `vox update`; assert every request until the restart step is answered by the
    old daemon's pid, none prints "no vox daemon is running", and `ps` shows no client-started
    daemon; (f-b) *interrupted, finished by the app at launch:* the apparatus watches the
    installed bundle's `Contents/Info.plist` version and SIGKILLs the updater the moment it
    changes (the publish); staging is confirmed when `vox status` still names the old daemon's
    pid and version, otherwise `APPARATUS: staging not achieved` (the restart step already ran);
    assert `vox status` says `the daemon runs <old> and the installed vox is <new>: Restart
    Daemon`; launch the app; assert within 30 + 15 + 30 s the daemon runs the new version under
    the login item; (f-c) *interrupted, finished by the next update:* the same staging; run `vox
    update` again; assert the same outcome; (f-d) *enrollment before the restart step:* the app
    not running, a client-started daemon serving, `login-item: keep` set and the job registered;
    after `vox update`, assert `vox status` names the login item's pid as serving and no app was
    launched. Fails on v0.4.30 (Linux Locked, run `c1`; a hook in the window starts a second
    daemon, runs `d1`, `h2`; a killed restarter leaves nothing, `restart.rs:516-527`; v0.4.30
    stops the daemon before `publish`, `bundle.rs:1129-1158`, so (f-a) is red); this proof's own
    red is not yet run. Mutants, each on its own assertion: let a daemon take the lock without
    the lease (the lock stays exclusive, so no two daemons serve; the person-visible failure is
    who serves) → in (a) the apparatus resumes the paused client after the old daemon has exited
    and before the replacement's next lock attempt, so the client's daemon wins the lock; the
    replacement's lock-wait re-observation finds another owner and reports `the daemon was
    replaced by pid <client's> (started by vox room list) before this restart could serve; it
    keeps serving`, exit 1; `vox status` names that pid as serving, started `--as-detached`, not
    the restart's → red, PRODUCT, quoting the restart's line and `vox status`'s pid; if the
    apparatus cannot resume the client in that interval (the old daemon's exit and the lock win
    are not observed in that order), the result is APPARATUS: staging not achieved, never a
    pass. Stop-then-start in the restarter → (c) leaves no daemon → red, PRODUCT, quoting `vox
    room list`'s "no vox daemon is running". Treat a protocol-11 holder as protocol 12 (send
    `Stop { reason }` instead of the cutover SIGTERM) → in (d1-remembered) the v0.4.30 daemon
    never receives a frame it decodes (`daemonipc.rs:1695`; the handshake refuses first,
    `:2270-2282`), the replacement reports `the daemon (pid N) did not stop within 30 s; it still
    runs vox 0.4.30`, exit 1, and the old pid still answers the socket → red, PRODUCT, quoting
    the restart's line and the pid. Classify a protocol-11 holder with unreadable
    arguments as detached → (d2-unreadable) signals the foreground daemon and the socket's
    authenticated pid changes → red, PRODUCT, quoting the pid before and after. Stop the daemon
    in `stop_transaction` again (v0.4.30's order) → (f-a) prints "no vox daemon is running" or a
    client's daemon appears → red, PRODUCT, quoting it. The app at launch ignores a journal past
    `Exchanged` with `daemon_complete` unset → (f-b) leaves `vox status` on the old version →
    red, PRODUCT, quoting it; the engine ignores it → (f-c) likewise. Write the enrollment after
    the restart step → (f-d) leaves the client-started daemon serving → red, PRODUCT, quoting
    `vox status`. Acceptance: F39-1, F41-1.

- **RS-3. After the computer restarts, a Linux node comes back from a TPM-sealed credential
  where it can, otherwise from a passphrase file, and says truthfully what it needs (changed
  r5; the decider's Q1, ledger row 43).** On Linux a node's passphrase for a reboot MUST come
  from a systemd credential sealed to the TPM where systemd is 258 or later and a TPM exists,
  and otherwise from a passphrase file the person names, as today. `vox node unlock` MUST offer
  the one that applies: on a host with systemd ≥ 258 and `/dev/tpmrm0`, it prints the credential
  recipe; elsewhere it prints the file command. A node with neither configured MUST be shown
  after a reboot as Locked with the reason the kernel gave and the one command that unlocks it.
  No surface may say "since the computer started" from an empty keyring alone, and no surface
  may tell the person to create it.
  - *Why:* item 39. The kernel keyring does not survive a reboot; it is also dropped
    `persistent_keyring_expiry` after its last get, and any same-uid process can revoke it, so an
    empty keyring proves only that the remembered passphrase is gone. The decider chose
    "combination of 1 and 2": the credential where the host can seal it, the file otherwise, and
    not an unlock per boot.
  - *What each protects, said in the manual and by `vox node unlock`:* a **TPM-sealed
    credential** (`systemd-creds encrypt --user --name <name> --with-key=tpm2`, `host+tpm2`
    where both exist) is decryptable only on this machine with this TPM; a stolen disk alone
    cannot read it; a process of the uid that the unit runs as can read the decrypted copy under
    `$CREDENTIALS_DIRECTORY` while the unit runs. A **passphrase file** (`vox node unlock
    --passphrase-file <path>`, the path the person chose, 0600) is readable by every process of
    the same user and by root, and by whoever has the disk unless the disk itself is encrypted;
    it survives a reboot; Vox never writes it, never moves it and never substitutes it for a
    refused keyring (ADR-038 FX-34). `--with-key=host` alone is decryptable by whoever has the
    disk and `/var/lib/systemd/credential.secret`; the recipe does not offer it. Both sources
    keep RS-1's kernel-keyring cache between reboots with its same-uid readability.
  - *Changes:* a keep source `KeepSource::Credential(name)` in `.daemon/attach`, read from
    `$CREDENTIALS_DIRECTORY/<name>` (systemd credentials, https://systemd.io/CREDENTIALS); `vox
    node unlock --passphrase-credential NAME` records it, after reading the credential once to
    prove it opens the vault; the manual's unit recipe (RS-5) gains
    `LoadCredentialEncrypted=<name>:%h/.config/vox/<name>.cred` with the recipe above. User
    units can load credentials only from systemd 258 (systemd/systemd#33796: 256–257 fail with
    `243/CREDENTIALS`); beast runs 259 (ledger row 21); whether it has a TPM is read-only
    `ls -l /dev/tpmrm0`, with his go. A credential that is configured but absent at start is a
    Locked node that says `its systemd credential <name> was not given to the daemon
    (CREDENTIALS_DIRECTORY unset)`. `vox node unlock`, after a typed unlock on Linux, ends with
    one line: `After this computer restarts it needs its passphrase again; to avoid that: <the
    credential recipe | vox node unlock omp-beast --passphrase-file <path>>`.
    In every case: when `attach_one_kept` finds no key where the keep source says `Keychain`, the
    node is Locked with the kernel's answer; `vox node list` is to say:

    ```
    node omp-beast  Locked: its remembered passphrase is no longer in this computer's memory (keyring: Required key not available)
    Unlock it once: vox node unlock omp-beast
    ```

    `vox status`'s layout for this line is ADR-042's; this ADR fixes only the fact and the command.
    The OMP extension's text is RS-7's.
  - *Deleted:* nothing beyond RS-1.
  - *Proof:* extend RS-1's proof. (a) *Reboot stand-in:* `kill -KILL` the Ready daemon and reap
    it; assert no daemon; APPARATUS removes the key (`keyctl unlink` of the key from
    `@persistent`, then `keyctl purge user us.vox.node:<account>`), as a reboot or an expiry
    leaves it; `vox daemon --detach`; assert `vox node list` shows the two lines above with the
    errno text the kernel gave (`keyctl print` of the missing key gives it; the proof does not
    assume ENOKEY's wording). (b) *Key removed while live:* with the daemon Ready, remove the key;
    assert `vox node list` says `Ready, no longer remembered` and the daemon log names the
    missing key, and that nothing says the computer restarted. Mutant: print "Ready" for a
    missing key in (a) → red, PRODUCT, quoting `vox node list`. The credential path needs systemd
    258 or later, a user manager and a TPM: an optional proof (`optional-proofs`) that prints
    `OPTIONAL PROOF NOT RUN` where it cannot run and never counts as green. Acceptance: F39-2.

- **RS-4. The update from v0.4.30 says what it will cost before it starts (changed r4).** A
  v0.4.30 daemon holds a Linux passphrase typed to it only in its memory, and a v0.4.30 client
  knows no lease. When `vox update` finds such a daemon, it MUST say, before it stops it, which
  nodes will be Locked afterwards and what the next unlock will do:

  ```
  vox update: omp-beast will be Locked after this update: vox 0.4.30 did not remember its passphrase. Unlock it once afterwards: vox node unlock omp-beast. That unlock tries to remember it in this computer's memory (the kernel keyring); if this system refuses the keyring, it says so, and each restart asks again unless you name a passphrase file.
  ```

  On macOS the same line is printed for a kept node whose Keychain item cannot be read (the
  Keychain is locked or refuses; `keychain.rs:31-44` never prompts), naming the Keychain instead.
  It then performs the restart as RS-2 says, with its cutover stop (SIGTERM to the protocol-11
  daemon; `kickstart -k` or `systemctl restart` where a manager is enrolled). A hook of a v0.4.30 extension typed
  in that window may still start a daemon of its own, once; an OMP whose extension predates this
  release prints its old advice once at that restart; the doctor already asks for an OMP restart
  after an update. No new client code can change what an unmodified v0.4.30 client does. The
  release notes carry the same three cases: remembered (nothing to do), refused keyring (unlock
  after every restart, or a file), and the old extension's one line.
  - *Why:* item 39. The update target's own engine performs the restart (`vox update` runs the
    target `vox update-apply`, rca-RcaAppQuit KNOWN 1), so v0.4.31's engine can say this. No
    algorithm can take the secret out of the dead v0.4.30 process, and whether the new store is
    usable is known only when that unlock tries it.
  - *Changes:* the message, in the target engine's restart step, when the running daemon's
    version is 0.4.30 and a kept node's keep source is absent off macOS or unreadable on macOS.
  - *Deleted:* nothing.
  - *Proof:* none. This is prior-release compatibility, out of scope by ADR-026 F-3 and AGENTS.md;
    it is checked by review. ADR-045 J7 stages the 0.4.30 update on B as the warned one-time
    unlock, apart from candidate-to-candidate restarts.

### 2. One daemon per data root, and its manager owns it

- **RS-5. A manager is enrolled per root, its daemon comes back by itself, and a client's daemon
  yields to it (changed r5; r7; the decider's Q4 and Q5, ledger rows 46, 47).** On a Mac with the
  login item enabled, or on Linux with a user unit enrolled for the data root, a daemon that
  dies for any reason other than a product stop, a clean external SIGTERM included, MUST be
  serving again within 15 s with nobody typing and no client involved. A client or hook that
  finds no daemon MUST: wait on the restart lease while it is held (up to 15 s, then say
  "restarting" and start nothing); then, when a manager is enrolled for the root and knows the
  job, ask that manager to start the daemon (`launchctl kickstart`, `systemctl --user start`,
  both idempotent on a running job) and wait up to 15 s for the socket, as ADR-026 S-2 does;
  when the manager refuses, or does not know the job, or no manager is enrolled, start a daemon
  itself (`--as-detached`), which serves `unsupervised` and says why. A daemon started by a
  client MUST yield to the manager's daemon whenever one arrives (RS-2's takeover), so a managed
  root is served by the manager's daemon as soon as the manager can run it. With these rules and
  RS-2, `ps` MUST show at most one serving `vox daemon` per data root at every moment; on a Mac
  with Keep Running on and launchd able to run the job it is `--no-node --login-item`; `vox
  status` MUST say `unsupervised` and why whenever it is not.
  - *Why:* item 41 (C3), item 47 and item 81 (C4): the Mac's daemon of record was a hook-started
    detached daemon, and nothing brought the daemon back for 120 s because the login item's
    `KeepAlive` is `{SuccessfulExit: false}` (`us.vox.daemon.plist:18-22`) and a clean SIGTERM
    stop exits 0 (`daemon.rs:719-765`): launchd, by design, does not restart it. Revision 2's
    `.daemon/manager`, written by the manager's daemon when it took the lock, could never be
    written on exactly that Mac (the login item's daemon was waiting or not loaded; second review
    N2).
  - *Changes:*
    - *Enrollment:* `<control dir>/manager` holds one line, `launchd gui/<uid>/us.vox.daemon
      <bundle path>` or `systemd <unit> <exe path>`, with the data root it is for. It is control
      plane: it is written by whatever can see that the job is registered, never by a daemon
      after it won the lock. Writers: the app when Keep Running is turned on
      (`SMAppService.register`, `Daemon.swift:11,48`) and at every launch while it is on, after
      `status == .enabled`; the update engine (`transition_handoff`, RS-2) before it chooses the
      restart owner, when the app's config says `login-item: keep` (`<config>/app`,
      `mac/app-config.txt`) and `launchctl print gui/<uid>/us.vox.daemon` succeeds; `vox daemon
      --restart` on the same evidence; `vox agent setup --service` on Linux (new: writes the unit
      below, `systemctl --user daemon-reload`, `enable --now`, then the enrollment). It is removed
      by the app when Keep Running is turned off, by `vox agent setup --no-service`, and by `vox
      uninstall`. A client reads it and confirms the manager still knows the job (`launchctl
      print` succeeds and names this bundle; `systemctl --user cat <unit>` succeeds and names this
      exe); then asks it. Enrollment present but the job unknown to the manager (login item
      disabled in System Settings, unit file removed) is "enrollment broken": the client says
      `vox: Keep Running is on but launchd does not know the login item (launchctl: Could not
      find service); starting a daemon of this session, unsupervised. Turn Keep Running off and
      on in Vox to repair it`, spawns `--as-detached --unsupervised "<answer>"`, and `vox status`
      and `vox doctor` say the same. **Enrollment present, job known, manager refuses to start
      it** (the decider's Q4, option (b), ledger row 46): the client prints the manager's answer,
      `vox: launchd refused to start the login item (launchctl: <answer>); starting a daemon of
      this session, unsupervised`, and spawns `--as-detached --unsupervised "<answer>"`. That
      daemon, under the lease, repeats the request once and watches 15 s for the job's pid (RS-2
      admission (2)); if the manager still refuses it takes the lock and serves; its hello says
      `supervised: false` with the answer, and `vox status` prints `unsupervised: launchd refused
      to start the login item (<answer>)`. One daemon per root holds throughout: the lease and
      the lock. **When the manager later recovers**, by its own `RunAtLoad` at the next login,
      by `launchctl kickstart` from any client that finds no daemon, or by a person repairing it,
      its daemon starts, takes the lease, finds the lock held by an `unsupervised` daemon, and
      takes the root over (RS-2's takeover: `Stop { reason: ManagerTakeover }`, the old daemon
      tells its subscribers `restarting`, stops cleanly, the manager's daemon takes the lock
      within 250 ms and attaches the nodes from the remembered store). Order: the manager's
      daemon holds the lease from before the stop until its nodes are terminal, so no third
      process gets in; the lock passes once; the only outage is the old daemon's clean stop plus
      the attach, read by the watcher as `starting`. The unsupervised daemon never refuses the
      takeover and never races it: a product stop is obeyed. `how_started(pid)` stays for a
      running daemon.
    - *The operator's Mac today* (ledger row 21, read with his go): the job
      `gui/502/us.vox.daemon` is registered and enabled, has run 15 times and exits 0 each time
      while a hook-started `--as-detached` daemon (pid 54418) serves; no `login-item.log` exists.
      Why the 0.4.30 login-item daemon exits 0 instead of waiting (`daemon.rs:180-208`) is
      UNKNOWN; it is not `refused_for_good` (no log line). The experiment that settles it runs in
      the macOS guest, never on his Mac: bootstrap the 0.4.30 bundle's job with a detached daemon
      serving and read the job's stderr. The design does not depend on the answer: after the
      update the job runs the 0.4.31 binary, whose waiting behaviour this ADR specifies.
    - *Item 81 on the operator's Mac, step by step:* `vox update` (or the app's update) publishes
      the 0.4.31 bundle; the engine reads `login-item: keep` and `launchctl print` (registered,
      not running) and writes the enrollment; the restart step takes RS-2's "managed root,
      client-started daemon serving" arm: it writes `planned {reason: transfer}` and runs
      `launchctl kickstart gui/502/us.vox.daemon`; the 0.4.31 login-item daemon starts, takes the
      lease, finds the lock held by a daemon whose hello names protocol 11 (a v0.4.30 hello
      carries only protocol, version, pid and nodes, `daemonipc.rs:892-904`, so it says nothing
      about who started it), classifies the holder by its pid, pinned by kernel start time, from
      its arguments (`--as-detached`: `how_started`, `restart.rs:770-794`) and the enrolled job's
      own record (`launchctl print` names no such pid), stops it with SIGTERM (the cutover arm),
      takes the lock within 250 ms of its exit, serves, and
      attaches omp-work and robert-work from the Keychain; the engine waits for the hello from
      the job's pid and reports. Killed at any step: the table in RS-2. From then on a hook finds
      the enrollment and never spawns. With the app not running, `relaunch_app` launches nothing
      (`bundle.rs:4218`), and nothing here needs it.
    - *Exit rule:* every product stop is a control request (`Stop { reason: Restart | Reset |
      Uninstall | Request }`); a daemon stopped by a *signal* has been stopped by something that
      is not the product. A `--login-item` daemon exits 71 after its clean stop on any signal,
      logging `stopped by SIGTERM from pid 51234 (…); launchd starts it again`, so launchd
      (`SuccessfulExit: false`) restarts it; on a product stop it exits 0. This needs no
      knowledge of the sender: `launchctl kickstart -k` restarts regardless, `launchctl bootout`
      unloads the job so no restart follows, and logout tears the domain down. A hand-run or
      client-started daemon keeps exit 0 (V210-93). `KeepAlive: {SuccessfulExit: false}` stays,
      because a start refused for good must exit 0 so launchd does not retry it every 10 s
      (`daemon.rs:342-375`).
    - *Linux unit* (`docs/manual/linux-service.md`, new; written by `vox agent setup --service`):
      `ExecStart=<exe> daemon --no-node --data-dir <root> --config-dir <config>`,
      `Restart=on-failure` plus `RestartForceExitStatus=71` and the same exit-71 rule (so an
      external signal restarts it and `systemctl --user stop` does not), `RestartSec=1`,
      `TimeoutStopSec=35`, `KillSignal=SIGTERM`, `WantedBy=default.target`, with `loginctl
      enable-linger`. beast today (ledger row 21): no vox unit of any kind; the daemon is a
      `--as-detached` process in a login-session scope (`session-2824.scope`) with `Linger=yes`;
      systemd 259. So beast and IO are unmanaged roots, and by the decider's Q5 (row 47) that is
      accepted: a dead daemon there returns at the next client, `vox status` says
      `unsupervised`, and no unit is required; `vox agent setup --service` is offered, not
      demanded. systemd 259 ≥ 258, so the credential path (RS-3) is available on beast if it
      has a TPM (`ls -l /dev/tpmrm0`, read-only, his go).
    - `daemon_client.rs` `ensure_daemon` and `ensure_daemon_for_hook` gain the lease wait and the
      enrollment lookup. The hook's text while the manager starts the daemon is today's "Vox is
      preparing node omp-work; this session joins it once it is Ready, and your rooms show from
      your next turn."
  - *Deleted:* revision 2's `.daemon/manager`. A socket that accepts and does not greet already
    spawns nothing (`daemon_client.rs:109`).
  - *Proof:* extend `the_daemon_and_its_nodes_proof.rs` (RS-2's file; r7: no new file, the
    manager staging is apparatus in the same journey), with a real manager, not the app proofs'
    stand-in (`Daemon.swift:18-24,48-58` registers nothing with launchd). The acts run only
    inside the VMs the gate uses (ledger row 32): the macOS guest, where a job with the proof's
    own label is bootstrapped under the guest account's `gui/<uid>` from a scratch plist and
    booted out at the end, and the Linux VM with a scratch user unit; never on a host or a real
    profile; outside them the acts print `APPARATUS: not inside the VM`. Journey: (a) with the
    job serving,
    `kill -TERM <pid>` from a shell (a clean external stop) and run **no client**; assert within
    15 s `launchctl print`/`systemctl --user show -p MainPID` names a new pid, then that a remote
    peer's `vox room read` of a post made by this node after the restart succeeds (the verdict
    is remote service, so the proof cannot heal its own failure by starting a daemon); (b)
    `kill -KILL` and the same; (c) the operator's shape: a detached daemon serving, the job
    registered and **not running** (it exited; the proof boots it out and in with `RunAtLoad`
    off), then `vox daemon --restart`; assert the job's pid serves after, `ps` shows no
    `--as-detached`, the restart's line names the replaced pid, and the shim (RS-7) printed
    nothing but the reconnected line; (c') the same with the restarter SIGKILLed 100 ms after
    `kickstart`; assert the job's pid serves within 15 s with no client (the takeover is the
    manager daemon's own); (d) enrollment broken: boot the job out, leave the enrollment; `vox
    room list`; assert the "launchd does not know the login item" line and that `vox status`
    says `unsupervised`; (d') the manager refuses (APPARATUS: the job's plist is edited so its
    program path does not exist; `launchctl kickstart` fails): `vox room list`; assert the
    refusal line names launchd's answer, a daemon serves, `vox status` says `unsupervised:
    launchd refused …`; then repair the plist and `launchctl kickstart`; assert within 15 s the
    job's pid serves, the old daemon's log says `stopping on request: manager takeover`, the
    shim printed only the reconnected line, and the peer's `vox room read` of a post made after
    the takeover succeeds; (e) during a managed restart (`kickstart -k`), run `vox agent hook
    --omp-prepare` and keep a `vox room list` paused after its probe, resumed after the old
    daemon exited and before the job's new pid appears (the apparatus watches `launchctl print`);
    assert the resumed client's daemon exited saying "asked launchd to start it", `ps` never
    shows a serving `--as-detached`, the job's pid is the socket's authenticated pid after, and
    record from the guest whether launchd's stop was SIGTERM then SIGKILL at `ExitTimeOut`
    (RS-6's line says which); (e') the same paused client in arm (c). Fails on v0.4.30 (after the
    clean SIGTERM nothing serves until a client; `cleanup/daemons-detail.txt`; (c) leaves the
    detached daemon in place, ledger row 21); not yet run. Mutants: exit 0 on the external
    signal → nothing serves within 15 s → (a) red, PRODUCT, quoting the peer's "could not
    reach"; skip admission (2) in the spawned daemon → in (e) the resumed client's daemon takes
    the lock and the job's daemon waits: `vox status` names the client's pid as serving and the
    restart's line reports `the login item did not become the daemon` → red, PRODUCT, quoting
    that line; skip the takeover → (d') leaves the unsupervised daemon serving after the repair
    → red, PRODUCT, quoting `vox status`. (f) *No manager enrolled* (the decider's Q5, r7), in
    the same file on a scratch root with no enrollment: a daemon serving; `kill -KILL` it and
    run no client for 30 s; assert no daemon returns (`vox status` from a peer: the computer is
    `offline, last seen …`); then `vox room list`; assert it answers within 15 s, `ps` shows one
    `--as-detached` daemon, and `vox status` says `unsupervised: no manager is enrolled for this
    folder (vox agent setup --service enrolls one)`. Mutant: print nothing for an unmanaged
    root → red, PRODUCT, quoting `vox status`. Acceptance: F47-2.

- **RS-6. Every stop names who asked for it (changed).** When a signal stops the daemon, its log
  line MUST name the signal and the sender's pid, uid and command, best effort:

  ```
  vox daemon: shutting down on SIGTERM from pid 51234 (uid 502: sh -c kill -TERM 38806; sleep 5)
  ```

  When the sender has exited before its command could be read, the line says `(uid 502; it has
  exited)`; when its command cannot be read but its executable can, the line names the executable
  only; a signal the kernel sent says `from the system`; one from pid 1 says `from launchd` or
  `from systemd` (which is the manager, not whoever asked the manager). A product stop logs
  `stopping on request: restart, asked by pid 51234 (vox daemon --restart)`.
  - *Why:* item 47 (C4): the Nov 12 sender cannot be found after the fact; the next one must name
    itself. The line is a diagnostic; nothing decides from it (RS-5's exit rule decides from
    "signal or request").
  - *Changes:* `app.rs:662` `stop_requested` installs the stop handlers with `SA_SIGINFO`; the
    handler stores `si_pid`, `si_uid` and `si_code` in atomics and wakes the existing waiter; it
    does nothing else (async-signal-safe). `daemon.rs:727` writes the line, reading the command
    with `sysctl KERN_PROCARGS2` (macOS; `proc_pidpath` is the executable-only fallback) or
    `/proc/<pid>/cmdline` (Linux), bounded to one line of 256 bytes, at once in the stop path;
    `ESRCH` → "it has exited". SIGINT, SIGHUP and SIGQUIT MUST keep working as V210-93 requires.
  - *Deleted:* nothing.
  - *Proof:* extend `daemon_shutdown_proof.rs`
    (`a_daemon_stops_on_sigterm_even_when_its_peers_have_vanished`): send SIGTERM from
    `sh -c "kill -TERM <pid>; sleep 5"` (the shell's builtin `kill`, so the sender lives); assert
    the stop line names that shell's pid and `kill -TERM`. Fails on v0.4.30 (the line names only
    SIGTERM, `daemon.rs:727`); not yet run. Mutant: drop the `si_pid` capture → red, PRODUCT,
    quoting the log line. `an_anchor_stops_on_ctrl_c_proof.rs` keeps Ctrl-C covered. Acceptance:
    F47-1.

### 3. A conversation survives a restart, and only a live conversation is followed

- **RS-7. A dropped connection is not a node state (changed r5; r7; r8; r9).** Across a planned restart or
  update, from the stop request until the conversation's node reaches a terminal state, an OMP
  conversation MUST show no Vox text, except at most one line after it reconnects:

  ```
  Vox restarted; this conversation is reconnected.
  ```

  "run `vox node create`" MUST appear only when the node's directory does not exist. A Locked node
  MUST read `Vox: omp-beast is Locked. Unlock it once: vox node unlock omp-beast`, and only once it
  is Locked, never while it is attaching. A node rewriting its store reads nothing until it is
  Ready. No Session in the room may get "OMP observation stopped" for a planned restart or update.
  - *Why:* item 40 (C2). Hello comes before Ready (`daemon.rs:474+` attaches kept nodes after the
    socket serves); revision 2 ended the watcher's "restarting" at hello and had no word for the
    interval after it (second review N10).
  - *Changes:* the watcher's frame types stay `owner`, `ack`, `matched`, `ready`, `unavailable`
    (an extension loaded before the binary was replaced dispatches on exactly those and fails the
    watcher on any other type, `omp-extension.ts:422-446`). The `unavailable` frame gains two
    fields the old extension ignores: `daemon: "starting" | "absent" | "serving"` and
    `node: "attaching" | "ready" | "locked" | "rewriting" | "missing" | "other-identity"`.
    `daemon: starting` is reported while the restart lease is held (RS-2: by whichever process
    is bringing the daemon up, until its kept nodes are terminal) **or** while
    `<control dir>/planned` is younger than 60 s (RS-2: written by a restarter or by `vox
    factory-reset` before anything stops, so that the interval between a manager's stop and its
    new daemon's lease reads as planned); `node` comes from the hello's per-node state when the
    daemon answers and from the lease otherwise. The daemon, on a product stop with reason
    `Restart`, `ManagerTakeover` or `Reset`, or on a signal stop while `planned` is young, tells
    its subscribers `restarting` before it closes. The new extension (`omp-extension.ts:437-445`)
    prints nothing for `starting`, `attaching` and `rewriting`, one sentence for `locked`,
    `missing` and `other-identity` (RS-9), and the reconnected line on the next `ready` after a
    `starting`. `omp_mirror.rs:1001-1023` posts "observation stopped" only when the bridge goes
    while neither the lease is held nor `planned` is young and the
    extension did not say it was stopping. After the replacement starts, the daemon follows its
    registrations again without posting (`host.rs:4832-4841`). The watcher's exit 76 succession
    stays for a genuine control-protocol change (RS-12).
  - *Deleted:* the four-sentence advice (`omp-extension.ts:444`) and `Vox update mismatch; update
    Vox and restart the daemon` (`:440`) from the extension that ships with v0.4.31.
  - *Depends on:* ADR-040 r3 for the other texts a conversation sees in a restart window (item
    29) and ADR-050 for the conversations a restart poisons (item 30); ADR-040's typed `NotYet`
    refusals whose prerequisite is the daemon are not displayed while the watcher reports
    `starting` (shared contract, listed under "Changes this revision asks of siblings"). ADR-042
    owns the general rule that no hint may name an action that destroys an identity unless its
    precondition is known.
  - *Proof:* a new file, `an_omp_conversation_survives_a_daemon_restart_proof.rs`. It is justified:
    no proof drives the extension. ADR-050's OMP journeys MUST live in the same file, not a
    second one: the file hosts **the acts TJ-10 places in this file, as ADR-050 states them**
    (r9; ADR-050 r11's sibling contract "ADR-041 RS-7, RS-9": acts 1, 2, 3, 4, 5, 7, 8 (8a–8f,
    8f′, 8f″), 9, 9b, 10 and 12 in this file; acts 6 and 11 in `agent_hook_proof.rs`; the
    decider's row 36 applies: an uncertain turn stays permanently uncertain). This ADR restates
    none of ADR-050's assertions; ADR-050 TJ-10 is the authority for each act's staging,
    assertion and mutant. APPARATUS: Node runs the real `crates/vox-tui/assets/omp-extension.ts`
    under a host shim that implements the `pi`/`ctx` surface it uses (RcaSessions' `shim.mjs`
    and E-30's `shim-hold.mjs` are the models; a test-side harness, allowed by ADR-018's
    2026-10-01 section). For TJ-10's acts the shim MUST (r9, ADR-050 r11's list): (1) log every
    `appendEntry` of `vox-context-staged` and `vox-context-accepted` with its `id`, `marker` and
    content; (2) log every `before_provider_request` payload so a marker's presence can be
    counted per step, and be able to emit zero, one or two such events in one step, and one
    whose payload omits the marker; (3) end a step with an assistant message carrying
    `stopReason: error` or an unknown stop reason, log every `message_end` with its `stopReason`
    and `errorMessage`; be able to run, after an error `message_end` has been forwarded to the
    extension, a replayed step as OMP's `agent_end` maintenance does (8f: Vox ends first); to
    emit two `before_provider_request` events for one step with no `message_end` between them (a
    provider-attempt retry that calls `onPayload` again: a second build, 8f′, uncertain); and to
    answer one request with a transport-level 429 that the shim's own fetch stub retries below
    the single payload callback (exactly one `before_provider_request`, no error `message_end`,
    then a clean `stop`: 8f″, Vox unaffected); the fetch stub **is to be written** for 8f″ (the
    E-30 shim has none: a retryable 429 once, then valid SSE ending in `stop`); (4) raise
    `session_before_switch` and `session_switch` during a prepare, and `session_shutdown`; (5)
    keep a session store with `getEntries`/`getBranch`/`appendEntry`/`ensureOnDisk`/
    `getSessionFile` under OMP's persistence rules for RS-9's own cases (no ADR-050 act calls
    `ensureOnDisk`); (6) be killable and restartable on the same session file; (7) hold an aside
    turn that injected content between the envelope and the model's answer while an arm file
    exists (E-30's `shim-hold.mjs`); (8) log `sendMessage` (wakes), `ui.notify`, `ctx.abort` and
    each `context` result's inserted messages. No longer needed (ADR-050 r6–r7): payload `tools`
    shapes, `message_update` with `toolcall_start`, re-placement logging, reparenting or
    `/clear` of the branch, a settable latched append failure. The shim's own
    events are apparatus; every assertion is what the person or the model sees, as TJ-10
    requires, and RS-9's and ADR-050's history cases are real.
    Journey: register; a peer posts; `vox daemon --restart` with the node's attach
    delayed (`test-knobs` `VOX_TEST_ATTACH_DELAY_MS=4000`, so hello precedes Ready by 4 s); type
    a prompt during the restart and another during the attach; assert the shim's notify log
    holds no line with `vox node create`, no Locked line, and nothing but the reconnected line;
    the turn after the restart carries the peer's post; `vox room session` shows no "observation
    stopped". Then `vox node lock` and a restart: assert the Locked line, once. Then the
    rewriting act (r7; RS-2 item 5, ADR-047 SO-10): the apparatus makes the node's store
    rewrite-eligible as ADR-047 SO-10's own proof does (its in-tree journey creates a store whose
    file length exceeds 2 × its in-use bytes), and holds the rewrite's completion with
    `test-knobs` `VOX_TEST_REWRITE_HOLD_MS=8000` (the test build logs `test knob: store rewrite
    held 8000 ms`; a run without that line is `APPARATUS: staging not achieved`, and a store the
    daemon did not judge eligible, `vox status` showing no rewrite, is `APPARATUS: store not
    rewrite-eligible`); `vox daemon --restart`; assert its reply is `… omp-work is rewriting its
    store (<size>); it is Ready when that ends`, exit 0, returned before the hold ends; type a
    prompt during the hold; assert the shim's notify log holds nothing and the hook's answer is
    "restarting", not Locked; after the hold, assert `vox node list` shows Ready, the turn
    carries the peer's post, and the notify log holds the reconnected line once. This act
    blocks (it is in-tree, in the VMs, part of this file's gate run). Then the
    loaded-consumer case: load the v0.4.30 extension file (APPARATUS: the file at tag v0.4.30)
    under the shim, replace the binary, and assert the conversation still registers and drains
    after the restart (its one old advice line is allowed, and asserted present so the case is
    known to have run). Fails on v0.4.30 (the advice, 37 ms in: run `a4`); not yet run. Mutants:
    end "starting" at hello → the prompt during the attach prints the Locked line → red,
    PRODUCT, quoting the notify log; report a rewriting node as `locked` → the rewriting act's
    prompt prints the Locked line → red, PRODUCT, quoting the notify log; make
    `wait_for_replacement` wait for Ready through a rewrite → the restart's reply arrives after
    the hold, not before, or times out at `REATTACH_WITHIN` → red, PRODUCT, quoting the reply
    and its time; emit `type: "state"` → the old-extension case fails the
    watcher → red, PRODUCT, quoting the shim's "invalid frame" line. Acceptance: F40-1.

- **RS-8. A registration whose OMP is gone is ended, once, and removed (changed r3).** A
  registration whose OMP process has exited MUST NOT be followed by the daemon, MUST NOT be listed
  as present by `vox room sessions` or `vox agent doctor`, MUST post nothing into the room except
  its Session's end and its participant's `bye`, each exactly once in the room's history however
  many times the daemon restarts, and MUST be gone from disk 24 hours after that end is in the
  room. A registration whose OMP lives MUST never be ended or removed, whatever its watcher is
  doing.
  - *Why:* item 42 (C5). The fence's `lifetime` lock belongs to the watcher process, not to OMP
    (`omp_fence.rs:211-245`). Revision 2 set `ended_ms` first and never retried the room end, so
    a daemon killed between the two left a phantom for ever (second review N8).
  - *Changes:* the registration (`wake.rs:393`) gains `instance` (the fence instance id; the
    extension passes `--instance`), `ended_ms` (the intent) and `end_posted` (the completion:
    the entry hashes of the Session end and the `bye` in the room). A registration is dead when,
    on two checks 60 s apart, both its instance's `lifetime` lock is free and a connect to its
    wake endpoint fails with `ENOENT` or `ECONNREFUSED` (a suspended OMP's listener still
    accepts; a timeout or a full backlog is "alive"). The reaper, every 60 s, under the
    registration's mutation lock, re-checks both before acting, then: (1) sets `ended_ms`; (2)
    for every registration with `ended_ms` and without `end_posted`, including after a restart,
    looks the room's history up by the Session's opening (`sessions::lookup`, `sessions.rs:311`)
    and the `bye` by `from = <session id>` and `data.opening = <opening entry hash>`; posts
    whichever is missing (the end with "OMP ended"; the `bye` as RS-11's), and records both hashes
    in `end_posted`; a refused append leaves `end_posted` unset and is retried next tick; (3)
    deletes the registration and its instance directory when `end_posted` is set and
    `now - ended_ms ≥ 24 h`. `open_registered` (`host.rs:2084-2218`) and the mirror follow only
    registrations without `ended_ms`. `vox agent doctor` says `ended (OMP gone, Nov 12 20:31)`,
    or `ending (OMP gone; its room end is not yet posted)`. A registration without an instance
    (Claude, Codex, OpenCode hooks, which register every turn) keeps today's behaviour.
    `omp-watch --cleanup` (the orderly path) sets both fields the same way.
  - *Deleted:* the "could not be opened" notice for dead registrations.
  - *Proof:* extend RS-7's file, with the peer's `vox room sessions --json` as the verdict: (a)
    SIGKILL the shim's Node process (OMP gone), restart the daemon; assert the daemon log has no
    "observation stopped" for that id and, after the second check, the peer lists it ended once;
    (b) kill only the watcher (`vox agent omp-watch`) while the shim lives; assert it is still
    listed as present and a turn drains; (c) a 76-exit succession (APPARATUS: a client built with
    another control-protocol number, `test-knobs`) while the shim lives; assert the same; (d)
    SIGSTOP the shim for 3 minutes; assert still present, and after SIGCONT a turn drains; (e)
    crash: with `test-knobs` `VOX_TEST_CRASH_AFTER=ended_ms` the daemon aborts after writing
    `ended_ms`; restart it; assert the peer lists one end and one `bye` for the session, not zero
    and not two, and the doctor said "ending" in between. Then restart the daemon with the clock
    moved 25 hours (`VOX_TEST_CLOCK_STEP_MS`, `crates/vox-core/src/time.rs:114`, `test-knobs`);
    assert (a)'s registration and instance directory are gone and the live ones are not. Fails on
    v0.4.30 ("observation stopped" for a dead registration: `beast/daemon-current.log:680`); not
    yet run. Mutants: judge by the lock alone → (b) ends a live conversation → red, PRODUCT,
    quoting the peer's list; skip step (2)'s retry → (e) shows no end → red, PRODUCT, quoting the
    peer's list. Acceptance: F42-1.

- **RS-9. A conversation keeps the identity it registered with (changed r5).** A conversation
  registered under one node identity MUST never act as another. After the node is rebuilt under
  the same name, with or without the whole data root, whether or not OMP restarted meanwhile, and
  whichever point of its own history the conversation has gone back to, the conversation's next
  turn MUST post, claim and drain nothing, and MUST show:

  ```
  Vox: this conversation was registered with omp-work as lp3juw…; omp-work is now bqkvu5… (made Nov 11). Nothing was posted. Start a new conversation, or carry this one over: vox agent session rebind 01a18476
  ```

  - *Why:* item 48 (C10). Revision 2 pinned the identity in the OMP session's active branch;
    selecting an earlier leaf (OMP's `session_tree`/`session_branch`, which the extension already
    follows at `omp-extension.ts:1084-1089`) walks a branch without the pin, and the rule "no pin
    means first registration" would adopt the rebuilt identity (second review N7). OMP's `/clear`
    appends a boundary whose parent is the current leaf, so a branch walk still passes the pin;
    only tree selection does not.
  - *Changes:*
    - *The binding is session-wide, not branch-wide:* the extension appends, with
      `pi.appendEntry("vox-identity", {node, fingerprint, at})` (a `custom` entry outside the
      model's context, the API it already uses for `CONTEXT_STAGED` at `:1231`), and reads the
      binding as **the newest `vox-identity` entry among all entries of the session**
      (`ctx.sessionManager.getEntries()`, exposed read-only to extensions), never from
      `getBranch()`. Entries are append-ordered and never removed, so "newest" is well defined
      and selecting an earlier leaf changes nothing. A session with any `vox-identity` entry has
      bound before.
    - *Order of effects, with a durability acknowledgment:* the first `--attention-register`
      carries no `--identity`; the daemon answers with the attached node's identity
      (`Attached.fingerprint`) and writes nothing but the registration file, marked
      `identity: pending`; it follows no wake and accepts no prepare or drain for a pending
      registration. The extension then (1) `pi.appendEntry("vox-identity", …)`, which the
      installed OMP records in memory and appends to the session file without throwing: a write
      failure is latched, not raised (`session-manager.ts:1954-1988`), and a new session may not
      have a file yet (`:1662-1664`); so (2) `await ctx.sessionManager.ensureOnDisk()`, which
      forces the file's creation, rewrites it if the append latched a failure, and rejects with
      that failure (`:2788-2793`, through `#rewriteAtomically` and `#scheduleDiskWork`,
      `:1795-1810,1355-1372`); then (3) reads `ctx.sessionManager.getSessionFile()` itself and
      confirms a line with `"customType":"vox-identity"` and the entry's id is in it; only then
      (4) calls `--attention-register --identity <fingerprint> --bound`, which the daemon answers
      by clearing `pending`; every later prepare and drain carries `--identity`. If (2) rejects
      or (3) does not find the line, or `getSessionFile()` is undefined (a session OMP does not
      persist), the extension stops at once: no prepare, no drain, the notify line `Vox: could not
      record this conversation's identity in its session (<error>); nothing was posted`, and it
      tries again at the next turn. A hook with no `--identity` from a session that has bound
      before is refused: `OtherIdentity`, exit 77, with the text above naming "unknown" for the
      old identity. A pending registration whose extension never returns is an ordinary dead
      registration for RS-8 and holds no node (a pending registration counts as no holder).
    - *Daemon side:* every `register`, `prepare` and `drain` compares `--identity` with the
      attached node's identity and refuses with the text above on a difference (`OtherIdentity`,
      exit 77; ADR-040's `NotYet` is for waits). The extension's hook wrapper
      (`omp-extension.ts:333-348`) today drains stderr and maps exit 77 to "registration failed";
      it is to read the refusal's structured line from stdout (`{"refused":"other-identity",
      "registered":"lp3juw…","now":"bqkvu5…","made":"2026-11-11","session":"01a18476"}`) and
      show the text above, once per identity change. The registration file records `identity`
      as a copy for `vox agent doctor` and `vox room sessions`; it is never the authority.
    - *Rebind, by the same transaction:* `vox agent session rebind <id>` writes
      `<control dir>/rebind/<id>` `{to: <fingerprint>, approved}` and ends the old Sessions it
      can reach. The next hook of that conversation that would be refused finds the
      authorization: the daemon marks the registration `identity: pending(B)` and answers with
      B; the extension runs the four steps above for B (append, `ensureOnDisk`, readback,
      `--attention-register --identity B --bound`); only on that acknowledgment for the
      authorized fingerprint does the daemon clear `pending` and remove the authorization. On an
      append failure, a readback miss or OMP's death at any point before the acknowledgment the
      authorization stays and the registration stays pending; the next hook repeats the steps
      idempotently (an entry for B already on disk is found by the readback and acknowledged).
      Newest entry wins, so an older branch cannot undo it. The watcher reports `node:
      "other-identity"` (RS-7).
    - *Pre-release conversations:* a session with no `vox-identity` entry and a registration
      file that predates this release takes the current identity at its first hook, once, and
      the daemon log says so; this is the one adoption, and it happens before any rebuild that
      this release can detect.
  - *Deleted:* nothing.
  - *Depends on:* RS-7 (the frame), RS-14 (an opened node is the identity its vault says).
  - *Proof:* extend RS-7's file; the shim's session store is OMP's own persistence shape (a
    JSONL file written by `appendCustomEntry`'s rules: in-memory first, a synchronous append
    whose failure latches and does not throw, `ensureOnDisk` rejecting on a latched failure), so
    that the apparatus can branch it, select a leaf, and make an append fail (`ENOSPC` on the
    store's file system, or a read-only directory). Cases, each ending with the assertions "the
    shim shows both fingerprints; the peer's `vox room read` is unchanged; `vox room board` lists
    no claim by it; after `vox agent session rebind`, a turn posts": (a) stop the daemon; `mv
    nodes/A nodes/A.old; vox node create A`; start; prompt; (b) the same with the whole root
    moved; (c) (a) then restart the shim (OMP restarted) before the prompt; (d) register under A,
    select an earlier leaf in the shim's store (before the `vox-identity` entry), rebuild,
    restart the shim, prompt: assert the refusal, not an adoption; (e) after rebind in (d),
    select the older leaf again: assert the conversation still acts as the rebound identity; (f)
    *append fails:* a pre-release conversation resumes with its session store on a file system
    the apparatus has filled (a small tmpfs in the Linux VM, a small RAM disk in the guest; a
    read-only parent directory would not stop an already-open writable file), so the append
    latches `ENOSPC`; the first hook; assert the notify line "could not record this
    conversation's identity", that the peer's `vox room read` is unchanged, and that `vox room
    sessions` lists it as `pending`; free the space, prompt again: assert the entry is in the
    file and the turn posts; (g) *a first attempt dies before the acknowledgment* (APPARATUS
    makes the append genuinely volatile: the same full file system, then SIGKILL the shim between
    the append and `ensureOnDisk`), rebuild as B, resume: the conversation had no confirmed
    binding, so the correct outcome is a pending registration that then binds to B, with no
    refusal and nothing posted under A; assert that, and that `vox room sessions` showed
    `pending` in between; (g') *a confirmed binding A, rebind to B authorized, the B append dies
    before the acknowledgment* (same staging): resume against B; assert the refusal names A, the
    authorization is still there, and the next hook finishes the rebind with no second command;
    (g'') the B entry on disk, killed before `--bound`: resume; assert the hook's readback finds
    B, acknowledges, and the authorization is removed. Fails on v0.4.30 (the turn posts as the
    new identity); not yet run. Mutants: read the pin from `getBranch()` → (d) adopts → red,
    PRODUCT, quoting the peer's read; skip the daemon comparison → (a) posts → red, PRODUCT,
    quoting the peer's read; proceed without the acknowledgment → (f) registers → red, PRODUCT,
    quoting `vox room sessions`; remove the authorization at the append → (g') needs a second
    rebind → red, PRODUCT, quoting the refusal after resume. Acceptance: F48-1.

### 4. Compatibility is by contract version

- **RS-10. Coordination is gated by claim-protocol level, never by package version (changed r5; r7;
  the decider's Q2, ledger row 44).** A claim made before `vox update` MUST still be held by the same session after
  every worker updated to a release with the same claim-protocol level. Every worker in a room
  MUST fold the same history: a worker folds only operations at its own level, and MUST refuse
  coordination when any participant's latest counted record carries a different level, naming
  both:

  ```
  vox: coordination refused: omp-beast (session 3f0c25bf) speaks claim protocol 2; this vox speaks 1. Update this computer: vox update
  ```

  A change to the claim fold's rules MUST raise the level; the release that raises it MUST ship
  the room's transition (the room-pinned level reserved in "Alternatives"), and the release notes
  MUST name the level. A record whose level is missing or malformed is level 0, which no worker
  implements, and is refused by name, with one exception the decider chose (Q2, ledger row 44):
  **a record from v0.4.30 (`data.vox == "0.4.30"` and no `coord`) reads as level 1, so every
  claim made on v0.4.30 is kept across the update**; that reading stays for as long as any
  room's held claims depend on it, is never removed by a package milestone, and leaves with the
  first room transition.
  - *Why:* item 43 (C6). With one level implemented, equality on the contract is the simplest
    rule that keeps every reader's fold identical; it is exactly today's rule with the package
    string replaced by the level. Revision 2's "deleted at v0.4.32" for the 0.4.30 reading would
    have ended a surviving 0.4.30 claim one release later (second review N13).
  - *Changes:* `crates/vox-agentcomms/src/version.rs`: `Stamp` compares `data.coord` (an integer)
    with `CLAIM_PROTOCOL = 1`. `claim.rs:375-385` folds ops at that level and reports the rest as
    `OtherLevel`. `coord.rs:880` writes `coord` and keeps `vox` for display only.
    `crates/vox-core/src/node/work_board.rs:29,627-628` pass the level, not the package version,
    to the fold and the table. `room_cli.rs:4528-4530` prints the one refusal text above.
  - *Deleted:* the `is_semver` gate (`version.rs:97,127`); the package-version equality in
    `stamp_of`; every other copy of the refusal wording.
  - *Proof:* extend `work_version_proof.rs`: two workers claim on binary A (level 1); update one to
    binary B (level 1, another package version: the proof builds B with a changed
    `CARGO_PKG_VERSION`, as `update_proof.rs:961-965` `vox_saying` builds its changed-version
    helper); assert `vox room board` on B lists A's claim held by the same session, and `vox room
    claim` of another unit on B exits 0. Then binary C, built with the `test-knobs` feature
    `coord-level-2` (it changes only the advertised number): assert B refuses naming "claim
    protocol 2" and C refuses naming 1; this proves the refusal, and nothing about a future
    transition, which is out of this release. Then the decider's Q2 (r7): A is the v0.4.30
    release asset (APPARATUS; ADR-045 FG-2): a worker on A claims a unit; update that worker to
    the candidate (RS-2 (d1-remembered)); assert `vox room board` on the candidate, and on the
    other worker, lists that claim held by the same session, and that `vox room claim` of the
    same unit by the other worker is refused as held. Fails on v0.4.30 (the board is empty after
    the update: run `b1`); not yet run. Mutants: restore package equality in `stamp_of` → red,
    PRODUCT, quoting the board; read a record with no `coord` as level 0 → the Q2 act's board
    drops the claim and the other worker's claim succeeds → red, PRODUCT, quoting the board. The
    proof's exact-version refusal assertions are deleted. Acceptance: F43-1.

- **RS-11. An open Session is announced by its daemon, and one Session's end retires only itself
  (changed r3).** A conversation whose Session is open in a room MUST count as a participant at
  the level its node runs now, from the moment the Session opens. After an update, every live
  conversation's level MUST be current as soon as its daemon has reopened its Sessions, with no
  turn and no claim. An ended Session MUST stop counting, and its end MUST NOT retire another
  live Session of the same node.
  - *Why:* item 44 (C7). The counted records are the existing work `hello` and `bye`
    (`envelope::HELLO`, `BYE`), admitted by the CLI snapshot (`coord.rs:761-778`) and the board
    (`work_board.rs:36-61,618-628`) and by `version.rs::counts`. Today's `version_table`
    (`version.rs:211-234`) keeps one latest record per **author** and drops the author when it
    is a `bye`, so a `bye` for one Session would retire its node's other live Session (second
    review N9).
  - *Changes:* the record is a work `hello` as an ordinary room post (not `AppendSession`, the
    private Session route at `sessions.rs:340-355`), `from = <session id>`, `data.coord`,
    `data.vox`, `data.opening = <opening entry hash>`, no name or cwd. The daemon posts it when it
    opens a Session (after `open_when_member`'s opening parts) and, at each daemon start, for
    every Session it reopens whose latest counted record in that room is missing or carries
    another `coord` or `vox` than this daemon's (the refresh on an upgrade; idempotent
    otherwise). The daemon posts the `bye` with the same `from` and `data.opening` when a Session
    ends (the harness's `SessionEnd`, RS-8's reaper, `vox agent session rebind`), under RS-8's
    retry rule. `version_table` keys its latest record by `(author, from)`: a `bye` ends that
    pair only; a node's level is the stamp of its latest live pair; `Participant` lists one row
    per live pair, and the board shows them. The CLI with no Session keeps `participate`'s hello
    (`coord.rs:1043-1046`) with its own `from`, as today. The 24 h horizon stays per pair. `vox
    room board --json` gains `coordination: "ok" | {"refused": <the RS-10 line>}` and
    `participants: [{node, session, level, vox, last}]` as its public schema.
  - *Deleted:* `announced_before` and `announced` (`coord.rs:343-400`) and the drain hook's
    announcement (`agent_hook.rs:4028-4038`); the "b-silent" assertion
    (`work_version_proof.rs:497-514`), which asserts the defect; the per-author table.
  - *Depends on:* RS-10, RS-8 (ended Sessions post their `bye`, once).
  - *Proof:* extend RS-10's proof: before the update, conversation A is open and idle on the
    worker to be updated; after the update, start conversation B (new session id) on that worker
    with no claim; assert the other worker's `vox room board --json` reports
    `coordination: "ok"` within one sync and lists A and B at level 1 (A refreshed, B announced);
    end B (the shim's SessionEnd); assert the board still lists A, no longer lists B, and `vox
    room claim` on the other worker exits 0. Fails on v0.4.30 (refusal until the new session
    claims: run `b3`); not yet run. Mutants: skip the hello at Session open → B absent and, with
    a level-0 peer staged, the refusal persists → red, PRODUCT, quoting the board; key the table
    by author → ending B drops A → red, PRODUCT, quoting the board. Acceptance: F44-1.

- **RS-12. A client and its own daemon agree by control-protocol number (changed r4; r8).** A client
  (the app, the TUI, every verb, every hook and the OMP watcher) MUST refuse its own daemon only
  when their control-protocol numbers differ, naming both:

  ```
  vox: this vox speaks control protocol 12 and its daemon speaks 11: restart the daemon with vox daemon --restart
  ```

  Different package versions with the same number MUST work everywhere. `vox status` and the app
  MUST still name both package versions when they differ (ADR-034 UP-3). Any change to a frame
  in `crates/vox-core/src/node/ipc.rs` or `daemonipc.rs` raises `PROTOCOL_VERSION`; v0.4.31
  raises it once, from 11 to 12, for everything this release adds. The list is not exhaustive
  (r8); it names what this and the sibling ADRs are known to add: the hello's `incarnation`,
  `supervised` and per-node states (RS-2), `Stop { reason }` (RS-5), `--identity` and
  `OtherIdentity` (RS-9), ADR-040 NW-1's typed attention answer with `wait_ms` and
  `Fault::NotYet`, `SessionRegister`'s `state` and `observed_ms` (ADR-040 NW-9), and ADR-049
  LE-1's `Frame::Left` (ADR-050's turn journal needs no request of its own: its exit 79,
  `--omp-finish`, `--decided`, `--record` and structured line are hook surface). A hook flag or
  exit code (ADR-050's 79, this ADR's 77) and the extension's pipe are not the control
  protocol; the daemon requests they need are.
  - *Why:* the contract-version goal; item 40's update window. Run `b2`: a prompt typed between the binary swap and
    the restart was refused `Vox's daemon is 0.4.29 and this vox is 0.4.30`, and that turn got no
    room news. The window still exists between the new binary landing and the restart, and with
    RS-2's bundle order it is longer (the old daemon serves until the restart step), so it must
    not refuse.
  - *Changes:* every client-side gate: `daemonipc.rs:2270-2282` keeps the `PROTOCOL_VERSION`
    check and drops the package-version refusal; `omp_watch.rs:92-100` (`open`) drops
    `g.version != CARGO_PKG_VERSION` and keeps the protocol comparison, so a same-protocol update
    no longer exits 76; `restart.rs:605-652` compares the protocol number and the expected
    package version it was asked to install (the updater's check, not a gate on requests); the
    app's hello (`apps/macos/Vox/Daemon.swift`) likewise. `vox daemon --restart` reaches a daemon
    of another protocol number through the hello alone, as the repair path does today
    (`restart.rs:360-370` reads Hello only).
  - *Deleted:* the package-version refusal (`IpcHandshake::Version`) and its texts, in every
    client.
  - *Proof:* extend `update_proof.rs:938` (`an_update_restarts_its_daemon_and_refuses_a_different_local_version`),
    two journeys kept apart. (a) *Same control protocol, another package* (every update after
    this one): binaries A and B at protocol 12, different `CARGO_PKG_VERSION` (`vox_saying`,
    `update_proof.rs:961-965`); in the window between publish and restart, `vox room list` from
    B is answered by A's daemon and the loaded extension (RS-7's shim) completes a turn. (b)
    *The 11 → 12 update* (this one): the v0.4.30 release asset's daemon serves; after publish and
    before the restart step, `vox room list` from the candidate is refused naming 12 and 11 and
    `vox daemon --restart`, the watcher exits 76 and the shim prints its "Vox update detected"
    line; the restart step then finishes within its bounds and the next turn completes. A client
    built with another control-protocol number (`test-knobs`) is refused with both numbers in
    either. Fails on v0.4.30 (run `b2`: (a)'s window refused by package version); not yet run.
    Mutant: restore the package-version refusal in `omp_watch::open` → the turn in (a)'s window
    gets the mismatch → red, PRODUCT, quoting the shim's log. Acceptance: F43-2.

### 5. The daemon is bound to the profile it opened

- **RS-13. Every write lands in the directory the daemon opened; a replaced root stops it
  (changed r3).** A daemon MUST write only into the directory inodes it opened when it took the
  lock, so that no write of its reaches a folder that took its path afterwards, whether or not it
  has noticed. A daemon whose data root is replaced or removed MUST stop as soon as it is
  scheduled and sees it (checked every second; a SIGSTOPped daemon sees it on resume) and say so:

  ```
  vox daemon: my data root /Users/robert/Library/Application Support/vox was replaced or removed; stopping. Nothing was written to the new folder.
  ```

  After "start over" under a running daemon, the new node MUST keep its own data: a post it
  made is read back after a restart, and its `store.redb` keeps its inode.
  - *Why:* item 45 (C8), the directory-identity goal.
  - *Changes:* `Account` and `Paths` (`crates/vox-core/src/node/paths.rs`) hold directory file
    descriptors for the data root, `.daemon/` and each attached `nodes/<node>/`, and offer
    `openat`/`renameat`/`unlinkat`/`mkdirat` helpers; `omp_fence.rs:181-209` already writes this
    way. The lock is opened through the root's descriptor. `Store` keeps `(dir, name)` instead of
    a path and opens through the descriptor: writable with redb's `Builder::create_file(File)`;
    read-only with a new vendored `Builder::open_read_only_file(File) -> ReadOnlyDatabase`
    (`vendor/redb/src/db.rs:2223-2236` opens the path itself today; the new method takes the
    `O_RDONLY` file the caller opened through the node's descriptor and wraps it in `FileBackend`
    as the path form does; `ReadOnlyDatabase::new` is private to the crate, so the method lives
    in the vendored crate). `make_writable` reopens through the same descriptor.
    `rewrite_fresh_locked` renames with `renameat`. `room_pause.rs:233` (in `crates/vox-tui/src/`),
    `decisions/`, `files/` and `pulls/` write through the node's descriptor. A 1 s watchdog
    compares the root descriptor's device and inode with `stat` of the path and begins the clean
    stop (S-1); every writer checks the watchdog's flag before it starts, and the fd binding, not
    the watchdog, is what keeps a late write out of the new folder. A waiting login-item daemon
    (ADR-014 M-9) resolves the path each time it polls and binds when it takes the lock. Review
    aid: `rg 'std::fs::(rename|write|create_dir|create_dir_all|remove_file|File::create|OpenOptions)'`
    over `crates/vox-core/src/node` and the daemon's code in `crates/vox-tui/src` is empty
    outside `paths.rs`; aliases and libraries escape it, so the proofs are the guard.
  - *Deleted:* the existence poll (`daemon.rs:318-321`).
  - *Depends on:* ADR-047 changes how the store is rewritten (disk-full recovery, compaction);
    every rewrite there MUST use the store's directory descriptor. A rewrite changes the store's
    inode legitimately; the inode assertion below runs with no rewrite scheduled.
  - *Proof:* extend `whatever_holds_a_profile_answers_for_it_proof.rs`, two journeys. (a) *Root
    replaced:* node A in a room with peer P; `mv data data.old; mkdir data`; assert within 10 s
    the old daemon's log has the line above and `ps` shows it gone; `vox node create A` in the
    new root; `vox daemon --restart`; assert `vox node list` shows A Ready. Mutant: drop the
    watchdog → the old daemon lives on → red, PRODUCT, quoting `ps`. (b) *Node directory
    replaced, root kept:* A with P; `vox room leave` on A with P down (a retained leave); stop
    nothing; `mv nodes/A nodes/A.old; mkdir nodes/A` (the root inode is unchanged, so the
    watchdog stays quiet); bring P back so the purge runs; assert within 10 s
    `nodes/A.old/store.redb` was rewritten (its mtime moved) and `nodes/A/` is still empty; then
    the fresh identity: `vox daemon --restart`; `vox node create A` in the kept root; join P's
    room; post; `vox daemon --restart`; assert `vox room read` on A shows its own post,
    `stat nodes/A/store.redb` keeps its inode, and `nodes/A.old` is intact. Mutant: restore the
    path `rename` in `rewrite_fresh_locked` → `nodes/A/store.redb` appears before the create →
    red, PRODUCT, quoting `ls nodes/A`. Fails on v0.4.30 (repro2: the old daemon's purge replaced
    the new store); not yet run on this journey. Acceptance: F45-1.

- **RS-14. A store is checked against its vault before any write, and a foreign store is never
  written (changed r3).** Opening a node MUST compare the identity in its store with the identity
  of its vault before anything is written to the store. A store of another identity MUST be
  refused by name, with its bytes unchanged, whether it is healthy or needs repair:

  ```
  vox: node omp-work cannot be opened: its store belongs to another identity (bqkvu5…, made Oct 31); its vault is lp3juw…. Nothing was changed.
  ```

  - *Why:* item 45 (C8), the directory-identity goal. `Profile::open_noting` gets the fingerprint only after
    `Store::open_read_only` (`profile.rs:279-285`), which falls back to a writable open when the
    read-only open fails or the schema is not current (`store.rs:601-623`); a writable open
    changes the header even without a transaction (`store.rs:535-541`) and redb's repair can
    roll a corrupt primary back and commit rebuilt roots before returning
    (`vendor/redb/src/db.rs:1462-1508,1658-1672`). Revision 2 repaired the original after the
    vault was proved, which proved nothing about the store (second review N5).
  - *Changes:*
    - `Store::open_read_only` never falls back: `DatabaseAlreadyOpen` is `ProfileBusy` (an old
      daemon still holds it; nothing is repaired around it); a non-current schema is refused as
      unsupported (ADR-026 F-3); a store redb cannot open read-only is `NeedsRepair`.
    - `Profile::open_noting` (`profile.rs:269-300`): on a read-only open, compares the store's
      `META_FINGERPRINT` with the `fingerprint` file beside the vault, valid only while its
      SHA-256 matches the vault (ADR-026 F-1); a mismatch is the refusal above, before any
      passphrase. The file is a consistency hint: a missing or stale file falls through to the
      unlock check, which stays the final word in every path (`profile.rs:311-314`, same text).
    - On `NeedsRepair`, the original is not opened writable. The profile opens with no store;
      `unlock` proves the vault first; then **inspection on a copy**: the store file is copied
      through the node's descriptor to `store.redb.inspect` (refused up front, unchanged, when
      the free space is below the file's size: `cannot check omp-work's store: its repair needs
      2.1 GB free and 0.4 GB is free`), the copy is opened writable (redb repairs the copy),
      its `META_FINGERPRINT` is read, the copy is deleted. A mismatch is the refusal above
      (`sha256` of the original is identical before and after). A match repairs the original by
      opening it writable, as `Store::open` does today, and the log says `omp-work's store was
      repaired (redb recovered its last commit)`. A copy that redb cannot repair either is
      refused as `omp-work's store cannot be read (redb: <error>); nothing was changed`, never as
      a foreign identity.
    - The pre-unlock text names the foreign store's own `META_CREATED` ("made Oct 31"); the
      vault's creation date is not stored anywhere authenticated (`atrest/vault.rs:91-110` holds
      version, profile, salt, nonce, ciphertext), so the text does not claim one.
  - *Deleted:* "an internal error — a bug in vox" for this case, "vault identity does not match
    the store", and the writable fallbacks in `open_read_only`.
  - *Proof:* the second half of RS-13's proof: copy `data.old/nodes/A/store.redb` over the new one
    (APPARATUS); assert `vox node unlock A` prints the refusal before asking for a passphrase, and
    the store file's `sha256` is unchanged. Then stage a store that needs repair in a way redb
    recovers from: APPARATUS copies the foreign store, opens it with the vendored redb, begins a
    write transaction and aborts the process before commit, which leaves a dirty primary redb
    repairs on open (`db.rs:1462-1508`); a truncation is not used, since redb need not recover
    it; assert `vox node unlock A` asks for the passphrase, then prints the refusal, and the
    original's `sha256` is unchanged. Then remove the `fingerprint` file: assert the unlock-time
    refusal, by name. Then (positive) the same dirty store under its own vault: assert the unlock
    succeeds and the log says "repaired". Fails on v0.4.30 ("an internal error"); not yet run.
    Mutants: skip the comparison at open → the first case asks for a passphrase → red, PRODUCT,
    quoting the prompt; repair the original instead of the copy → the dirty foreign case changes
    the `sha256` → red, PRODUCT, quoting the two hashes. Acceptance: F45-2.

- **RS-15. "Start over" is `vox factory-reset`, after an explicit confirmation (changed r5; r8; the
  decider's Q3, ledger row 45).** `vox factory-reset` MUST show what it is about to do and act
  only on an explicit confirmation; then stop the daemon of record, refuse while any other
  daemon can still write into the root, move the data root aside (never delete it), say what
  moved, and leave the root served by its enrolled manager if it has one. Interrupted at any
  step it MUST leave the root either as it was or moved, never a half-moved tree, and the next
  `vox status` MUST say what it left, judged from the folders' identities, never from their
  names alone:

  ```
  $ vox factory-reset
  vox factory-reset moves this computer's Vox data aside and starts over with nothing:
    data folder   /Users/robert/Library/Application Support/vox  (5 nodes: omp-work, robert-work, …; 2.4 GB; 14 rooms)
    moved to      /Users/robert/Library/Application Support/vox.reset-20261111T005702Z
    kept          this computer's manager enrollment (/Users/robert/Library/Application Support/vox.control)
    deleted       nothing; the moved folder stays until you delete it
  Every node here, its rooms, claims, sessions and this computer's trust become unavailable; other computers will see this one as gone.
  To go on, type the data folder's name exactly: vox
  > vox
  vox: stopped the vox daemon (pid 57505, launchd's login item)
  vox: moved /Users/robert/Library/Application Support/vox to /Users/robert/Library/Application Support/vox.reset-20261111T005702Z (5 nodes, 2.4 GB)
  vox: this computer now has no nodes and no computer trust; the login item serves the new folder
  ```

  The confirmation is the data folder's last path component, typed exactly (`vox` on a default
  install; the scratch root's name under a proof); anything else, or end of input, is `vox
  factory-reset: not confirmed; nothing was changed`, exit 1. When stdin is not a terminal the
  command MUST refuse without the explicit flag `--confirm-move-aside <folder name>` (the same
  name, so a script states what it moves): `vox factory-reset needs a confirmation: run it in a
  terminal, or pass --confirm-move-aside vox`, exit 2, nothing changed; with the flag it prints
  the same summary and acts. No other flag skips the confirmation.
  - *Why:* item 45. "Stop, then move" alone recreates C3's lock-free interval: a waiting
    login-item daemon polls the lock every 250 ms (`daemon.rs:180-208`) and a client may
    cold-start; revision 2 put its exclusion inside the root it moved (second review N4);
    revision 4 judged a killed reset by which paths existed, which a cold-starting client can
    change (fourth review F4-2). The decider asked for the command "with an approval follow up
    required" (row 45).
  - *Changes:* a new verb, a transaction whose authority lives in the control directory
    (`<data root>.control`, Terms), which the rename of `<data root>` does not touch; on a
    default Mac the config dir is the data root itself (`paths.rs:837-858`) and holds nothing of
    this. Steps, after the confirmation: (1) take the restart lease (Terms: the command is about
    to take the lock itself) and write `planned {reason: reset}`; every daemon start and every
    waiting daemon's `take_account` attempt obeys the lease, every client waits on it; (2) scan
    for processes that can still write into the root: every process with a file open under
    `<data root>` (`lsof +D` on macOS, `/proc/*/fd` on Linux); the daemon of record (the pid and
    incarnation the hello gave) is expected; the enrolled manager's job pid, if it is waiting,
    holds no file open (its `try_lock` opens and closes `.daemon/lock` on each failed attempt)
    and is not refused; any other process is a writer that obeys no new rule (the pre-fix orphan
    of `rca-RcaStore`, or a daemon started by hand on this path): `vox: factory-reset refused:
    vox daemon pid 57505 (started Nov 10, vox 0.4.30) still holds files under this folder; stop
    it first: kill 57505`, and stop, nothing changed; if the scan itself fails, refuse with its
    error; (3) write `<control dir>/reset.journal` `{root, root_id: <dev, inode of the root
    directory>, to, daemon: {pid, start_time}, phase: stopping, began}`, where `to` is a
    destination that does not exist (the timestamp name, with a `-2` suffix if it does); (4) stop
    the daemon of record by product request `Stop { reason: Reset }` (exit 0, so no manager
    restarts it; SIGTERM for a protocol-11 daemon, RS-2) and wait until that pid with that start
    time is gone; rescan as in (2), now expecting nobody; (5) take `.daemon/lock` through the
    root's descriptor; journal `phase: moving`; `rename` the root to `to` (atomic); journal
    `phase: moved`; (6) create the new empty root, write `<new root>/.daemon/reset-from` naming
    `to` and `root_id`, journal `phase: done`, remove the journal; (7) release the lock and the
    lease, remove `planned`; where a manager is enrolled, `kickstart`/`start` it (a waiting
    login-item daemon takes the new root by itself; its lease attempts resume when the command's
    lease is gone). *Recovery after a kill, by identity, under the lease:* the readers are the
    daemon at start (before admission, so a client's daemon never creates `.daemon` under a root
    in question: RS-2 moved `create_private_dir` into the daemon after the lease), `vox status`
    and `vox factory-reset`; each takes the lease, reads the journal, and `stat`s `<root>` and
    `<to>`, comparing with `root_id`:
    - `<to>` is a directory with `root_id` → **moved**, whatever `<root>` is: if `<root>` is
      absent, the reader creates it with `reset-from` and finishes; if `<root>` exists without
      `reset-from` (a cold start made it after the rename), the reader writes `reset-from` into
      it and finishes, touching nothing else in it; if it has `reset-from` naming `to`, the
      reader finishes the journal. `vox status`: `a factory reset begun 00:57 moved the old data
      to <to>; this folder is new`.
    - `<root>` is a directory with `root_id` and `<to>` is absent → **not moved**. If the journal
      is `stopping` the reader re-observes the captured daemon (pid and start time): still there
      and serving → `a factory reset begun 00:57 did not start; nothing changed` and the journal
      is removed; stopping or gone → `a factory reset begun 00:57 stopped the daemon and moved
      nothing`, the journal is removed, and the next client or the manager serves the unchanged
      root (RS-5). `moving` with this state is the same as `stopping`: the rename did not happen.
    - anything else (neither directory carries `root_id`; `<to>` exists with another identity;
      `<root>` carries `root_id` and `<to>` also exists) → **refuse to decide**: `vox status`:
      `a factory reset begun 00:57 cannot be reconciled: <root> is not the folder it recorded and
      <to> <is missing | is another folder>; nothing was changed; see <journal path>`; no daemon
      serves the root (the daemon at start exits saying so) until a person removes the journal or
      runs `vox factory-reset --abandon-journal` after reading it. Nothing is ever moved twice.
    What it says about pairing again is ADR-043's. *On the fleet (r8, X041-19, Main's ruling):*
    ADR-045 J8 runs `vox factory-reset --confirm-move-aside <name>` with a daemon running where
    it rebuilt the profile by hand before, as one step of that journey, and asserts the three
    lines above; ADR-045 carries that step. The refusal arm (an orphan writer; the wrong or
    missing confirmation) and the confirmation arm stay in this requirement's in-tree proof.
  - *Deleted:* nothing. `vox reset` (revisions 2–4) was never a verb.
  - *Proof:* extend RS-13's proof, in the VMs, orderings each with a `vox room list` loop in the
    background and a client paused after its probe (RS-2's apparatus): (a) `vox factory-reset`
    with a daemon running, confirmed by typing the folder name; assert `ps` shows no daemon for
    the old root at the moment of the move, the root is moved and byte-identical (`sha256` over
    the tree), `vox node create` works in the new root, and no `vox room list` started its own
    daemon; (a') typed wrong, and non-interactive without the flag: assert "not confirmed" / the
    exit-2 line and that nothing changed; (b) with a real waiting login-item daemon (RS-5's guest
    job): assert the command did not refuse it, it serves the new root after the reset and its
    log never names the old one; (c) with an orphan staged (APPARATUS: a second daemon started
    on a copy of the root path that was then moved): assert the refusal names its pid and
    nothing moved; (d) kill the command (SIGKILL) at each of four points (`test-knobs`
    `VOX_TEST_CRASH_AFTER=stopping|moving-renamed|moved|created`; `moving-renamed` is after the
    rename and before the `moved` write), and at `moving-renamed` let a cold-starting client
    create the original path before any reader runs (the apparatus runs the v0.4.30 release
    asset's `vox room list`, whose `start_daemon_bounded` still creates `.daemon` by path,
    `daemon_client.rs:179-186`); assert the moved tree is byte-identical and at `to`, `vox
    status` prints the matching line above (for `moving-renamed`: "moved …; this folder is
    new", never "moved nothing"), the paused client resumed started no daemon while the lease
    was held, and once it is gone the manager's or its own daemon serves a root whose
    `.daemon/reset-from` names the moved one; (d') the ambiguous state (APPARATUS renames `to`
    away after the kill): assert the "cannot be reconciled" line and that no daemon serves;
    on the default Mac layout (data root and config dir the same path, the guest's real
    `~/Library/Application Support/vox`), not only on scratch roots. Fails on v0.4.30 (no verb);
    not yet run. Mutants: release the lease before the rename → (b)'s waiting daemon opens the
    old root → red, PRODUCT, quoting its log; judge by path existence instead of `root_id` →
    (d) at `moving-renamed` says "moved nothing" → red, PRODUCT, quoting `vox status`; keep the
    journal in the config dir → (d) on the default layout prints nothing after the kill → red,
    PRODUCT, quoting `vox status`. Acceptance: F45-3.

### 6. The updater judges the process itself

- **RS-16. The app's quit is judged from the process table (changed r3).** `vox update` MUST
  report the app quit only when the pid it captured, with that process's kernel start time, is
  gone from the process table. It MUST report failure only when, after `terminate`, SIGTERM and
  SIGKILL each given 10 s, that process is still there; the update log MUST then hold a stack
  sample of it, if it was still there to sample. It MUST never launch a second instance while the
  captured one lives, MUST never signal a pid whose start time is not the captured one, and MUST
  treat an exit between identifying, capturing and terminating as the app having quit.
  - *Why:* item 46 (C9), the plan's "the updater judges the process itself". Right under reading A and reading
    B; it does not wait for the probe. The operator's "did not quit within 30 seconds" came from
    the 0.4.28 engine's 30 s poll; v0.4.30's engine (`bundle.rs:3975-3993`) waits 10 s on
    `isTerminated`, then `forceTerminate`, then `SIGKILL`, and under reading B throws after
    `kill` of a gone pid because its observer still says the app is there.
  - *Changes:* the `stop` branch of `bundle.rs`'s `APP_HANDOFF` becomes a Rust wait in `bundle.rs`:
    the JXA identifies the instance and returns its pid; Rust captures the kernel start time at
    once (`proc_pidinfo(PROC_PIDTBSDINFO)`, as `daemon_process` at `restart.rs:94-125` does) and
    never compares it with AppKit's `launchDate`; a pid already gone or with another start time
    at capture is "quit"; the JXA sends `terminate`; Rust waits with `kill(pid, 0)` until
    `ESRCH`, re-reading the start time before every step so a reused pid is never signalled;
    after 10 s `/usr/bin/sample <pid> 3` into the update log (best effort: a process that exits
    during the sample is "quit"), SIGTERM, 10 s, SIGKILL, 10 s; a zombie counts as gone; an
    inspection error fails the update honestly with the error and signals nothing. The relaunch
    in `transition_failed_journal` is gated by the same kernel check. The log is to say
    `Vox.app quit on request; pid 84218 gone at +2.9 s`, or `Vox.app did not quit on request;
    stopped with SIGKILL at +20.4 s; stack sample in <log>`. launchd (`ExitTimeOut`) and systemd
    (`TimeoutStopSec`) judge a stop the same way.
  - *Deleted:* the `isTerminated` polls and `forceTerminate` (`bundle.rs:3975-3993`).
  - *Proof:* extend `update_proof.rs:938`, macOS section. APPARATUS: a stub app bundle whose exit
    is held 40 s after it accepts the quit (reading A), and a plain fast quit. Assert the update
    succeeds, exactly one app instance runs after, and the log holds the kernel line with a time:
    `gone at +<t> s` with t < 5 for the fast quit, and `stopped with SIGKILL` plus a sample file
    for A. Reading B cannot be staged from outside, and no proof asserts on code. v0.4.30 under
    A succeeds without a sample and says "stopped" (read from `bundle.rs:3989-3994`, not run), so
    its red is the missing sample line: unverified until run. Mutant: restore v0.4.30's JXA
    verdict → no kernel line in the log → red, PRODUCT, quoting the log. Acceptance: F46-1.

## Review record

Each finding, verified against v0.4.30 (commit 8d71ab337), its classification, and the
requirement that answers it. Receipts are in `adr-041-revision.md`.

### First review (`adr-041-sol-review.md`)

| # | Finding | Class | Evidence | Answered by |
|---|---|---|---|---|
| 1 | RS-2 detached nodes, then handed over secrets the daemon no longer has | CONFIRMED | `host.rs:255-290` `Attached` holds `keep: Option<KeepSource>` and no passphrase; `profile.rs:19-20` "never retained"; detach wipes keys (`host.rs:5241-5247`) | RS-2: nothing crosses the restart; the remembered store (RS-1, Keychain) is the only source. A node with no remembered source is Locked and says so (RS-1, RS-4; Q5) |
| 2 | The hand-over pipe is filled before exec with no reader | CONFIRMED | revision 1 RS-2 step 3; `pipe(7)` capacity | RS-2: no pipe, no exec |
| 3 | The bundle transaction stops before `publish`; an exec there runs the wrong binary | CONFIRMED | `bundle.rs:1129-1158` `stop_transaction` is called before `publish` (`:1160`); `stop_captured_daemon`'s only caller is `:1145` | RS-2 (r3): the daemon is no longer stopped before `publish`; the restart step runs after it |
| 4 | No abort path when `execve` fails after nodes are detached | CONFIRMED | `execve(2)` returns to the old image | RS-2: no exec |
| 5 | No directory identity or descriptor manifest across exec | CONFIRMED | `daemon.rs:407-475` opens, locks and binds by path | RS-2: no exec; RS-13's descriptors are the daemon's own |
| 6 | RS-9's pin lives in the directory a rebuild replaces | CONFIRMED | registration path `nodes/<node>/sessions/<id>` (`wake.rs:393`) | RS-9 (r3): the newest `vox-identity` entry among all entries of the OMP session |
| 7 | Session rows never reach the coordination consumers | CONFIRMED | `coord.rs:761-778`; `work_board.rs:36-61,618-628` | RS-11: the daemon posts the counted work `hello`/`bye` as ordinary room posts |
| 8 | Announcements are not refreshed on upgrade and never end | CONFIRMED | `sessions.rs:198-237`; `version.rs:211-229` | RS-11: refresh at daemon start; `bye` at every Session end, retried (RS-8) |
| 9 | `<=` folding diverges across levels and on a self-downgrade | CONFIRMED | `version.rs:211-229` | RS-10: equality on the level; a level change ships a room transition |
| 10 | A new frame type fails the loaded old extension | CONFIRMED | `omp-extension.ts:422-446` | RS-7: types kept, fields added; old-extension proof case |
| 11 | `omp_watch::open` has its own package gate | CONFIRMED | `omp_watch.rs:92-100` | RS-12: every gate enumerated |
| 12 | `open_read_only` falls back to a writable open before the identity check | CONFIRMED | `store.rs:601-623`; `store.rs:535-541` | RS-14 (r3): no fallback; inspection on a copy; the original is never written before the pair is proved |
| 13 | Reset recreates the lock-free interval; no orphan handling | CONFIRMED | `daemon.rs:180-208` | RS-15 (r3): lease outside the data root obeyed by waiting daemons (r4: in the control directory); orphan scan before any stop; journal |
| 14 | A clean external SIGTERM leaves a managed daemon stopped until a client | CONFIRMED | `us.vox.daemon.plist:18-22`; `daemon.rs:719-765` | RS-5 (r3): every signal is foreign → exit 71; product stops are requests |
| 15 | The `lifetime` lock proves no watcher, not no OMP | CONFIRMED | `omp_fence.rs:211-245`; `omp_watch.rs:320`; `omp-extension.ts:450-499` | RS-8: lock free *and* wake endpoint refusing, twice |
| 16 | `proc_pidpath` gives the executable, not argv | CONFIRMED | Apple's `proc_pidpath` returns the path only | RS-6: `KERN_PROCARGS2`, with the executable-only fallback |
| 17 | C4's exclusions and the unique-hook attribution are stated as KNOWN | PARTLY | `restart.rs:516-527` has a crash window; the PATH-helper shape identifies a class of clients | C4: sender UNKNOWN; product path and hook attribution INFERRED |
| 18 | RS-16's red and mutant were 0.4.28's, and the login-item stand-in registers nothing | CONFIRMED | `bundle.rs:3989-3994`; `Daemon.swift:18-24,48-58` | RS-16; RS-5's proof uses a real launchd job |
| 19 | RS-13's mutant stays green because the watchdog stops the old daemon first | CONFIRMED | the journey moved the root before the purge | RS-13: node-directory-only journey with the root inode unchanged |
| 20 | "Locked since the computer started" is not what an empty keyring proves | CONFIRMED | `persistent-keyring(7)` | RS-3: the kernel's answer is quoted; no reboot claim |

### Second review (`adr-041-sol-review-2.md`)

| # | Finding | Class | Evidence | Answered by |
|---|---|---|---|---|
| N1 | A restarter killed after the stop and before the start leaves the root unserved; the lease's release starts nothing | CONFIRMED | `restart.rs:516-527`; `systemd.service(5)` `Restart=` excludes a manager stop; `SuccessfulExit: false` does not relaunch exit 0 | RS-2 (r3): managed roots are one manager request (`kickstart -k`, `systemctl restart`) that the manager finishes; unmanaged roots start the replacement first and it does the stop; the kill-point table; the one ownerless window (the replacement itself dying on an unmanaged root) is stated and is Q5 |
| N2 | `.daemon/manager` is written by the manager's daemon when it takes the lock; on the operator's Mac that daemon was waiting or not loaded, so the file could never exist | CONFIRMED | `daemon.rs:180-208`; `how_started` identifies a running pid only; `cleanup/daemons-detail.txt` | RS-5 (r3): enrollment outside the data root (r4: `<control dir>/manager`), written by the app at registration and by `vox agent setup --service`; "enrollment broken" state; the item-81 sequence step by step |
| N3 | A lease probe is not exclusion for a later spawn; two restarters act on stale observations; `stop_captured_daemon` carries no guard across `publish` | CONFIRMED | `daemon_client.rs:96-137,186` separates probe and spawn; `restart.rs:360-384` observes before the signal; `bundle.rs:1145` | RS-2 (r3): exclusion is held by processes (lease, lock), never by a probe: a daemon that starts under another's lease does not take the lock; the replacement revalidates pid and incarnation under the lease; a second restarter is told "already in progress"; the bundle's restart step runs after `publish` from one process; proof (a) pauses a client after its probe, (b) runs two restarters |
| N4 | Reset: a waiting daemon takes the lock between stop and reset's lock; after the rename the lease and manager record are in the moved tree; killed after the rename, the root is not "in place" | CONFIRMED | `daemon.rs:180-208,407-415` | RS-15 (r3): lease and enrollment outside the data root (r4: the control directory), obeyed by `take_account`; journal with phases and `vox status` lines for each kill point; orphan scan before any stop |
| N5 | A foreign store that needs repair is repaired (written) before its identity is compared | CONFIRMED | `vendor/redb/src/db.rs:1462-1508,1658-1672`; `store.rs:535-541` | RS-14 (r3): inspection on a copy; the original is written only after the pair is proved; free-space refusal; `sha256` assertions |
| N6 | `Builder::open_read_only` takes a path, not a `File`; `create_file` returns a writable `Database` | CONFIRMED | `vendor/redb/src/db.rs:2223-2252`; `ReadOnlyDatabase::new` private | RS-13 (r3): a vendored `open_read_only_file(File)` is in scope |
| N7 | A pin on the active branch is lost when an earlier leaf is selected; the rebuilt node then adopts | CONFIRMED | OMP `session-manager.ts:3940` `getBranch` walks ancestry; `:4031` `getEntries` returns every entry; `omp-extension.ts:1084-1089` follows tree selection | RS-9 (r3): the newest `vox-identity` entry among `getEntries()`; order of effects; rebind as a newer entry; proof cases (d), (e) |
| N8 | `ended_ms` set, daemon killed before the room end → phantom for ever; `bye` after `SessionEnd` not retried | CONFIRMED | `sessions.rs:311-331` returns early for an ended row; `:340-374` | RS-8 (r3): `ended_ms` is intent, `end_posted` is completion; retry against room history by opening hash until both are in; proof case (e) |
| N9 | `version_table` keys by author and drops the author on a `bye`: one Session's `bye` retires its node's live sibling | CONFIRMED | `version.rs:211-234`; `work_board.rs:680+` | RS-11 (r3): latest record per `(author, from)`; a `bye` ends its pair only; participants listed per pair; mutant |
| N10 | "restarting" ends at hello, but nodes attach after it; the watcher has no word for attaching or rewriting | CONFIRMED | `daemon.rs:474+`; `restart.rs:605-652` waits for nodes after hello | RS-2 (r3): the lease is held until kept nodes are terminal; the hello carries per-node states; RS-7 (r3): `starting`, `attaching`, `rewriting`; mutant |
| N11 | RS-4 promised "remembered from then on" on hosts whose keyring is refused | CONFIRMED | RS-1's own refusal path; E1 | RS-4 (r3): the text says what the next unlock tries and what a refusal costs; the macOS unreadable-Keychain case; release notes |
| N12 | Refresh every 12 h ignores a configured expiry shorter than that; a key lost while live is not noticed | CONFIRMED | `persistent-keyring(7)`: expiry from the last `GET_PERSISTENT` | RS-1 (r3): refresh every `min(expiry/4, 12 h)`; too-short expiry refuses to promise; post-refresh search; "no longer remembered" |
| N13 | Q2(a) "deleted at v0.4.32" ends a surviving 0.4.30 claim one release later | CONFIRMED | `claim.rs:375-385` consults the stamp of every historical op | RS-10 (r3): the reading stays until the first room transition, never removed by package milestone |
| N14 | RS-3's proof clears the keyring under a live Ready daemon; `vox daemon --detach` finds it and hands off, so the product rightly shows Ready | CONFIRMED | `daemon.rs` already-running path; `host.rs:4550-4597` | RS-3 (r3): kill and reap the daemon first; a separate clear-while-live case |

Further points in the second review, all accepted: the outage bounds (STOP 30 s, START 15 s,
REATTACH 30 s) are now named with their clocks in RS-2; podman's default errno is ENOSYS, not
EPERM, and RS-1 quotes the kernel's text; the kernel-keyring retention is described in the manual
as an expansion over today's typed unlock (RS-1); the launchd `si_pid` assumption is gone (RS-5
decides from "signal or request", not from the sender); E1's receipt directory was recreated
under `/tmp/adr041/` with the two profiles and their hashes (receipt lost in the reboot of
2026-11-13; figures recorded in `adr-041-revision.md`, revisions 2 and 3; to be re-run
as the fleet baseline); the vault has no
authenticated creation date (RS-14's text drops it); `Positive` consequences are rewritten to the
narrower promises; ledger row 15 is resolved in RS-12 (one protocol bump for the release).

### Third review (`adr-041-sol-review-3.md`)

| # | Finding | Class | Evidence | Answered by |
|---|---|---|---|---|
| R3-1 | On a default Mac the config dir *is* the data root, so revision 3's "config dir" authority (lease, enrollment, journal) moved with the reset | CONFIRMED | `paths.rs:837-858`: `default_data_root` and `default_config_root` both give `~/Library/Application Support/vox` on macOS | Terms (r4): the control directory `<data root>.control`, a sibling never moved; RS-5 enrollment, RS-9 rebind, RS-15 lease and journal live there; RS-15's proof runs the default layout in the guest, with a mutant that puts the journal back in the config dir |
| R3-2 | The restarter held the lease its own replacement had to take; a daemon under another's lease "proceeds to the lock" in RS-2 but "must not" in RS-15 and D-1 | CONFIRMED | revision 3 lines 506-509 vs 1172-1174; `daemon.rs:95-101` closes inherited descriptors, so nothing is delegated by inheritance | Terms (r4): one rule, "take the lease immediately before trying the lock; never try the lock without it"; the restarter never holds it; a daemon that finds it held never tries the lock; RS-2's four arms and the amended D-1 say the same sentence |
| R3-3 | On an enrolled root served by a detached daemon, the product stop came before any manager-owned successor existed; the restarter's death in between left the root down | CONFIRMED | ledger row 21: the Mac's job is enabled and not running while a hook-started daemon serves; revision 3 RS-5's item-81 sequence | RS-2 (r4) "managed root, detached daemon serving": `kickstart` first, wait for the job's pid (the 0.4.31 login-item daemon waiting on the lock), stop only then; its kill-table column; RS-5 proof (c), (c'); r5: the takeover makes the manager's daemon the owner, no restarter stop |
| R3-4 | Enrollment was written by the app at launch, but the bundle handoff restarts the daemon before relaunching the app, and relaunches nothing if the app was not running | CONFIRMED | `bundle.rs:4203-4230` `transition_handoff`: `restart_for_handoff` before `relaunch_app`; `:4218` | RS-5 (r4): the update engine and `vox daemon --restart` write the enrollment from `login-item: keep` + `launchctl print` before choosing the restart owner; the app's enrollment at launch is a second writer; RS-2's bundle order lists it as step (1) |
| R3-5 | A protocol-11 daemon cannot receive `Stop { reason }`: its decoder accepts the one-element `Stop` only, and a protocol-12 client refuses the connection; RS-12's proof promised an answered turn in the 11→12 window | CONFIRMED | `daemonipc.rs:1695` `(T_REQ_STOP, 1)`; `daemonipc.rs:2270-2282`; `host.rs:5823` | RS-2 (r4) cutover arm: SIGTERM to the hello's pid, identity by kernel start time, for protocol 11 only, deleted at v0.4.32; managed 0.4.30 daemons by `kickstart -k`/`systemctl restart`; RS-12's proof split into the same-protocol journey and the 11→12 journey, which asserts the refusal naming both numbers |
| R3-6 | `pi.appendEntry` returns void and never throws; a write failure is latched; a new session may have no file yet; "if the append fails" was not observable | CONFIRMED | OMP `session-manager.ts:1954-1988` (latched, non-throwing append), `:1662-1664` (deferred file), `:2788-2793` (`ensureOnDisk` forces the file and rewrites), `:1795-1810,1355-1372` (`#rewriteAtomically` awaits `#scheduleDiskWork`, which rejects with the latched failure); `ensureOnDisk` and `getSessionFile` are on `ReadonlySessionManager` (`:765-790`) | RS-9 (r4): registration `pending` until `ensureOnDisk` resolves and the extension reads the entry back from the session file; no prepare or drain before `--bound`; unpersisted sessions fail closed; proof cases (f), (g) |
| R3-7 | The expiry case set a stand-in of 120 s under a rule that refuses to remember below 10 minutes, and a Vox variable is not the kernel's timer | CONFIRMED | RS-1's own rule; `persistent-keyring(7)` | RS-1 (r4) proof: the sysctl itself, set by the apparatus as root in the Linux VM: (c) 60 s proves the refusal, (d) 660 s with the daemon dead proves the real expiry (optional, eleven minutes) |

Further points in the third review, all accepted: `launchctl kickstart -k`'s SIGTERM-then-SIGKILL
sequence is [INFERENCE] and owed to the guest journey (RS-2, RS-5(e)); the unmanaged ownerless
window is described through useful node service, not only before hello (RS-2's table, Q5); a
waiting manager daemon is not refused by reset's orphan scan, since it holds no file open (RS-15
step 2); the reset journal brackets the rename with `moving`/`moved` and the reader reconciles the
filesystem (RS-15); Q1 no longer suggests that "one unlock per boot" opts out of RS-1's cache;
Q5(b) requires both an enrolled manager and a usable remembered store. Ledger rows applied in this
revision: 21 (the Mac's and beast's facts, in C4, RS-5 and the Negative consequences), 18 (the
cutover arm is for one update of every machine together; no mixed-version support is designed),
22–27 (nothing of this ADR's prints "locked" as a fact about another computer's node: RS-3's
Locked line is the local daemon's own node; no repair facility is referenced), 32 (every proof
here runs in the macOS guest or the Linux VM; the host runs nothing), 15 (RS-12, with ADR-050's
note: no request of its own).

### Fourth review (`adr-041-sol-review-4.md`)

| # | Finding | Class | Evidence | Answered by |
|---|---|---|---|---|
| F4-1 | On a managed root the lease is free between the old daemon's exit and the new one's lease, and a client's daemon that probed earlier could take lease and lock there; a manager's waiter releasing the lease per attempt loses the same way; RS-7 read only the lease | CONFIRMED | Terms (r4) release the lease at terminal nodes and after each failed attempt; `daemon_client.rs:167-218` separates the probe from the spawn; no holder exists across a manager's stop | RS-2 (r5): admission under the lease re-reads the enrollment and yields to a known job (asks it, exits), so nothing but the manager's daemon serves a managed root; the manager's daemon takes over an `--as-detached`/`unsupervised` holder itself, holding the lease from before the stop until terminal; `<control dir>/planned` (60 s) gives RS-7 and the mirror the planned-stop state across the manager's interval; `vox factory-reset` holds the lease throughout; RS-5 proof (e), (e') pause a client in both managed arms |
| F4-2 | Recovery of `moving` by which paths exist: a cold-starting client can recreate the original path after the rename, and "both present" was read as "not moved"; the pre-rename state was undescribed | CONFIRMED | `daemon_client.rs:179-186` creates `.daemon` by path before spawning | RS-15 (r5): the journal records the root's `(dev, inode)` and the captured daemon's pid and start time; recovery compares identities, not names: `<to>` carries the identity → moved whatever `<root>` is; `<root>` carries it and `<to>` is absent → not moved; anything else → refuse to decide, no daemon serves; `create_private_dir` moves into the daemon after the lease (RS-2); proof (d) at `moving-renamed` with the v0.4.30 asset's client creating the path, and (d') the ambiguous state |
| F4-3 | Rebind appended the new entry and removed the authorization without the acknowledgment the first binding requires; a volatile append plus OMP's death lost the approved operation | CONFIRMED | OMP `session-manager.ts:1954-1988` (latched append), `:2788-2793` | RS-9 (r5): rebind runs the same pending → append → `ensureOnDisk` → readback → `--bound` transaction; the authorization is removed only on the acknowledgment for the authorized fingerprint; proof (g'), (g''); mutant |
| F4-4 | The lease mutant asked for "two serving daemons", which the exclusive lock makes impossible | CONFIRMED | `daemon.rs:407-415` `try_lock` is exclusive | RS-2 (r5) proof: the verdict is who serves: the stale client's daemon takes the lock, the `--take-over` replacement reports "the daemon changed before it could be replaced", exit 1, and `vox status` names the client's pid; RS-5 (r5) mutant likewise on "the login item did not become the daemon" |

Proof-oracle corrections in the fourth review, applied: RS-9 (f) stages real `ENOSPC` (a full
small file system in the VM), not a read-only parent directory; (g) distinguishes a first attempt
that never bound (correct outcome: pending, then bound to the rebuilt identity) from a confirmed
binding with a rebind in flight (g'), and the volatile append is made so by the apparatus, not
assumed. The decider's answers of 2026-11-13 (rows 43–47) are applied in RS-3, RS-5, RS-10,
RS-15 and the first section; ledger rows 36 (ADR-050 r2's acts in RS-7's journey) and 32 (VMs)
are restated where they apply.

### Fifth review (`adr-041-sol-review-5.md`)

| # | Finding | Class | Evidence | Answered by |
|---|---|---|---|---|
| F5-1 | The takeover classified the lock holder by a hello field ("started `--as-detached`") that a protocol-11 hello never carried, so the cutover from v0.4.30 could not select its SIGTERM arm; item 81 claimed the old hello supplied it | CONFIRMED | `daemonipc.rs:892-904`: `Hello { protocol, version, pid, attached }` and nothing else at v0.4.30 | RS-2 (r6) takeover: classification by what the holder's protocol gives; for protocol 11, by the pid pinned by kernel start time, from the process's arguments (`how_started`/`arguments`, `restart.rs:770-794`) and the enrolled job's own record; missing arguments are treated as a terminal's, never as detached; revalidation before SIGTERM; re-observation of the holder in the lock wait; item 81 corrected; cutover proof (d) covers an old detached owner (transferred) and an old foreground owner (waited for, never stopped) |
| F5-2 | The unmanaged lease mutant expected the pre-stop "daemon changed" error, but a stale daemon can win the lock only after the old owner exits, past that check; `Handed::TakeOver` only polls the lock | CONFIRMED | `daemon.rs:211-241` polls `take()` and signals, re-observes nothing | RS-2 (r6): the replacement re-observes the holder on every lock attempt and reports `the daemon was replaced by pid N (started by …) before this restart could serve; it keeps serving`, exit 1; the mutant's verdict is that line plus the pid `vox status` names, with the client resumed after the old exit, and unmet staging is APPARATUS; the kill-table cell matches |

### Task-readiness review (`v0431-tasks-ADR-041-sol-review.md`, revision 7)

Gaps in this ADR's own proof specifications, found when it was cut into tasks; none changes a
design decision or a decider's answer.

| # | Gap | Class | Evidence | Answered by |
|---|---|---|---|---|
| T1 | RS-2 proof (d1) asked the restart's reply to report Ready "after" RS-4's later unlock | CONFIRMED | RS-4: a passphrase typed to a v0.4.30 daemon is lost at its stop (`client.rs:866-873`: no keep source off macOS for typed input) | RS-2 (r7) proof (d1-remembered) with a source the candidate reads, and (d1-typed) asserting Locked in the reply, then Ready after the one unlock |
| T2 | No proof act for the rewriting line (RS-2 item 5, RS-7) and no row for ADR-047 SO-10 | CONFIRMED | revision 6 named the line in RS-2 and RS-7 and no act | RS-7 (r7) rewriting act: SO-10's staging, `VOX_TEST_REWRITE_HOLD_MS`, the restart's reply before the hold ends, a prompt during it, APPARATUS cases, blocking; the exact SO-10 row under "Changes this revision asks of siblings" |
| T3 | Acts the tasks had to invent: the bundle order and interrupted handoff; unreadable arguments for (d2); the Locked restart line; `unsupervised` on an unmanaged root; a v0.4.30 claim kept; mutants for (d1)/(d2) | CONFIRMED | revision 6's proofs | ratified with corrections: RS-2 (r7) (e), (f-a)–(f-d) with mutants in `update_proof.rs:938`; (d2-unreadable) with `VOX_TEST_ARGS_UNREADABLE=<pid>` and its confirmation line; (d1) mutant "treat protocol 11 as 12"; RS-5 (r7) (f); RS-10 (r7) the Q2 act and its mutant |
| T4 | RS-5's real-manager journey named no proof file | CONFIRMED | revision 6 RS-5 | RS-5 (r7): `the_daemon_and_its_nodes_proof.rs`, RS-2's file; the manager staging is apparatus there; no new file |
| T5 | The implementation order omitted RS-15 and put RS-5 before RS-7, whose reconnected line RS-5's proof asserts; RS-4 sat with RS-1 although its restart is RS-2's cutover arm | CONFIRMED | revision 6's order | the order (r7): RS-7 at 5, RS-5 with RS-4 at 6, RS-15 at 7 |
| T6 | RS-1's sysctl cases need root in the Linux VM; AGENTS.md forbids `sudo` | CONFIRMED | AGENTS.md "Never use `sudo`" | RS-1 (r7): root in the VM's own namespace by `podman machine ssh`, as ADR-044 RD-12's kernel arm; the proof refuses to run outside the VM |

Task-readiness points not this ADR's to close (recorded for the task writer): exact source
excerpts must keep their bytes (template rule 7); V431-041-05's mutant ownership; V431-041-15's
dependency on the sender capture (RS-6 precedes RS-5 in the order above).

### Cross-ADR asks and the correction batch (`adr-cross-asks.md`, `adr-correction-batches.md`, revision 8)

Target ADR-041 rows whose disposition was not STALE, and the rows where ADR-041 is a side.

| id | ask | class | done, where |
|---|---|---|---|
| X040-1 | `SessionRegister` gains `state` and `observed_ms`: counted in the bump | CONFIRMED | RS-12 (r8): named in the list |
| X040-2 | the typed attention answer and `Fault::NotYet` in the bump | CONFIRMED | RS-12 (r8): `Fault::NotYet` named |
| X049-9 | `Frame::Left` inside RS-12's one bump | CONFIRMED | RS-12 (r8): named, and "the list is not exhaustive" |
| X050-3 | the shim's logs (staged with marker, provider payloads, accepted), restart on the same store, switch events, error stops, zero/one/two requests | CONFIRMED | RS-7 (r8): ADR-050 r6's eight duties hosted verbatim in substance |
| X050-4 | RS-7 hosts "TJ-10's acts", not "acts 1–5" | CONFIRMED | RS-7 (r8): "TJ-10's acts 1–10 as ADR-050 states them"; sibling bullet likewise; the contradiction row "Acts in RS-7's file" is closed on ADR-050's side |
| X041-13 | root for RS-1's sysctl cases | answered | the decider, ledger row 69: inside the Linux test VM only, never on his machines; RS-1 (r8) says so; the proof refuses to run elsewhere |
| X041-19 | a fleet act for `vox factory-reset` | answered | Main: ADR-045 J8 runs it where it rebuilt the profile by hand; RS-15 (r8) says so and keeps its refusal and confirmation arms in tree |
| L3-64-041 | lost-receipt note | CONFIRMED | Context (one note for all, after the status words), C8, C9, the second-review record |
| X042-22 | ADR-042 TR-25 "needs its passphrase again until ADR-041 lands" | ASKER DROPS, confirmed here | siblings bullet "ADR-042 TR-19": RS-1/RS-3 own restart and reboot behaviour; ADR-042 deletes the clause |
| X041-8 (side: ADR-040) | the `NotYet` display rule while the watcher reports `starting` | BOTH ALIGN | siblings bullet "ADR-040 r3 / ADR-050": the rule is the extension's, RS-7 owns it; ADR-040 replaces "No text change" with the one clause |
| X041-14, X041-15, X041-16 (side: ADR-042) | who prints the Locked, `unsupervised`, waiting and factory-reset lines | CONFIRMED | siblings bullet "ADR-042 TR-19 (who prints what)": ADR-041 owns the words, ADR-042 the layout; printed in ADR-041's words until the layout rows exist |
| contradiction "Linux restart cost" (ADR-042 TR-25, ADR-043 related work vs RS-1/RS-3) | — | ADR-041 wins | no change here; ADR-042 and ADR-043 reword |
| contradiction "Ledger row 15" | hook surface, not IPC | — | RS-12 unchanged on this; the ledger row is stale |
| unresolved reference ADR-050:1044-1046 → ADR-041 `:789-790`, `:796`, `:1399-1402` | dead line numbers | — | ADR-050 r6 moved those rows to its sibling contracts; nothing to change here |
| amendment quotes (`adr-amendment-quotes.md`) | 17 rows | all FOUND | no change |
| privacy (public repository) | real addresses, ports, home paths | checked | none outside sample output (`/Users/robert/…` appears only in sample output; no LAN address or port) |

The SO-10 row for ADR-047 (r7) stands as written under "Changes this revision asks of siblings".

### Revision 9 (`adr-041-pending-r9.md`, after ADR-050 r11 passed its review)

| # | change | class | where |
|---|---|---|---|
| r9-1 | "TJ-10's acts 1–10" named a count that ADR-050 r8–r11 changed (acts 6 and 11 moved to `agent_hook_proof.rs`; 8f′, 8f″ and 12 added) | CONFIRMED | RS-7 Proof and the siblings bullet "ADR-040 r3 / ADR-050" now say "the acts TJ-10 places in this file, as ADR-050 states them", with ADR-050 r11's placement (acts 1, 2, 3, 4, 5, 7, 8 (8a–8f, 8f′, 8f″), 9, 9b, 10, 12 here; 6 and 11 in `agent_hook_proof.rs`; each id checked in the frozen `ADR-050.ba79a3e3f.md`) and its eight shim duties, duty 3 from ADR-050's corrected paste (three retry boundaries: HTTP retry below one payload callback, Vox unaffected; provider-attempt retry repeating `onPayload`, a second build, uncertain; OMP step replay after an error `message_end`, Vox ends first), the fetch stub for 8f″ to be written, and the "no longer needed" list |
| r9-2 | implementation-order step 3 listed the cutover arm and the bundle's new order, which need step 6's enrollment and takeover | CONFIRMED | moved to step 6 |

### Why not replace in place, once made sound

What a restart must preserve is (1) the node secrets, (2) one daemon per root with no window for a
client to start another, (3) the manager's ownership, and (4) conversations' quiet reconnection.
With the secret in a store outside the process, (1) needs nothing from the old process on any
platform except a host that refuses the keyring, where exec would still not cover a crash or a
reboot. (2) is a lease held by the process bringing the daemon up. (3) is the manager doing the
restart, which is what it exists for. (4) is the watcher reading the lease and the hello. In-place
exec gives (2) and (3) inherently and (1) for the refused-keyring case, at the cost the first
review enumerated: a second startup path that adopts a lock, a control listener and a UDP socket
instead of binding them; a framed hand-over bounded by pipe capacity or a memory file; an abort
that re-attaches every node when `execve` returns; new journal phases and recovery predicates in
the bundle transaction; and whether Security.framework grants a re-exec'd image the Keychain
items its predecessor made, which nobody has measured and which the quiet Keychain code
(`keychain.rs:31-44`) would turn into a silent failure. Neither design keeps the old daemon serving
when the new program fails after it started; both rely on the manager's retry and the update's
rollback. The service-manager design has fewer moving parts and no unverified platform dependency,
and the update from 0.4.30 looks the same under both (a stop and a start by the 0.4.31 engine,
RS-4). Socket activation (launchd `Sockets`, `sd_listen_fds`, systemd `FDSTORE=1`) was considered
for (2): it would keep the control socket bound across a managed restart, but it needs a second
mechanism per platform, cannot cover unmanaged installs, and the lease already closes the window
for both.

## Unchanged rulings

- **No agent changes the Vox version or restarts a daemon on the operator's machines without his
  explicit go.** AGENTS.md (the decider, 2026-11-12, after an agent rolled two machines back during
  his work day): "Never change the Vox version on any of the operator's machines without his
  explicit go for that specific action. No `vox update`, no `vox update --rollback`, no reinstall,
  on this Mac or on any host he owns (beast, vince's, .203, .46). … The same goes for restarting his
  daemon: say first what it will cost (a Linux node needs its passphrase again), then wait for his
  word." Nothing here changes it, and approving this ADR authorizes no reset, restart or update
  of his machines. The settling experiments in this ADR that touch his machines (C4's
  `launchctl print`, C9's quit probe, beast's `systemctl --version` and `systemctl --user status`)
  run only with his go.
- At most one daemon per data root (ADR-026 D-1). RS-2, RS-5 and RS-13 enforce it; they do not
  change it.
- Vox never writes a passphrase file on its own, and remembers a file only by the path the person
  named (ADR-038 FX-34). The kernel keyring is memory, not a file; a refused keyring is never
  replaced by a file Vox chose.
- A hook never attaches a node and never takes a passphrase (ADR-028 K-13).
- Peers of different versions are never refused for their version (ADR-034 UP-2, the decider,
  2026-10-10).
- No prior-release compatibility is owed in v0.4.x (ADR-026 F-3; AGENTS.md). RS-4 applies it;
  the decider's Q2 (keep v0.4.30's claims) is his one exception, by choice, not by this rule.
- A daemon that refuses to die is what `kill` is for: no daemon restarts itself (RS-5 lets the
  manager do it, by the daemon's exit status), and a daemon asked to stop by product request
  always stops (the manager's takeover depends on it).
- Every claim is proved by real use of the shipped binary, with a mutant (ADR-018).

## Superseded and amended lines

Narrow amendments. Lines are in `docs/adr/` at d9a8667ba. Requirements not named here stay in
force. Main applies these after the decider signs.

| # | ADR and rule | Current text (file:line) | Replacement text |
|---|---|---|---|
| 1 | ADR-038 FX-34 | "Where there is no such store, Linux today, `vox node unlock` MUST NOT persist the passphrase anywhere and MUST say that a daemon restart will ask again; a node Locked after a restart is unlocked again by hand, which the decider accepts ("that's ok as long as I can actually unlock them", 2026-10-21), so no Linux credential store is built for now." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:711-715`) | "On Linux, `vox node unlock` MUST store the passphrase in the kernel's per-user persistent keyring, never on disk, so a restart, an update or a crash needs nothing typed while the key is kept (ADR-041 RS-1); after the computer restarts the node returns as ADR-041 RS-3 says. Where the kernel refuses the keyring, `vox node unlock` MUST say the node is not remembered, name the refused call and the kernel's answer, and say that a restart asks again unless the person names a passphrase file." |
| 2 | ADR-028 K-10 | "Where there is no Keychain Vox can use (Linux), Vox MUST say plainly that the node is not remembered and how to keep it (`--keep --passphrase-file`)." (`ADR-028-one-experience-keyring-rooms-services-files.md:114-115`) | "On Linux the kernel's per-user persistent keyring is the store (ADR-041 RS-1); after a reboot a node is Ready only from a credential or a passphrase file, and otherwise says its remembered passphrase is gone and how to unlock it once (ADR-041 RS-3)." |
| 3 | ADR-031 CW-3 | "After a daemon restart, an update or a reboot, every remembered node MUST come back Ready by itself, the person's node included, whatever any "keep running" setting says." (`ADR-031-agent-nodes-join-a-repo-room-by-themselves.md:183-184`) | Append: "A node is remembered only where its store can hold it (ADR-041 RS-1); on Linux, after a reboot, a node comes back Ready by itself only as ADR-041 RS-3 says." |
| 4 | ADR-026 D-1 | "A daemon MUST hold an exclusive lock on `<data root>/.daemon/lock` for its whole life" (`ADR-026-daemon-and-nodes.md:31-32`) | "A daemon MUST hold an exclusive lock on `<data root>/.daemon/lock`, opened through the data root's directory, for its whole life; it MUST write only into the directories it opened, and MUST stop when it sees its data root replaced or removed (ADR-041 RS-13). No process tries that lock without holding `<data root>.control/restart`, taken immediately before the attempt; a daemon keeps it until its remembered nodes are terminal, a waiting daemon releases it after each failed attempt, and a process that finds it held by another never tries the lock (ADR-041 Terms, RS-2, RS-15)" |
| 5 | ADR-026 S-1 | "SIGHUP, SIGTERM, SIGINT and SIGQUIT MUST each detach every node cleanly and then stop the daemon." (`ADR-026-daemon-and-nodes.md:205-206`) | Append: "The stop line MUST name the signal's sender as far as it can be read (ADR-041 RS-6). A product stop is a `Stop { reason }` request, never a signal; a `--login-item` daemon stopped by any signal exits 71 after its clean stop so that launchd starts it again, and a unit's daemon likewise (`RestartForceExitStatus=71`); every other daemon keeps exit 0 (V210-93; ADR-041 RS-5)." |
| 6 | ADR-026 S-2 | "A client that may attach a node (L-2: a session-holding verb, the TUI, `vox node attach`), or an agent's hook, that finds no daemon MUST start `vox daemon --detach`" (`ADR-026-daemon-and-nodes.md:207-209`) | "… that finds no daemon MUST wait while `<data root>.control/restart` is held, then start the daemon through the manager enrolled for the data root, and otherwise MUST start `vox daemon --detach`, which itself takes the lease before the lock or exits if another holds it (ADR-041 RS-2, RS-5)" |
| 7 | ADR-026 L-5 | "*Deferred (additive):* a sweep that unregisters the sessions of a harness that died without ending them. Until it exists, such a session MUST keep holding its node." (`ADR-026-daemon-and-nodes.md:124-125`) | "An OMP registration whose process is gone is ended, once, and removed (ADR-041 RS-8). A harness without a fence instance keeps holding its node until it ends its session." |
| 8 | ADR-026 F-1 | "It MUST be shown only while that hash matches the vault there, and is for display only: nothing MAY decide trust, an attach or anything else from it." (`ADR-026-daemon-and-nodes.md:256-257`) | "It MUST be shown only while that hash matches the vault there. Nothing MAY grant trust or an attach from it; it MAY be used to refuse to open a store of another identity before the passphrase is asked, with the decrypted vault the final word (ADR-041 RS-14)." |
| 9 | ADR-014 M-9 | "The login item's daemon, finding another daemon serving the data root, MUST wait and serve once that one stops: launchd restarts it only after a crash." (`ADR-014-macos-client.md:86-87`) | Replace: "With Keep Running on, the app, the updater and `vox daemon --restart` enroll the login item for the data root (`<data root>.control/manager`). The login item's daemon, finding the data root served by a daemon a client started (`--as-detached`, or one serving `unsupervised` after launchd refused), MUST take the root over: holding the restart lease, it asks that daemon to stop by product request and serves once it has; finding it served by a daemon a person runs in a terminal, or by another login-item daemon still stopping, it MUST wait and serve once that one stops (ADR-041 RS-2, RS-5). No client starts a daemon of its own while the login item is enrolled and launchd can run it; when launchd refuses, the client's daemon serves `unsupervised` until the login item's takes over (the decider, 2026-11-13, Q4). launchd restarts the login item after any signal stop (RS-5). A waiting login-item daemon takes the restart lease for each lock attempt and binds to the data root it finds when it takes the lock (ADR-041 RS-13, RS-15)." |
| 10 | ADR-034 UP-1 | "`vox update` and the app's update MUST stop the running daemon and start the new version's daemon as part of the update" (`ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md:55-56`) | "`vox update` and the app's update MUST bring up the new version's daemon as part of the update, after the new bundle is published, under the restart lease and through the daemon's manager where it has one (ADR-041 RS-2)" |
| 11 | ADR-034 UP-2 | "A client of a daemon (the app, the TUI, every verb and every hook) MUST refuse its own daemon when their versions differ, and MUST NOT attempt any other request on that connection." (`ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md:58-59`), and "Measuring when two versions are compatible, between a client and its daemon and between peers, is planned for v0.4.5 and is not part of this ADR." (`:65-66`) | "A client … MUST refuse its own daemon when their control-protocol numbers differ, and MUST NOT attempt any other request on that connection (ADR-041 RS-12)." The second sentence is deleted. |
| 12 | ADR-021 5.1 | "Comparison is exact string equality; a stamp that is not a valid semantic version is unknown." (`ADR-021-work-item-interop.md:160-161`) | "Every claim-protocol operation and work `hello` MUST also carry `data.coord`, the claim-protocol level; comparison is equality on that level; `data.vox` is shown, never compared (ADR-041 RS-10)." |
| 13 | ADR-021 5.2 | "The fold MUST apply only operations stamped with the folding worker's own version; others change nothing and are reported. An upgrade therefore ends every claim made under the previous version." (`ADR-021-work-item-interop.md:162-164`) | "The fold MUST apply only operations at the folding worker's own claim-protocol level; others change nothing and are reported. An update that keeps the level keeps every claim; a release that raises it ships the room's transition (ADR-041 RS-10)." |
| 14 | ADR-021 5.4 | "The drain hook and idle clients do not announce. Updating a daemon or harness integration alone does not rewrite room participation." (`ADR-021-work-item-interop.md:179-180`) | "The daemon announces each Session it opens or reopens with a work `hello` at the level its node runs now, and ends it with a `bye` for that Session alone (ADR-041 RS-11); a hook never announces; a `hello` from a verb is posted only with no Session." |
| 15 | ADR-021 5.5 | "When any participant's version is mismatched, missing or unknown:" (`ADR-021-work-item-interop.md:181`) | "When any participant's claim-protocol level differs from this worker's, or is missing or malformed:" |
| 16 | ADR-021 5.6 | "These diagnostics and the refresh in §5.4 MUST NOT weaken the exact-version gate or the version-filtered claim fold." (`ADR-021-work-item-interop.md:188-189`) | "These diagnostics MUST NOT weaken the level gate or the level-filtered claim fold; the refusal names the level the other worker speaks and this worker's own (ADR-041 RS-10)." |
| 17 | ADR-029 SE-4 | "A Session MUST end only on the harness's real end: the hook's `SessionEnd`, which unregisters the session (ADR-020 6.10)." (`ADR-029-sessions-and-the-repo-room.md:65-66`) | Append: "For OMP, the end of its process, found as ADR-041 RS-8 says (its watcher's lifetime lock free and its wake endpoint refusing, twice), is also the harness's real end; the end is posted once, however many times the daemon restarts." |

## Changes this revision asks of siblings

Not edited here; listed for the ledger (`adr-cross-changes.md`) by target and requirement.

- **ADR-045 J7(c):** candidate-to-candidate restarts on B prove RS-1 only on a profile that
  permits `add_key`/`keyctl` (positive case), with a separate default-profile case asserting the
  refusal line and its errno (ENOSYS under podman's current default); a passphrase file on B
  proves the file source, not RS-1, and must not be reported as RS-1's green. The update from
  0.4.30 on B is staged apart, with RS-4's warned unlock.
- **ADR-045 J7(d):** the silence assertion carries RS-4's exception: an extension loaded before
  the update may print its old advice once at that one restart.
- **ADR-045 J7(f):** "dead registrations gone ≤ 60 s" becomes "ended and listed as ended by a
  peer within 150 s (two checks 60 s apart) with exactly one `OMP ended` and one `bye` in room
  history; files removed 24 h after the end (the clock-knob proof)".
- **ADR-045 J7(g):** already qualified; with Q2's recommendation (keep 0.4.30 claims as level 1,
  retained until the first room transition) the first reading applies.
- **ADR-045 J7(j):** add the clean external `kill -TERM` with no client request, back ≤ 15 s under
  the login item with a remote read as the verdict (RS-5), beside the `kill -9` case; add the
  operator's shape (detached daemon serving, job registered and not running), the restarter
  killed after the stop, and the restarter killed after `kickstart` and before the stop.
- **ADR-047 SO-10 (r7, the exact row ADR-047 is to carry):** "A rewrite that runs at daemon
  start precedes the node's Ready. The daemon's hello reports that node in state `Rewriting`
  (ADR-041 RS-2's per-node states) from the moment the rewrite is chosen until it ends; `vox
  daemon --restart` and `vox update`, finding a kept node `Rewriting`, print `<node> is
  rewriting its store (<file length>); it is Ready when that ends` and exit 0 at once (ADR-041
  RS-2 item 5), and the OMP watcher shows nothing for it (ADR-041 RS-7). The test build
  (`test-knobs`) honours `VOX_TEST_REWRITE_HOLD_MS=<ms>`, which holds the rewrite's completion
  for that long and logs `test knob: store rewrite held <ms> ms`; SO-10's own in-tree journey is
  the staging ADR-041 RS-7's rewriting act reuses to make a store rewrite-eligible." RS-13's
  inode assertions run with no rewrite due.
- **ADR-040 r3 / ADR-050:** a typed `NotYet` whose prerequisite is the daemon is not displayed
  while the watcher reports `daemon: starting`: the display rule is the extension's and RS-7
  owns it; ADR-040's sibling bullet is to say that one clause instead of "No text change"
  (X040-1's row X041-8). The acts TJ-10 places in RS-7's file live there, as ADR-050 states
  them (r9: ADR-050 r11 places acts 1, 2, 3, 4, 5, 7, 8 (8a–8f, 8f′, 8f″), 9, 9b, 10 and 12 in
  it and acts 6 and 11 in `agent_hook_proof.rs`; the eight shim duties of its "ADR-041 RS-7,
  RS-9" contract are listed in RS-7's APPARATUS). Ledger row 15: ADR-040 NW-1's typed attention answer with `wait_ms`,
  `Fault::NotYet` and `SessionRegister`'s `state`/`observed_ms` (ADR-040 r6–r8) are counted in
  the one v0.4.31 bump to control protocol 12 (RS-12); ADR-050 adds no request; exit 79 and
  `--omp-finish` are hook surface.
- **ADR-045 FG-1/R-10 (row 32):** every proof of this ADR runs in the macOS guest or the Linux
  VM: the real-manager cases (RS-5, RS-15) in the guest's own `gui/<uid>` domain, the sysctl
  cases (RS-1) as root inside the Linux test VM (ledger row 69), the default-layout reset case
  (RS-15) on the guest's real default paths; none on the host or a real profile. **ADR-045 J8
  (X041-19, r8):** where J8 rebuilds the profile by hand today it runs `vox factory-reset
  --confirm-move-aside <name>` with a daemon running, one step in that journey, and asserts
  RS-15's three lines; the refusal and confirmation arms stay in RS-15's in-tree proof.
- **ADR-042 TR-19 (who prints what, r8):** ADR-041 owns the words and the fact; ADR-042 owns the
  layout of `vox status`, `vox node list` and `vox doctor` and places them. The words: RS-3's
  Locked line (`Locked: its remembered passphrase is no longer in this computer's memory
  (keyring: <kernel text>)` / `Unlock it once: vox node unlock <node>`); RS-5's `unsupervised:
  <why>` (enrollment broken, the manager refused, or no manager enrolled: the decider's Q4 and
  Q5) and `the login item is waiting`; RS-15's four factory-reset lines (`did not start`,
  `stopped the daemon and moved nothing`, `moved the old data to …; this folder is new`,
  `cannot be reconciled`). Until ADR-042 carries the layout rows, the implementation prints
  them in ADR-041's words on their own line of the node or daemon block. ADR-042 TR-25's "needs
  its passphrase again until ADR-041 lands" is ADR-042's to delete (X042-22): RS-1 keeps the
  passphrase across restarts and RS-3 covers the reboot.
- **ADR-043:** nothing new; RS-15's "pairing again" text stays ADR-043's.

## Alternatives the plan and the revisions rejected

- **Replace in place (`execve` under the running pid; revision 1's RS-2).** See "Why not replace
  in place, once made sound".
- **Stop, then start, by the restarter (revision 2's RS-2).** The restarter's death between the
  two leaves the root unserved with nobody to notice (second review N1).
- **The old daemon spawns its successor and passes the passphrases over a socket pair (plan F;
  nginx's binary upgrade, HAProxy's `-x`).** The successor is not the manager's process: under
  launchd the job's process group is killed when its main process exits (`launchd.plist(5)`,
  `AbandonProcessGroup`), and under systemd the unit's control group is (`systemd.kill(5)`); and
  with the remembered store there is nothing to pass. RS-2's unmanaged path keeps the one good
  idea, "the replacement exists before the old one stops", without the hand-over and only where
  no manager exists.
- **Socket activation (launchd `Sockets`, `sd_listen_fds`, systemd `FDSTORE=1`)**: keeps the
  control socket bound across a managed restart and could park a memory file holding secrets in
  systemd's fd store; two mechanisms per platform, nothing for an unmanaged install, and the lease
  plus the remembered store make both unnecessary.
- **A helper process that outlives the restarter to finish an unmanaged restart:** that is what
  the replacement daemon is; a separate helper would be a second thing to kill.
- **The restarter holds the lease and its replacement inherits or shares it (revision 3):**
  nothing is inherited across the spawn (`daemon.rs:95-101`), and a shared lease has two owners;
  the rule "the process about to take the lock holds it" has one.
- **Stopping the detached daemon, then asking the manager (revision 3's item 81):** the
  restarter's death between the two leaves the root down with the manager's job not running
  (third review R3-3); the manager's daemon is started first and waits.
- **The config dir as the authority outside the data root (revision 3):** on a default Mac it is
  the data root (`paths.rs:837-858`).
- **Moving the data root's contents instead of the root, so the root stays as the authority:**
  several renames instead of one atomic one; the sibling control directory keeps the single
  rename.
- **A cross-protocol `Stop` frame for the v0.4.30 daemon:** a second codec for one update;
  v0.4.30's own SIGTERM stop, kept for protocol 11 only, is what that daemon already understands.
- **Linux passphrase store.** (A) Secret Service over D-Bus (gnome-keyring, KWallet): on a headless
  host the login collection is unlocked only by a PAM login, so a daemon started by
  `systemctl --user` after a reboot finds it locked or absent. (B) A file encrypted with a key from
  `/etc/machine-id` and an install secret: both inputs are readable by the same user that can read
  the file, so it is a 0600 file wearing a cipher; it is equivalent to `--passphrase-file`. (D)
  systemd credentials alone: they survive a reboot but need systemd 258 for user units
  (https://systemd.io/CREDENTIALS, systemd/systemd#33796); kept as Q1's reboot source.
- **`KeepAlive: true` for the login item:** a start refused for good would then be retried every
  10 s forever (`daemon.rs:342-375` exits 0 to stop that); the exit-status rule keeps the plist
  and the refusal behaviour.
- **Deciding "foreign stop" by the sender's pid (revision 2):** needs launchd to deliver
  `si_pid == 1`, which nobody measured; "signal or request" needs nothing.
- **Manager discovery from the running daemon (revision 2's `.daemon/manager`):** cannot be
  written on the root that showed the defect (second review N2).
- **A client's daemon serving a managed root for good once the manager refused (a plain
  reading of Q4(b)):** the decider's answer keeps one daemon per root and the manager's
  ownership; the takeover when the manager recovers is what makes both true without a person.
- **Stopping the client's daemon before the manager's job runs (revision 4's transfer arm):**
  the restarter's death between the two left a window (third review R3-3); the manager's daemon
  stopping it itself, under its own lease, has no such window.
- **A long-lived flock for the managed restart interval:** no process lives across the
  manager's stop and start to hold it; the admission rule (yield to a known job) and the
  age-bounded `planned` record need no holder.
- **A restart lease with a deadline in a file:** goes stale after a crash; a lock does not.
- **Self-restart on SIGTERM**: a daemon that refuses to die is what `kill` is for.
- **Watcher-side debounce** (wait 10 s before telling the person): hides the fact, does not name
  it.
- **Liveness of a registration by its endpoint alone, or by a renewed lease:** the endpoint alone
  mistakes a refused connect during OMP's own restart for death; a lease needs more registration
  writes (item 29's lock contention) and a trusted clock.
- **Room-pinned coordination level** (Matrix room versions, https://spec.matrix.org/latest/rooms/):
  one fold per room; more than one level needs; reserved for the release that first raises the
  level, which must ship it then. **`<=` level folding**: diverges (first review, finding 9).
- **Keep exact version match and only re-announce:** fixes the freeze, not the lost claims.
- **The hook announces at the first drain of a new session:** the daemon owns the Session and its
  hello. **A new Session-row field as the announcement:** reaches no consumer.
- **Repairing the original store after the vault is proved (revision 2's RS-14):** proves the
  vault, not the store (second review N5). **Refusing every store that needs repair:** leaves a
  person's own dirty store unusable; inspecting a copy costs disk once and keeps the rule.
- **The identity pin in the registration file, or on the OMP session's active branch:** replaced
  with the node directory; lost on tree selection.
- **Lock the root directory itself instead of a file in it:** subsumed by RS-13's descriptors.
- **A silent carry-over of a conversation to the rebuilt node, with a notice:** the carry-over is
  the defect. **Identity in the hook's node argument** (`--node omp-work@lp3juw…`): every rebuild
  reinstalls the extension, and conversations still need the refusal text.
- **The updater spawns the app as its own child and waits on it:** the relaunched app would be a
  child of a passing updater, not of launchd. **Widening the 30 s poll:** hides reading A, does not
  fix reading B.

## Implementation order and related work

1. RS-13, RS-14: directory binding, the vendored read-only open, the store check. No
   dependencies; the largest change; first.
2. RS-1, RS-3: the kernel keyring and the reboot case.
3. RS-2, RS-6: the lease, `planned`, `Stop { reason }`, admission, the replacement's take-over
   on an unmanaged root; the sender line (RS-5's exit rule and proof read it).
4. RS-8: liveness, the two-field end, the reaper.
5. RS-7: watcher fields and the extension's text (needs 3 and 4). It comes before RS-5 because
   RS-5's proof (c), (d') asserts RS-7's reconnected line (r7).
6. RS-5: enrollment, the manager's takeover, `unsupervised`, the exit rule (needs 3, 5); with
   them RS-2's cutover arm and the bundle transaction's new order, which need this step's
   enrollment and takeover (r9), and RS-4, whose warning precedes the restart the cutover arm
   performs (r7).
7. RS-15: `vox factory-reset` (needs 1 for the descriptors, 3 for the lease and `planned`, 6 for
   the enrollment it keeps and the manager it starts) (r7).
8. RS-9: identity in the conversation (needs 5 and 1).
9. RS-10, RS-11, RS-12: levels, the per-pair table, numbers (RS-11 needs RS-10 and RS-8).
10. RS-16: independent; in parallel with any.

Dependencies on other lanes, by ADR:

- **ADR-040** (named waits and failure containment): the restart-window texts other than C2's, the
  poisoned conversation, and "session registration is busy" (items 29, 30). Its OMP journeys share
  RS-7's proof file.
- **ADR-042** (status reports outcome): the layout of RS-3's Locked line in `vox status`, the
  `unsupervised` and reset lines, and the rule against hints that may destroy an identity.
- **ADR-043** (adding, replacing and removing a computer): what RS-15 says about pairing again.
- **ADR-044** (the daemon stays responsive under agent load): "Preparing" after a restart (item
  18). RS-2's terminal state is Ready, not prepared.
- **ADR-045** (the fleet release gate): journeys J7 and J12 run this ADR's claims on the fleet; the
  real-manager cases of RS-5 and RS-15 run on its guest M; fleet host B needs the two keyring
  cases.
- **ADR-047** (storage): every store rewrite uses RS-13's directory descriptor; SO-10's rewrite at
  start is a terminal state the restart names.

## Consequences

### Positive

- Where a node has a remembered store, `vox daemon --restart` and `vox update` leave it Ready on
  both platforms with nobody typing, and conversations say at most one line.
- A restart's completion never depends on the process that asked for it: a manager finishes it,
  or the replacement that is about to serve does.
- One serving daemon per data root at every moment; on his Mac it is the login item's, enrolled
  by the app, and it comes back by itself after any stop that is not the product's.
- An update keeps the board, and ending one conversation never silences another.
- A replaced profile stops the old daemon instead of feeding it; a foreign store is refused with
  its bytes untouched, healthy or dirty.
- The next unexplained SIGTERM names its sender, and the manager undoes it.
- No second daemon startup path, no hand-over protocol: the restart is the stop and the start
  every service manager already knows how to do.

### Negative

- The kernel keyring is readable by every process of the same user, and by root, as a passphrase
  file is; it keeps a reusable passphrase after the daemon that took it exited, which today's
  typed unlock did not. It does not survive a reboot, and a copy an attacker took cannot be
  recalled.
- A host that refuses `add_key` (Docker's and podman's default profiles) has no remembered store
  short of a passphrase file; a restart there asks again, and says so beforehand.
- A Linux root without an enrolled unit (beast and IO today) is unmanaged, by the decider's Q5:
  a dead daemon returns at the next client, not by itself, and `vox status` says `unsupervised`.
  On an unmanaged root the one death nothing survives is the replacement's own, after the old
  daemon stopped and before its nodes are Ready.
- By the decider's Q4, a manager that refuses to start its job leaves the root to a client's
  daemon, `unsupervised`, until the manager recovers; the takeover then is one more planned
  restart (a clean stop and an attach), read by the watcher as `starting`.
- `vox factory-reset` cannot be run by a script without naming the folder it moves
  (`--confirm-move-aside <name>`); that is the confirmation the decider asked for.
- The cutover from v0.4.30 keeps one SIGTERM arm for protocol-11 daemons until v0.4.32, and a
  protocol-12 client is refused by a protocol-11 daemon between the bundle swap and the restart
  step of that one update.
- A control directory appears beside every data root (`<data root>.control`); a person who moves
  a data root by hand must move it too, or `vox status` says the root's manager is not enrolled.
- Every restart is still an outage of the stop plus the start (0.5–3 s measured; bounded at
  30 + 15 + 30 s before the restarter gives up); the lease and the watcher make it quiet, not
  invisible.
- Inspecting a dirty foreign store needs free disk equal to its size, once.
- The directory-descriptor change touches every writer in `vox-core` and the daemon, and adds a
  method to the vendored redb; one missed path keeps the hole. The proofs are the guard.
- The update to v0.4.31 itself: Linux nodes typed to a 0.4.30 daemon need one unlock (one per
  restart where the keyring is refused), and an OMP whose extension predates the update prints
  its old advice once.
- The login item's and the unit's exit status carries meaning to the manager (71 after a signal).

### Neutral

- macOS keeps the Keychain; the app's login item keeps its plist; the bundle keeps its swap, with
  the daemon's restart after it.
- The watcher's frame gains fields; the registration, the hello and the claim ops change format;
  the control protocol goes from 11 to 12; v0.4.x owes no prior-release compatibility.

## The decider's answers (2026-11-13)

Asked as five single-choice questions in revision 4 (`adr-cross-changes.md` rows 43–47);
answered in the widget, two rounds for Q4 and Q5. Each is applied in the requirement it names;
none is open.

1. **Q1, a Linux node after the computer restarts** (row 43): "combination of 1 and 2": a systemd
   credential sealed to the TPM where systemd ≥ 258 and a TPM exist; otherwise a passphrase file
   as today; not one unlock per boot. Applied in RS-3, with what each source protects and does
   not. The ADR had recommended the credential with one unlock as the fallback.
2. **Q2, claims made on v0.4.30** (row 44): kept across the update. Applied in RS-10: a
   v0.4.30 record reads as level 1 until the first room transition.
3. **Q3, "start over" as a command** (row 45): yes, named `vox factory-reset`, "with an approval
   follow up required". Applied in RS-15: the summary, the typed folder name, the
   `--confirm-move-aside` flag for scripts, refusal without either.
4. **Q4, the enrolled manager knows the job and refuses to start it** (row 46): option (b),
   against the ADR's recommendation: the client starts a daemon itself and `vox status` says
   `unsupervised`; one daemon per root still holds and the refusal is named. Applied in RS-5
   (`--unsupervised`, the admission rule) and RS-2 (the manager's daemon takes the root over when
   the manager recovers).
5. **Q5, the scope of the goal** (row 47): a root with no enrolled manager (beast, IO) gets its
   daemon back at the next client, shown as `unsupervised`; no managed service is required
   there. Applied in RS-5 and the Negative consequences. With the same answer he corrected the
   premise: "a restart needs no human" was the plan's summary, not his ruling; the ADR now states
   it as its own goal (the first section).

## Links

- Fix list: `v0431-fix-list.md` items 39–48, 81. Plan: `plan-F.md`. Reviews:
  `adr-041-sol-review.md`, `adr-041-sol-review-2.md`. Revision note:
  `adr-041-revision.md`. Analyses: `rca-systemic.md`, `rca-RcaSessions.md`,
  `rca-RcaStore.md`, `rca-RcaAppQuit.md`, `rca-RcaTrust.md`.
- [ADR-014: the macOS app](ADR-014-macos-client.md) (M-8, M-9)
- [ADR-018: product proofs](ADR-018-quality-bar-and-product-proof.md)
- [ADR-021: work-item interop](ADR-021-work-item-interop.md) (§5)
- [ADR-026: the daemon and its nodes](ADR-026-daemon-and-nodes.md) (D-1, S-1, S-2, L-5, F-1, F-3)
- [ADR-028: keyring](ADR-028-one-experience-keyring-rooms-services-files.md) (K-10, K-13)
- [ADR-029: Sessions](ADR-029-sessions-and-the-repo-room.md) (SE-4)
- [ADR-031: Ready or Locked](ADR-031-agent-nodes-join-a-repo-room-by-themselves.md) (CW-3)
- [ADR-034: updates](ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md) (UP-1, UP-2)
- [ADR-038: FX-34](ADR-038-daemons-trust-daemons-and-sessions-are-presence.md)
- External: `persistent-keyring(7)`, `keyctl_get_persistent(3)`, `add_key(2)`, `keyctl(2)`;
  https://systemd.io/CREDENTIALS; `systemd-creds(1)`; `systemd.kill(5)`; `systemd.service(5)`
  (`Restart=`, `RestartForceExitStatus=`); `launchd.plist(5)` (`KeepAlive`, `ExitTimeOut`);
  `launchctl(1)` (`kickstart -k`, `bootout`); `sysctl(3)` `KERN_PROCARGS2`; `proc_pidinfo(3)`;
  `pipe(7)`; `execve(2)`; https://docs.docker.com/engine/security/seccomp/; containers/common
  `pkg/seccomp/seccomp.json`; OMP `packages/coding-agent/src/session/session-manager.ts`
  (`getEntries`, `getBranch`, `appendCustomEntry`); https://spec.matrix.org/latest/rooms/.
