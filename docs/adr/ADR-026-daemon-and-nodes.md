# ADR-026: The Daemon and the Nodes That Use It

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted by the decider, 2026-10-03 (#397, V030-35). **Built** (v0.3.0,
`crates/vox-core/src/node/`, `crates/vox-core/src/transport/`, `crates/vox-tui/src/`), except: N-2
(the TUI still locks its node), S-4 and C-7 (the TUI still embeds its node), and what is marked
*Deferred*. §10 names the proof of each claim.
**Date**: 2026-10-03
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: daemon, node, identity, control-plane, lifecycle, layout

## Context

The daemon is the machine's Vox service, distinct from the nodes that use it, as one terminal
multiplexer daemon serves many harnesses. A node is an identity: a person or an agent, never a
device (ADR-002). Several nodes can live under one OS account: a person's node, and one node for each
agent working beside them. Which nodes run on a machine changes over the day: an agent's session
needs its node attached (by the operator, outside the session, ADR-028 K-13) and lets it go when
it ends, and the person can attach and detach by hand. Every node that is in runs in
full, side by side; naming a node matters only for an action done as it. Unlocking works as
gpg-agent does: a node gets its passphrase once, when it attaches; a keyring change asks again
unless one was typed for a keyring change in the last 30 minutes (ADR-028 K-12). The daemon owns the machine's one
network presence from the start: there is no interim design with one socket per node.

## Requirements

### 1. The daemon

- **D-1.** There MUST be at most one daemon per data root, so normally one per OS account, which has
  one data root. Two data roots under one OS account (`VOX_DATA_DIR`) MAY each run their own daemon; each has its own lock, socket, port and nodes. A
  daemon MUST hold an exclusive lock on `<data root>/.daemon/lock` for its whole life; a second daemon
  that cannot take the lock MUST exit, saying a daemon is already running. A second `vox daemon`
  invocation that names a node MUST hand that node to the running daemon (attach, §3) instead.
- **D-2.** The daemon MUST NOT be a node. It holds no identity key, takes no part in any room and
  MUST run with zero nodes attached.
- **D-3.** The daemon MUST own, once for its data root:
  - one UDP socket and one QUIC endpoint (ADR-011), bound once, with one dual-stack self-test;
  - the port, kept in `<data root>/.daemon/port` and reused on every start (ADR-012). `--listen` on
    a client verb MUST set the address the daemon listens on only when that command starts the
    daemon; if a running daemon listens elsewhere, the client MUST warn and use it;
  - the gateway port mapping (ADR-012). Detaching a node MUST NOT remove a mapping; stopping the
    daemon MUST;
  - the observed (reflexive) address cache and LAN discovery (nearby);
  - the inbound handshake gate and the identity exchange's pre-identity gate (ADR-011);
  - the execution of relay circuits, with one relay circuit ledger and one set of relay limits per
    daemon, since it is one presence (ADR-012 N-45). Each relay is governed per node: a node relays
    for its own rooms' members (PRD-001 R33);
  - board (rendezvous) service, executed by the daemon with one board per node (ADR-012 N-45);
  - agent session registration and unregistration (ADR-020), so a session end and a detach are
    decided together (L-3);
  - the control socket (§4), metrics, signal handling, the async runtime and node lifecycle (§3).
- **D-4.** Each attached node MUST publish its own address record (ADR-012). Every node of one daemon
  publishes the same ip:port.
- **D-5.** Detaching a node MUST close only that node's connections, in today's order (goodbye,
  relayed connections first), and MUST NOT close the endpoint or touch another node's connections,
  tunnels or sessions.

### 2. Nodes

- **N-1.** A node MUST be an identity with its own: composite long-term key (a vault, or a headless
  key for an anchor), store, trust keyring, rooms, services, sessions, cursors and config (§7).
- **N-1a. Names.** A node's name MUST be one path component of 1–64 bytes from `[a-z0-9._-]`, MUST NOT
  start with `.`, and MUST be case-folded to lower case before use. `.daemon` and `nodes` are
  reserved and MUST be refused.
- **N-2. No locked node.** There MUST be no locked state, and no lock or unlock request or event. A
  node MUST receive its passphrase once, when it attaches, and MUST run in full while attached: it
  dials, accepts, syncs, serves, relays and publishes. Keyring changes (trust add, remove, rename, a
  capability change)
  MUST ask for the passphrase unless one was entered for a keyring change within the keyring window
  (30 minutes, V210-159); the passphrase given at attach MUST NOT open that window (ADR-028 K-12).
  Detaching is the only way a node stops. *Built (#409): there is no `Lock` command and no
  `Locked` or `Unlocked` event; the vault is opened once, by the daemon's attach, and a detach wipes
  the node's secrets once work holding one has finished
  (`a_detach_leaves_no_secret_in_memory_proof`).*
- **N-3.** All attached nodes MUST run concurrently: each syncs, receives, serves and wakes its agents
  independently. Selecting a node for a request MUST NOT idle, pause or deprioritise any other node.
- **N-4.** There MUST NOT be an "active node". A node is named only to say which node an action is
  done as (C-3).
- **N-5. Anchor.** An anchor MUST be a daemon with one headless node attached in the anchor role
  (ADR-016). `vox node` MUST start a daemon with that node; it MUST NOT be a separate process type.
- **N-6. Agents.** Each agent MUST be its own node, one per (host, harness). An agent MUST NOT use a
  person's node, and a person MUST NOT share a node with an agent. The agent's node is created by its
  skill pack's setup (`vox node create <harness>-<host>`, with a passphrase the operator types, as
  for every node, ADR-028 K-11). Its hooks MUST be installed as
  `vox agent hook --node <name>` and MUST act only as that node. A hook invoked without `--node` MUST
  refuse; it MUST NOT fall back to any other node (ADR-020).

### 3. Node lifecycle

- **L-1.** The daemon MUST keep one state per node, `detached → attaching → attached → detaching →
  detached`, and MUST serialise every transition of one node through it.
- **L-2. Attach.** A node MUST be attached:
  - by hand: `vox node attach <name> [--keep]`;
  - implicitly, only by a verb that holds a session (`serve`, `connect`, `up`, `forward`, `lan up`)
    or by the TUI, when the client supplies the node's passphrase. An agent's hook MUST NOT attach
    a node: when its node is not attached, it MUST show the operator the attach command to run
    outside the session (ADR-028 K-13);
  - at daemon start: every node in the `--keep` list (`<data root>/.daemon/attach`).

  One-shot verbs (`room`, `status`, `share`, `app` and the like) MUST NOT attach: they MUST refuse
  when their node is not attached, saying how to attach it.

  Attaching MUST: take the node's directory lock, open its files, start its actor as its own task,
  take its passphrase, reopen its saved rooms (ADR-010 AR-25), and start its tasks (wake loop,
  notifier, anchor follow). Attaching an attached node MUST be idempotent. A second concurrent attach
  of one node MUST wait for the first and then succeed.
- **L-3. Holders and detach.** A node attached implicitly MUST count its holders: the open held
  connections (L-7) and the registered agent sessions that act as it. When the count reaches zero, it
  MUST detach. An agent session's unregistering and the detach it causes MUST be decided atomically
  in the daemon. A node attached by hand or from `--keep` MUST stay attached until `vox node detach
  <name>` or the daemon stops.

  Detaching MUST: answer every in-flight request for the node with a distinct "node detached" error
  (which MUST NOT trigger an implicit re-attach), stop its tasks, close its connections (D-5),
  unregister its signer from the identity exchange (ADR-011) before its keys are wiped, wipe its keys,
  close its store and release its directory lock.
- **L-4. Keep.** `--keep` MUST record the node in `.daemon/attach` with its passphrase source: none
  (an anchor's headless key, N-1), or a file path. A file source serves attach only, never a keyring
  change (ADR-028 K-13; the decider, 2026-10-06). On daemon start each kept node MUST re-attach, and its rooms and services MUST come
  back. *Deferred (additive):* an environment-variable passphrase source in the attach file.
- **L-5. Silent harness death.** *Deferred (additive):* a sweep that unregisters the sessions of a
  harness that died without ending them. Until it exists, such a session MUST keep holding its node.
- **L-6. Panic isolation.** Each node's actor MUST run as its own task. The daemon MUST watch its
  handle; a panic MUST detach that node only, and MUST be reported (status, event and log). The
  daemon and every other node MUST keep running. Process-wide state MUST tolerate a poisoned lock.
- **L-7. Held sessions.** `vox serve`, `vox connect`, `vox up`, `vox forward` and `vox lan up` in the
  foreground MUST be daemon-side sessions bound to the client's control connection. When the daemon
  stops or dies, the client MUST notice the connection close and exit non-zero, saying so; it MUST
  NOT keep running on a dead listener.
- **L-8. An auto-started daemon** (S-2) MUST exit once it has no attached node and no client
  connection, after a 1 s linger. It MUST NOT take that exit within 10 s of serving, so the client
  that started it, slow to connect on a loaded machine, finds it there. A daemon started by hand
  MUST run until stopped.

### 4. Control plane

- **C-1.** The daemon MUST serve exactly one control socket, `<data root>/.daemon/vox.sock`, mode
  `0600`, checked against the peer's uid. It MUST NOT admit uid 0. Per-node sockets MUST NOT exist.
- **C-2.** A client MUST name its node once per connection, with an opening `Use { node }` frame,
  not on every request. Daemon requests (attach, detach, list nodes, daemon status, metrics, stop)
  MUST work with no `Use`.
- **C-3. Resolution.** A client MUST resolve the node for `Use` as, in order:
  1. the node it names (`--node <name>` or `VOX_NODE`);
  2. else the only attached node;
  3. else the only node on disk;
  4. else `default`, when the data root has no node at all, for identity-creating verbs only;
  5. else refuse, listing the nodes.

  `--profile` MUST be replaced by `--node`, with no alias.
- **C-4.** The control protocol MUST be IPC version 9. `Hello` MUST report the daemon's version and
  the attached nodes. The daemon MUST emit events for attach and detach.
- **C-5.** The socket's vocabulary MUST stay narrow: no identity creation, `Revoke` or passphrase
  rotation over the socket. `vox node create` MUST write the new node's files in the client and then
  attach it.
- **C-6.** Passphrases MAY travel over the socket (attach, keyring changes): the OS account is the
  boundary (ADR-001). They MUST be carried in zeroizing buffers end to end. A passphrase taken from
  an environment variable MUST be resolved in the client, never by the daemon. A foreground
  `vox daemon` attaching its own foreground node is that node's client: it MAY read
  `VOX_IDENTITY_PASSPHRASE` for that node only, never for a node another client asks it to attach.
  A keyring change MUST NOT take its passphrase from an environment variable or a file; it is typed
  (ADR-028 K-13).
- **C-7.** The socket MUST offer what the TUI needs as a client: open and close of a closed room,
  per-node status, attach and detach. *Built (#409): `OpenRoom`/`CloseRoom`, the node snapshot
  (`node::snapshot`), status and tunnel close on the node's connection, and the daemon's attach,
  detach and events; the TUI uses only these (`the_tui_shows_the_room_truthfully_proof`, `tui_member_names_proof`, `tui_unread_backfill_proof`).*

### 5. Starting the daemon and the clients

- **S-1.** `vox daemon` MUST run in the foreground. SIGHUP, SIGTERM, SIGINT and SIGQUIT MUST each
  detach every node cleanly and then stop the daemon.
- **S-2. Auto-start.** A client that may attach a node (L-2: a session-holding verb, the TUI,
  `vox node attach`), or an agent's hook, that finds no daemon MUST start
  `vox daemon --detach`, writing its stderr to `<data root>/.daemon/log` from its first line, and MUST
  wait up to 15 s for the socket. After that it MUST fail, saying the daemon did not start and naming
  the log's path. Concurrent starts MUST end with exactly one daemon (D-1).
- **S-3.** No verb MUST host its own node: `serve`, `connect`, `up`, `forward`, `service`, `trust` and
  every other verb MUST be clients of the daemon.
- **S-4. Clients.** The TUI and the macOS app MUST be clients of the daemon (ADR-014, ADR-015); they
  MUST NOT embed a node. A client has no node lock: SIGHUP MUST stop the client cleanly, the same as
  quitting, and the client MUST only drop its hold, so a node it attached implicitly detaches if that
  was its last holder (L-3) and one attached by hand or with `--keep` stays attached. The one
  exception is the iOS app (v0.4.0), which hosts its own node because iOS runs no background daemon.
  *Built for the TUI (#409): `the_tui_shows_the_room_truthfully_proof`, `tui_member_names_proof`, `tui_unread_backfill_proof`, `a_detach_leaves_no_secret_in_memory_proof` (SIGHUP
  mid-attach). Not built for the macOS app (ADR-014).*
- **S-5. `vox lan up`.** The user-side `vox lan up` MUST be a daemon client holding a session (L-7).
  The daemon, as the same uid, MUST ask the root helper (`sudo vox lan helper`) for the device and
  run the LAN itself. The helper MUST serve its interface over its own socket owned by `SUDO_UID`;
  the account socket MUST NOT admit uid 0.
- **S-6.** *Deferred (additive):* `vox daemon install` (a launchd or systemd unit).

### 6. Identity on the shared endpoint

- **I-1.** A connection MUST be identified as (local node, remote node, remote process). The remote
  node MUST be established by ADR-011's identity exchange, never by the TLS handshake.
- **I-2.** After the exchange the listener MUST apply admission (trust, join gate; ADR-016) as the
  target node.
- **I-3.** Connection, circuit and dial bookkeeping (`MuxSocket` peers, circuit lookups, dial-backs,
  outbound circuits) MUST be keyed by (local node, remote node). The remote process identity used for
  supersession MUST be `sha256(remote daemon leaf ‖ instance)`, where `instance` is the 16-byte
  per-attach value the remote node signs in the exchange (ADR-011), so a node that re-attaches is
  seen as a new process.
- **I-4.** Two nodes of one daemon MUST reach each other by dialling the daemon's own address, through
  the same exchange as any other pair. The first piece of work MUST be a real-binary proof that this
  works, including connection loss and redial, before anything else depends on it.

### 7. Files, and no migration

- **F-1. Layout.**
  ```
  <data root>/.daemon/        lock, vox.sock, port, log, attach,
                              config (listen, metrics, relay limits)
  <data root>/nodes/<name>/   vault.cbor | node-identity.key, store.redb,
                              config/   (today's file names: anchors, config,
                                         retention, serve, downloads,
                                         tunnel-stuck-after)
                              cursors/, sessions/
  ```
- **F-2.** A node's setting MUST be read from `nodes/<name>/config/<file>`; when that file is missing,
  from the same file in the account's config directory. The daemon's own settings (listen, metrics,
  relay limits) MUST be read from `.daemon/config`; the relay limits are `relay-circuits` and
  `relay-circuits-per-asker` (ADR-012 N-45).
- **F-3. No migration.** Vox MUST carry no code that reads, converts or migrates data written by a
  release before v0.3.0: nobody has run one (decider, 2026-10-04, #423).
  - A directory of the data root outside `nodes/` holding `vault.cbor`, `node-identity.key` or
    `store.redb` is not a node. A data root holding one MUST be refused by every verb, and by the
    daemon before it takes its lock, saying "`<root>` is not a Vox data directory this version
    reads: `<root>/<name>` is not a node", and MUST be left byte for byte unchanged.
  - Only this version's formats are read: a vault, keyring, store blob, cache row or log entry of
    another version is malformed, never converted.
  - One node is one identity: a node holding a vault runs its anchor (`vox node`) as node
    `<name>-anchor`.

### 8. Process-wide state

- **P-1.** Every `static`, `OnceLock`, `Once` and module-level atomic in `vox-core` and `vox-tui` MUST
  be listed below with its disposition. A check MUST enumerate them against this table, so a new one
  is a deliberate decision.

  | State | Disposition |
  |---|---|
  | `LIVE`, `CLOSED` tunnels (`quic.rs`) | per owning node; every reader filters; tunnel ids over IPC are node-scoped |
  | `DIAL_BACKS`, `OUTBOUND_CIRCUITS` | keyed (local node, peer) |
  | the relay circuit ledger (circuits this daemon carries) | one per daemon |
  | `FINISHING` (`tunnel/session.rs`) | per node; daemon stop waits on all |
  | `STUCK_AFTER_SECS` (`tunnel/session.rs`) | a per-node setting |
  | `MuxSocket.by_peer`, circuit lookups | keyed (local node, remote node) |
  | origin-tag `KEY` (`circuitstream.rs`) | per relaying node |
  | `ident::NAMES`, `ident::ME` (`vox-tui`) | removed; names passed explicitly |
  | test-knob maps by room (`actor.rs`), the `LEFT` counter | keyed (node, room) |
  | test-knob environment `OnceLock`s (`prekeys.rs`, `channel.rs`, `log/sync.rs`, `nat/store.rs`, `ipc.rs`, `transport/mux.rs`) | process-wide, test builds only |
  | `NEXT_TUNNEL`, `NEXT_SERIAL`, `paths::NEXT` | process-wide unique counters |
  | `PINNED` (`atrest/lock.rs`) | process-wide mlock bookkeeping; every node shares `RLIMIT_MEMLOCK` |
  | `SAID` (`quic.rs`), cached strings (`api.rs`, `viewmodel.rs`) | process-wide |
  | `SENDING` (`claude_injector.rs`) | process-wide: one tmux send at a time, whichever node's Session it types into (ctm's lock), so two drives never interleave their keys; it holds no node's state |
  | `ASCII`, `DEPTH` (`theme.rs`, `vox-tui`) | process-wide: what this process's terminal can show, read once from its environment; a TUI runs in one terminal |
  | signals, metrics (labelled `node=`), runtime size | daemon-level |

### 9. Diagnostics

- **G-1.** A dial that finds no node answering as the expected identity MUST say "nothing at
  `<address>` answers as `<expected node>`". It MUST NOT say who else answered there: the generic
  refusal (ADR-011) gives a dialler nothing more, and a daemon's leaf names no node.

### 10. Proofs

Each claim MUST be proved by real use of the shipped binary (ADR-018), with one mutant per claim:
1. two nodes on one daemon post, read and serve concurrently, and a remote daemon reaches both at one
   ip:port, each as itself (`two_nodes_are_clients_of_one_daemon_proof`,
   `two_nodes_answer_at_one_address_proof`);
2. node to node within one daemon, including loss and redial (I-4)
   (`the_nodes_of_one_daemon_proof`);
3. detaching one node keeps the other's live tunnel and sync (mutant: endpoint closed on detach)
   (`the_nodes_of_one_daemon_proof`);
4. tunnels, counters, status and metrics are per node; node A cannot list or close B's tunnel
   (`two_nodes_are_clients_of_one_daemon_proof`). The metrics exposition's shape, with each
   family's `HELP` and `TYPE` once across nodes and `node` first among a sample's labels, has no
   proof: its in-process test was deleted in v0.4.1 (AGENTS.md: no unit tests);
5. a panic in one node's actor leaves the daemon and the other nodes serving
   (`the_daemon_and_its_nodes_proof`);
6. two clients attaching one node at once both succeed with one attach; a detach with a request in
   flight answers "node detached"; the last holder's going detaches an implicit node, atomically
   with an agent session's unregister (`the_daemon_and_its_nodes_proof`,
   `a_detach_mid_request_is_said_in_words_proof`);
7. a `--keep` node and its rooms and services return after a daemon restart
   (`the_daemon_and_its_nodes_proof`); a foreground `vox serve` exits non-zero when the daemon
   stops (`the_nodes_of_one_daemon_proof`);
8. two clients with no daemon running end with exactly one daemon, and an auto-started daemon exits
   when its last node detaches (`the_daemon_and_its_nodes_proof`);
9. a hook acts only as its `--node`, and refuses without it
   (`an_agents_wiring_acts_only_as_its_node_proof`); a one-shot verb refuses an unattached node
   (`the_nodes_of_one_daemon_proof`); node names follow N-1a (`the_nodes_of_one_daemon_proof`);
10. a fresh data root works end to end, and one holding a node's files outside `nodes/` is refused
    with the reason and left unchanged (`a_data_root_of_an_earlier_release_is_refused_proof`);
11. a node keeps running in full past the keyring window, and only a keyring change asks for the
    passphrase again (`a_keyring_change_needs_a_recent_passphrase_proof`);
12. R40 and R42 are re-measured (`perf_r40_chat_latency_proof`, `perf_r40_relayed_chat_proof`,
    `a_first_direct_connection_is_prompt_proof`, `a_first_punched_connection_is_prompt_proof`,
    `a_first_relayed_connection_is_under_two_seconds_proof`);
13. the process-wide-state enumeration (P-1) (`every_process_wide_state_is_listed`).

ADR-011's identity-exchange proofs are listed there.

## Consequences

Accepted by the decider as the costs of one network presence:
- **Co-hosting is visible.** Nodes on one machine share an address, so anyone holding their address
  records can tell they are co-hosted.
- **The presence probe.** A party that knows a node's fingerprint can test whether that node is
  attached at an address (ADR-011's identity exchange). Today an address reveals the one identity it
  serves.
- **One daemon leaf** links all of a daemon's connections, as the shared ip:port already does.
- **One handshake gate** serves every node: a flood on the port starves all of them, where one port
  per node isolated them.

Also:
- One port, one mapping and one self-test per machine, whatever the number of nodes.
- Passphrases cross the control socket; the OS account is the boundary (ADR-001). An attached node's
  keys stay in memory until it detaches.
- A failed dial can no longer name who else answered at an address (G-1).
- Every existing real-binary proof that starts a per-profile daemon or a self-hosting verb has to be
  moved onto the daemon model.

## Related ADRs

ADR-001 (the OS account is the boundary), ADR-002 (identity), ADR-010 (at-rest keys, reopened rooms),
ADR-011 (the identity exchange and the neutral leaf), ADR-012 (reachability, port, self-test, relay,
board), ADR-013 (tunnels), ADR-014 (the macOS app as a client), ADR-015 (the CLI and TUI as clients),
ADR-016 (node runtime, anchors), ADR-017 (services), ADR-018 (proofs), ADR-020 and ADR-021 (agents,
hooks, sessions), ADR-023 (leaving and ending rooms).
