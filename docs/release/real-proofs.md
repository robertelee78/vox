# Real-binary proof replacements

- **Source**: the decider's choice (a) for V29-17, 2026-09-25: a test that does not drive the shipped `vox` is kept only while it backs a product claim, and each such test gets its own item to replace it. *"I don't like clutter I don't like junk. I don't want to pretend that a test is a valuable thing unless it actually is."*
- **Rule for every item**: the replacement drives the shipped `vox` (and only it) for every node in the claim, is mutation-checked (it goes red when the behaviour it covers is broken), and the in-process test is deleted in the same change. Until then the in-process test is never cited as evidence.
- **Delivery boundary**: an item is delivered when its replacement is merged to `main`.
- **Exempt**: `vox-core/tests/watchdog_proof.rs` proves the test harness's own watchdog (a hung test process is killed), not the product, so it makes no product claim and needs no replacement.

### RP-01 — The agent-comms envelope and claim rules hold, through the shipped binary
**Why.** `crates/vox-agentcomms/tests/agentcomms_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that the agent-comms envelope and claim rules hold, goes red under a mutation that breaks it, and `crates/vox-agentcomms/tests/agentcomms_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-agentcomms/tests/agentcomms_gate.rs` no longer exists.

### RP-02 — A room is joinable when one of its members is offline, through the shipped binary
**Why.** `crates/vox-core/tests/a_join_is_not_hostage_to_one_member.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a room is joinable when one of its members is offline, goes red under a mutation that breaks it, and `crates/vox-core/tests/a_join_is_not_hostage_to_one_member.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/a_join_is_not_hostage_to_one_member.rs` no longer exists.

### RP-03 — A silent stream cannot stop a node, through the shipped binary
**Why.** `crates/vox-core/tests/a_silent_stream_cannot_wedge_the_node.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a silent stream cannot stop a node, goes red under a mutation that breaks it, and `crates/vox-core/tests/a_silent_stream_cannot_wedge_the_node.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/a_silent_stream_cannot_wedge_the_node.rs` no longer exists.

### RP-04 — A stranger holding only a .vox address cannot stop a node, through the shipped binary
**Why.** `crates/vox-core/tests/a_vox_name_is_not_a_licence_to_wedge.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a stranger holding only a .vox address cannot stop a node, goes red under a mutation that breaks it, and `crates/vox-core/tests/a_vox_name_is_not_a_licence_to_wedge.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/a_vox_name_is_not_a_licence_to_wedge.rs` no longer exists.

### RP-05 — One WANT cannot stop a room, through the shipped binary
**Why.** `crates/vox-core/tests/a_want_cannot_wedge_a_room.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that one WANT cannot stop a room, goes red under a mutation that breaks it, and `crates/vox-core/tests/a_want_cannot_wedge_a_room.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/a_want_cannot_wedge_a_room.rs` no longer exists.

### RP-06 — An anchor may be named by hostname, through the shipped binary
**Why.** `crates/vox-core/tests/anchor_hostname_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that an anchor may be named by hostname, goes red under a mutation that breaks it, and `crates/vox-core/tests/anchor_hostname_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/anchor_hostname_gate.rs` no longer exists.

### RP-07 — The at-rest passphrase factor meets its Argon2id floor, through the shipped binary
**Why.** `crates/vox-core/tests/atrest_profile_floor.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that the at-rest passphrase factor meets its Argon2id floor, goes red under a mutation that breaks it, and `crates/vox-core/tests/atrest_profile_floor.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/atrest_profile_floor.rs` no longer exists.

### RP-08 — Two members who joined a room read each other, through the shipped binary
**Why.** `crates/vox-core/tests/f12_joiners_read_each_other.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that two members who joined a room read each other, goes red under a mutation that breaks it, and `crates/vox-core/tests/f12_joiners_read_each_other.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/f12_joiners_read_each_other.rs` no longer exists.

### RP-09 — A quiet connection survives, through the shipped binary
**Why.** `crates/vox-core/tests/idle_connection_survives.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a quiet connection survives, goes red under a mutation that breaks it, and `crates/vox-core/tests/idle_connection_survives.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/idle_connection_survives.rs` no longer exists.

### RP-10 — A stream parked open across a withdrawal of trust is refused, through the shipped binary
**Why.** `crates/vox-core/tests/m17_11_parked_stream_proof.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a stream parked open across a withdrawal of trust is refused, goes red under a mutation that breaks it, and `crates/vox-core/tests/m17_11_parked_stream_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/m17_11_parked_stream_proof.rs` no longer exists.

### RP-11 — A v0.1.0 room keeps its name and its genesis grant authorizes nobody, through the shipped binary
**Why.** `crates/vox-core/tests/m17_13_v010_compat_proof.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a v0.1.0 room keeps its name and its genesis grant authorizes nobody, goes red under a mutation that breaks it, and `crates/vox-core/tests/m17_13_v010_compat_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/m17_13_v010_compat_proof.rs` no longer exists.

### RP-12 — A circuit's synthetic address reveals nothing it must not, through the shipped binary
**Why.** `crates/vox-core/tests/mux_circuit_addressing.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a circuit's synthetic address reveals nothing it must not, goes red under a mutation that breaks it, and `crates/vox-core/tests/mux_circuit_addressing.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/mux_circuit_addressing.rs` no longer exists.

### RP-13 — Two nodes behind NATs connect by hole punching, through the shipped binary
**Why.** `crates/vox-core/tests/nat_holepunch_through_nat.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that two nodes behind NATs connect by hole punching, goes red under a mutation that breaks it, and `crates/vox-core/tests/nat_holepunch_through_nat.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/nat_holepunch_through_nat.rs` no longer exists.

### RP-14 — A single-device node works end to end, through the shipped binary
**Why.** `crates/vox-core/tests/node_m13_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a single-device node works end to end, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m13_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m13_gate.rs` no longer exists.

### RP-15 — Two clients behind symmetric NATs talk through an anchor, through the shipped binary
**Why.** `crates/vox-core/tests/node_m15_anchor_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that two clients behind symmetric NATs talk through an anchor, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m15_anchor_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m15_anchor_gate.rs` no longer exists.

### RP-16 — A member opens a session from another member's bundle record, through the shipped binary
**Why.** `crates/vox-core/tests/node_m15_session_from_bundle_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a member opens a session from another member's bundle record, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m15_session_from_bundle_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m15_session_from_bundle_gate.rs` no longer exists.

### RP-17 — Revocation rotates the key with one member left out, through the shipped binary
**Why.** `crates/vox-core/tests/node_m18_revocation_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that revocation rotates the key with one member left out, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m18_revocation_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m18_revocation_gate.rs` no longer exists.

### RP-18 — Two client processes share one node, and one dying disturbs neither, through the shipped binary
**Why.** `crates/vox-core/tests/node_m19_ipc_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that two client processes share one node, and one dying disturbs neither, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m19_ipc_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m19_ipc_gate.rs` no longer exists.

### RP-19 — The trust keyring, not room membership, decides who reads, through the shipped binary
**Why.** `crates/vox-core/tests/node_m19_trust_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that the trust keyring, not room membership, decides who reads, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m19_trust_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m19_trust_gate.rs` no longer exists.

### RP-20 — Removing a key from the ring changes the lock, through the shipped binary
**Why.** `crates/vox-core/tests/node_m19_untrust_lock_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that removing a key from the ring changes the lock, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m19_untrust_lock_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m19_untrust_lock_gate.rs` no longer exists.

### RP-21 — A chat message over a relay arrives in under 1s, through the shipped binary
**Why.** `crates/vox-core/tests/perf_r40_relayed_chat_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a chat message over a relay arrives in under 1s, goes red under a mutation that breaks it, and `crates/vox-core/tests/perf_r40_relayed_chat_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/perf_r40_relayed_chat_gate.rs` no longer exists.

### RP-22 — A first direct connection completes in under 2s, through the shipped binary
**Why.** `crates/vox-core/tests/perf_r42_first_connect_open_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a first direct connection completes in under 2s, goes red under a mutation that breaks it, and `crates/vox-core/tests/perf_r42_first_connect_open_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/perf_r42_first_connect_open_gate.rs` no longer exists.

### RP-23 — A first hole-punched connection completes in under 2s, through the shipped binary
**Why.** `crates/vox-core/tests/perf_r42_first_connect_punch_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a first hole-punched connection completes in under 2s, goes red under a mutation that breaks it, and `crates/vox-core/tests/perf_r42_first_connect_punch_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/perf_r42_first_connect_punch_gate.rs` no longer exists.

### RP-24 — A first relayed connection completes in under 2s, through the shipped binary
**Why.** `crates/vox-core/tests/perf_r42_first_connect_relay_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a first relayed connection completes in under 2s, goes red under a mutation that breaks it, and `crates/vox-core/tests/perf_r42_first_connect_relay_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/perf_r42_first_connect_relay_gate.rs` no longer exists.

### RP-25 — A relayed pair keeps trying for a direct path, through the shipped binary
**Why.** `crates/vox-core/tests/relayed_path_is_retried.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a relayed pair keeps trying for a direct path, goes red under a mutation that breaks it, and `crates/vox-core/tests/relayed_path_is_retried.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/relayed_path_is_retried.rs` no longer exists.

### RP-26 — A better path displacing a worse one cuts nothing it carries, through the shipped binary
**Why.** `crates/vox-core/tests/retire_keeps_carried_paths.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a better path displacing a worse one cuts nothing it carries, goes red under a mutation that breaks it, and `crates/vox-core/tests/retire_keeps_carried_paths.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/retire_keeps_carried_paths.rs` no longer exists.

### RP-27 — vox forward binds loopback only, through the shipped binary
**Why.** `crates/vox-core/tests/sec_forward_binds_loopback_only.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that vox forward binds loopback only, goes red under a mutation that breaks it, and `crates/vox-core/tests/sec_forward_binds_loopback_only.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/sec_forward_binds_loopback_only.rs` no longer exists.

### RP-28 — No consent without a ring entry, and no author without evidence, through the shipped binary
**Why.** `crates/vox-core/tests/sec_no_consent_without_a_ring_entry.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that no consent without a ring entry, and no author without evidence, goes red under a mutation that breaks it, and `crates/vox-core/tests/sec_no_consent_without_a_ring_entry.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/sec_no_consent_without_a_ring_entry.rs` no longer exists.

### RP-29 — A room's log is served only to its members, through the shipped binary
**Why.** `crates/vox-core/tests/sync_serves_a_room_only_to_its_members.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a room's log is served only to its members, goes red under a mutation that breaks it, and `crates/vox-core/tests/sync_serves_a_room_only_to_its_members.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/sync_serves_a_room_only_to_its_members.rs` no longer exists.

### RP-30 — A host answers the next joiner straight after the last, through the shipped binary
**Why.** `crates/vox-tui/tests/a_second_joiner_is_not_locked_out.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a host answers the next joiner straight after the last, goes red under a mutation that breaks it, and `crates/vox-tui/tests/a_second_joiner_is_not_locked_out.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/a_second_joiner_is_not_locked_out.rs` no longer exists.

### RP-31 — An interrupt fires only when a message is addressed and urgent, through the shipped binary
**Why.** `crates/vox-tui/tests/interrupt_proof.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that an interrupt fires only when a message is addressed and urgent, goes red under a mutation that breaks it, and `crates/vox-tui/tests/interrupt_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/interrupt_proof.rs` no longer exists.

### RP-32 — A running daemon follows its anchor when the anchor moves, through the shipped binary
**Why.** `crates/vox-tui/tests/a_daemon_follows_its_anchor.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a running daemon follows its anchor when the anchor moves, goes red under a mutation that breaks it, and `crates/vox-tui/tests/a_daemon_follows_its_anchor.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/a_daemon_follows_its_anchor.rs` no longer exists.

### RP-33 — A room with a long history reopens and a newcomer catches up, through the shipped binary
**Why.** `crates/vox-tui/tests/a_long_room_reopens_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a room with a long history reopens and a newcomer catches up, goes red under a mutation that breaks it, and `crates/vox-tui/tests/a_long_room_reopens_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/a_long_room_reopens_proof.rs` no longer exists.

### RP-34 — vox agent hook works in both harness shapes, through the shipped binary
**Why.** `crates/vox-tui/tests/agent_hook_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that vox agent hook works in both harness shapes, goes red under a mutation that breaks it, and `crates/vox-tui/tests/agent_hook_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/agent_hook_proof.rs` no longer exists.

### RP-35 — Two agent sessions and an operator converse in one room, through the shipped binary
**Why.** `crates/vox-tui/tests/agent_rehearsal_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that two agent sessions and an operator converse in one room, goes red under a mutation that breaks it, and `crates/vox-tui/tests/agent_rehearsal_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/agent_rehearsal_proof.rs` no longer exists.

### RP-36 — vox daemon runs with no terminal, through the shipped binary
**Why.** `crates/vox-tui/tests/daemon_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that vox daemon runs with no terminal, goes red under a mutation that breaks it, and `crates/vox-tui/tests/daemon_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/daemon_proof.rs` no longer exists.

### RP-37 — A file crosses between two agents, through the shipped binary
**Why.** `crates/vox-tui/tests/file_exchange_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a file crosses between two agents, goes red under a mutation that breaks it, and `crates/vox-tui/tests/file_exchange_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/file_exchange_proof.rs` no longer exists.

### RP-38 — The unskippable verbs work while a daemon runs, through the shipped binary
**Why.** `crates/vox-tui/tests/it_just_works_with_a_daemon_running.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that the unskippable verbs work while a daemon runs, goes red under a mutation that breaks it, and `crates/vox-tui/tests/it_just_works_with_a_daemon_running.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/it_just_works_with_a_daemon_running.rs` no longer exists.

### RP-39 — The OpenCode plugin works with a real model, through the shipped binary
**Why.** `crates/vox-tui/tests/opencode_plugin_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that the OpenCode plugin works with a real model, goes red under a mutation that breaks it, and `crates/vox-tui/tests/opencode_plugin_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/opencode_plugin_proof.rs` no longer exists.

### RP-40 — An urgent message from another node interrupts its addressee, through the shipped binary
**Why.** `crates/vox-tui/tests/remote_interrupt_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that an urgent message from another node interrupts its addressee, goes red under a mutation that breaks it, and `crates/vox-tui/tests/remote_interrupt_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/remote_interrupt_proof.rs` no longer exists.

### RP-41 — vox room speaks to a node it did not start, through the shipped binary
**Why.** `crates/vox-tui/tests/room_verbs_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that vox room speaks to a node it did not start, goes red under a mutation that breaks it, and `crates/vox-tui/tests/room_verbs_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/room_verbs_proof.rs` no longer exists.

### RP-42 — A room-bound service is reached through the overlay, through the shipped binary
**Why.** `crates/vox-tui/tests/service_rehearsal_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a room-bound service is reached through the overlay, goes red under a mutation that breaks it, and `crates/vox-tui/tests/service_rehearsal_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/service_rehearsal_proof.rs` no longer exists.

### RP-43 — Two agents split work, through the shipped binary
**Why.** `crates/vox-tui/tests/work_board_proof.rs` drives the shipped `vox` but also runs nodes in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that two agents split work, goes red under a mutation that breaks it, and `crates/vox-tui/tests/work_board_proof.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-tui/tests/work_board_proof.rs` no longer exists.

### RP-44 — A .vox name for a room this machine never joined is refused at the proxy, through the shipped binary
**Why.** `crates/vox-core/tests/node_m17_up_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a .vox name for a room this machine never joined is refused at the proxy, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m17_up_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m17_up_gate.rs` no longer exists.

### RP-45 — A wedged client cannot stall a node and is told it lagged, through the shipped binary
**Why.** `crates/vox-core/tests/node_m19_fanout_gate.rs` runs every node in-process, so it is not proof that a person running `vox` gets this.
**Acceptance.** A proof that drives only the shipped `vox` shows that a wedged client cannot stall a node and is told it lagged, goes red under a mutation that breaks it, and `crates/vox-core/tests/node_m19_fanout_gate.rs` is deleted.
**Validation.** The new proof is green on `main` and red under its mutation; `crates/vox-core/tests/node_m19_fanout_gate.rs` no longer exists.
