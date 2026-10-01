# Gate audit: can each blocking test tell a broken product from a broken test?

Tree: `/opt/vox/.claude/worktrees/v0210`, branch `integrate/v0.2.10` at `69616f40`. The audit was read-only: nothing was built, run or edited.

Every test was judged against the decider's rules:
- "If I cannot tell the difference between a broken product and a broken test, it's not a valid test."
- A check that can never fail is fake.
- Only proofs that drive the shipped `vox` binary count.

## What was read

**CI and gate configuration**, read in full: `.github/workflows/ci.yml`, `.github/workflows/release.yml` and `scripts/release-gate.sh`.

**Test sources:**
- All 152 files in `crates/vox-tui/tests/*.rs` (42,211 lines, 157 test functions). Seven parallel readers each took a disjoint slice and read every file in it in full.
- Support files, read in full: `crates/vox-core/tests/support/watchdog.rs` and `crates/vox-tui/tests/support/world.rs`.
- Support files, read in the parts the proofs call: `relay.rs`, `room.rs`, `sync_pair.rs`, `port_forward.rs`, `pty_driver.rs`, `syscalls.rs`, `nat.rs`, `previous_release.rs`, `raw_sync.rs`, and the pty drivers `tui_member_names.py`, `tui_room_truth.py` and `tui_lock_unlock_join.py`.

**Spot-checked against source myself** before writing: the opencode silent returns, `failure_reasons:537`, `a_rooms_own_anchor:150`, `a_first_direct:135`, `relay.rs circuits()`, `sync_pair.rs texts()`, `a_trust_check rss()`, the `shell_setup` zsh claim, the watchdog inner helper, and R41 report-only.

**Out of the test sets:**
- `#[test]` in `crates/*/src`: none.
- Doctests: no runnable doctest blocks were found in `src`.
- `vox-core/tests`: holds only `support/`, no test targets.
- `vox-agentcomms` and `vox-test-interpose` have no tests.

### What runs where

| Code | Invocation | Where |
|---|---|---|
| **D** | `cargo test --workspace --no-fail-fast` (debug; non-ignored only) | CI `build-test` on ubuntu and macOS; release-gate "debug suite" |
| **R** | `cargo test --release --workspace --no-fail-fast -- --ignored --skip r40_ --skip r41_` | CI `build-test` on ubuntu and macOS; plus release-gate `-- --ignored` (no skips) |
| **R-mac** | Same as R, but the file is `#![cfg(target_os = "macos")]` or the fn is `#[cfg(macos)]` | Compiles to **0 tests on ubuntu, silently**; runs on macOS CI and the release gate |
| **T** | `cargo test --release --workspace -- --ignored r40_ r41_`, with `VOX_PERF_REPORT_ONLY=WAN` on macOS | CI `transport-gates` on ubuntu and macOS; plus the release gate |

CI-wide environment: `VOX_PROOF_ALLOW_UNPROVEN=opencode`. The release gate unsets that and the `VOX_PERF_*` knobs.

**Run coverage.** Only 5 tests are not `#[ignore]`d, and they run in D only: `attach_names_its_error`, `install_sh`, `shell_setup`, `skill_cli` and `update`, plus 2 fns in `nothing_local_leaks`. Every other test runs in R or T. No `#[ignore]`d test is left out of every run.

**Filters.** The only fns that match `r40_` or `r41_` are the 4 perf fns, so the substring filters are correct.

**Ignore counts.** Some files show more ignore matches than tests: `room_verbs`, `service_rehearsal`, `tunnel_honesty` and three others. Those extra matches are doc comments that contain "`#[ignore]`d". No test is hidden.

## Summary

| Class | Count |
|---|---|
| VALID | **5** |
| FIXABLE | **130** |
| INVALID | **22** |
| Total | 157 |

VALID means every red path names its side. The 5 are:
- `atrest_argon2id_floor`
- `attach_names_its_error`
- `cross_process_join`
- `no_consent_without_a_ring_entry`
- `nothing_local_leaks::an_accept_error_does_not_end_the_control_socket`

Most FIXABLE rows share one set of shared-harness red paths that don't say which side failed (section H below). Fixing about ten lines in `world.rs`, `room.rs`, `sync_pair.rs` and `relay.rs` would remove the generic finding from roughly 110 rows. What remains is the test-specific paths listed per row.

### The ten most important findings

1. **A security defect is reported as "CANNOT MEASURE".**
   - **Where:** `failure_reasons_proof.rs:537-540`.
   - **What:** If an untrusted guest's bytes come back through `vox forward`, the host has carried an untrusted identity to its service. The loop at `:524-535` then times out with `"CANNOT MEASURE (7): an untrusted guest's connection went through"`. The decider would read that red as broken apparatus.
   - **Fix:** a PRODUCT verdict that quotes the forward and host transcripts.
2. **Four live-model proofs are a silent `ok` on CI.**
   - **Where:** `opencode_plugin:186-201`, `tracker_rehearsal:413-415` and `agent_rehearsal:178-184` each do `assert!(allow_unproven("opencode")); return;`. `an_agent_wake::live:686-692` and `drain_self_filter:145-152` skip their live halves the same way.
   - **What:** Nothing is printed, and libtest shows `ok` on both runners. The gap is the decider's accepted ADR-018 gap, but the CI log cannot show that the test proved nothing.
   - **Fix:** print `UNPROVEN (excused): …` before returning, or use a skip the log can see.
   - **On the release gate:** `agent_rehearsal:146-155` never checks `opencode run`'s exit status. An expired credential, a rate limit or a network fault goes red as "alice's model did not read its assignment", which reads as a product verdict for an apparatus fault.
3. **Shared-harness failures look like product failures, which turns both negative and positive claims vacuous.**
   - `sync_pair.rs:391-401`: `Reader::texts` returns `Vec::new()` on any IPC error. A "was never read" claim, such as `an_entry_that_was_not_asked_for:131`, passes when the read socket is broken. A delivery claim reads the same failure as "sync is slow".
   - `relay.rs:118-126`: `circuits()` returns `.unwrap_or(0)` when no `"peer(s) connected"` status line was ever parsed. So `assert_direct` and every `Split::None` control pass if the anchor's status line disappears or changes format. That covers `perf_r40_relayed::r40_control…`, `a_circuit_carries…::without_the_split…` and others.
4. **A silent false green in a blocking gate.**
   - **Where:** `a_rooms_own_anchor_is_redialled_proof.rs:150-155` sends `kill -STOP <host>` and discards the result (`let _ =`).
   - **What:** If the stop does not take, the host republishes the guest's record itself, and the assertion at `:205` passes without measuring the claim.
   - **Related silent passes:**
     - `a_trust_check…:42-51`: `rss()` maps unparseable `ps` output to 0, so the memory bound always passes.
     - `two_fetches_at_once…:465-482`: `lsof`'s exit status is never checked.
     - `two_members_posting_at_once…:114,117`: `busy_refused` uses `unwrap_or(0)`.
5. **A gate that hangs instead of going red.**
   - **Where:** `a_first_direct_connection_is_prompt_proof.rs:135`. The loop guard is `answered.duration_since(ready) < GIVE_UP * 2`, but `answered` never changes inside the loop.
   - **What:** The `continue`s at `:138-139` and `:142-143` skip the only time-based `break` (`:150`). A proxy that keeps refusing spins until the 600 s watchdog. The watchdog then prints "It is hung, not slow … the runtime is not making progress" and never says the product refused.
6. **Twenty INVALID tests decide on a wall-clock bound and never measure the apparatus's own timing**, on runners CI itself documents as stalling (R41 WAN is report-only on macOS for exactly that reason).
   - **Worst cases:**
     - R40 direct: 250 ms per sample across 25 samples, including process spawn.
     - `a_post_answers_promptly`: p95 under 100 ms for a whole spawned `vox room post`; it was already red once on ubuntu at 148 ms.
     - `simultaneous_posts`: 250 ms.
     - `a_trust_check`: 1 s and 150 ms, under 32 Argon2id clients the test starts itself.
     - R42 direct, punch and relay, plus the 150 ms restart bound in R42 relay.
     - `a_dead_member`: 1 s.
   - **Coverage:** none of these properties is proved anywhere else, so deleting the tests would lose them.
   - **Fix:** a same-clock apparatus control (a timed no-op `vox --version` spawn, the poll loop's own maximum gap, or emulator lateness) that turns an over-budget apparatus into CANNOT MEASURE. Where counters already exist, assert the counter: P2 `skipped_at_cap`, P8 retries, the R42-relay supersede count.
7. **Short TTLs race the harness's own latency, and a slow runner becomes a product red.**
   - **Where:**
     - `work_board_proof.rs:150-165`: a 2 s TTL, then `until` polls by spawning `vox` processes.
     - `work_renew_proof.rs:85-98`, `:133-136` and `:150-190`.
     - `work_handoff_proof.rs:294-300`: a 3 s TTL.
     - `claim_lost_proof.rs:68-71`: a 2 s TTL.
   - **What:** Every overrun reads as "a live ttl claim must still bind" or "`again` should still be held". `work_board` was already pulled from the gate once as flaky.
   - **Fix:** measure the elapsed time since the claim, and fail CANNOT MEASURE when propagation took longer than the TTL.
8. **Product failures are labelled as apparatus.** This inverts the attribution, so a real defect would be excused.
   - `a_retrust…:232`: bob reading carol before trust is a confidentiality breach, but it is labelled CANNOT MEASURE.
   - `a_join_is_not_hostage:321-323`: known defect #217, "authenticator invalid", becomes CANNOT MEASURE.
   - `an_agent_wake:263,310,802`: a missing wake is the defect that case (1) exists to catch.
   - `a_rollback…:129,503,537`.
   - `perf_r41:705`: `vox connect` failed.
   - `the_path_mtu:156,159`.
   - Pty drivers: `tui_member_names.py:83-99` and `tui_lock_unlock_join.py:55,63,68` send product failures (create, join or trust failed; the TUI never re-unlocked) to exit 2, APPARATUS, and the Rust side reports CANNOT MEASURE.
9. **Known product defects are retried past, so no gate can go red on them.**
   - **Where:** `sync_pair.rs:252-262`, `room.rs` (up to 6 join retries), `a_daemon_follows_its_anchor:440-456`, `a_dead_member:230-247` and `the_prekey_ring:480`.
   - **What:** These retry `vox room join`. The code's own comment says this covers "a separate, known defect": a join turned away while the host is busy admitting.
   - **Similar:** `a_consent_cut_short…:392-396` counts "killed, and bob never got the key", which is the V210-88 defect, as `keyless` and skips it rather than going red.
10. **Checks that can never fail.**
    - `shell_setup_proof.rs:161-170` `zsh.completion_loadable`: `autoload -Uz _vox` is lazy, so `print OK` runs whether or not `_vox` exists. It should be `whence -w _vox`, or call the function.
    - `tracker_rehearsal:263-272` `never_past_acceptance`: the stub tracker has no code path that sets `ReleaseReady` or `Done`.
    - `a_watchdog_abort…::inner_a_hung_gate_with_children:45-47` returns unless `VOX_WATCHDOG_PROOF_INNER` is set, so it is a green test on every `--ignored` run.
    - Always-true counters: `a_cli_failure:541,692`, `the_path_mtu:205`, `whatever_holds:157`, `adapter_stream:378` (`n == 1800`, where n is a sum of constants), and `a_relayed_pair_finds_a_direct_path:188`.
    - R41's WAN link on macOS CI is report-only (`perf_r41:784-786,793,811`): it is measured and printed, and it also skips its own fidelity assert. The 10 Gbit/s and Wi-Fi links are `gated: false` on every runner. Separately, `VOX_PERF_ONLY` set to a value that matches no link measures nothing and passes (`:781`).

### Other cross-cutting findings

- **The watchdog's abort text misattributes.** `watchdog.rs` `fire()` always says "It is hung, not slow … the runtime is not making progress". In a real-binary proof the test process is only waiting on its children, and a stalled runner looks the same. It should say "budget exceeded: product hang **or** apparatus stall; see the descendant dumps".
  - `a_slow_joiner…::…is_told_why` needs at least 485 s of grind inside the default 600 s budget (`watchdog::arm()`, not `arm_for`), so on a slow runner this message will fire.
- **Precondition order.** These check CANNOT MEASURE preconditions after the product claim, so an unstaged run is blamed on the product:
  - `a_hostile_entry` (`:184` after `:166/:180`; `:439` after `:421/:435`)
  - `a_crash_after_a_consent:455`
- **Staging never verified.**
  - `two_backlogs_meet:321,337` prints freeze durations but never asserts they stayed under the 30 s dead-connection line that the scenario depends on.
  - `a_member_whose_connection_died` never observes that the connection was declared dead.
  - `simultaneous_session_race` (first arm) never shows the race was forced.
  - `a_taken_first_key:390` counts any stream as evidence that the delivery path ran.
  - `every_room_and_trusted_identity_lists` never shows that paging happened.
- **Test-only knobs in the shipped binary.** These have no `cfg` gate, so the proofs exercise code paths a person never runs:
  - `VOX_TEST_ADVERTISE` (`vox-core/src/node/network.rs:85`)
  - `VOX_TEST_SOLVE_AT_LEAST_MS` (`joinstream.rs:541`)
  - `VOX_TEST_CLOCK_SKEW_MS`
  - `VOX_TEST_LOSE_HELLOS`
  - `VOX_TEST_ONE_TIME_PREKEYS`
  - the max-frame knob used by `every_room…:62`

  This is noted, not classified.
- **macOS-only proofs** compile to zero tests on ubuntu with no line in the log: `a_consent_cut_short`, `a_crash_after_a_consent`, `a_file_that_holds_the_identity`, `a_rollback_survives_a_power_loss` (3 fns), `syscall_recorder` and `a_profile…::a_vault_whose_directory_will_not_flush`.
- **`update_proof` (D) measures more than this build.** Three groups of its claims don't measure this build:
  - `install_sh.curl_*` measures curl.
  - `journey.*` and `verify.*` run the published old binary against published artifacts.

  A red in any of these is a GitHub or published-artifact fault. `published_version` returning `None` on a network failure is reported as "no stable release is published yet" (`:176`, `:463`).
- **Stale ignore strings and docs** that tell a reader the wrong thing:
  - `a_relayed_host_restart:5-11` still says "This gate is red today, on purpose".
  - `two_members_posting` says "three real daemons … 40 rounds"; the code uses 2 daemons and 60 rounds.
  - `work_handoff` says "three networked nodes"; the code uses two.
  - `a_member_relays_what_it_learned` says "run under the timing lock", but CI runs it without one.
  - `perf_r40_chat_latency:20-22` names a file that does not exist.

### H: shared-harness red paths that don't say which side failed

Rows below say "inherits H" instead of repeating these.

- `world.rs`:
  - `VoxProc::spawn_exe`: `panic!("spawn {name}: {e}")`. This is apparatus, but unlabelled.
  - `vox_once`: `.expect("run vox")`.
  - `expect_within`: the timeout `"timed out after {within:?} waiting for {what}. It said: …"` quotes the product, but cannot separate a product hang from slow setup.
  - `room_pass_file`, `World::new` and `passphrase_file`: `unwrap()`s on tempdir, `create_dir_all` and write.
  - `World::new`: `assert!(ok, "vox id …")` and `trust add` are staging asserts not labelled CANNOT MEASURE.
  - `up` and `forward`: `.expect("an address…")` / `.expect("a socket address")` on product output, with no transcript.
  - **`socks5_connect`: `.unwrap()` on every `read_exact`/`write_all`.** A proxy that closes early, which is a product failure, panics as `called Result::unwrap() on an Err value: UnexpectedEof`.
- `room.rs`:
  - `:238` sends the anchor's stderr to `Stdio::null()`, so `:251-253` "the anchor never printed its spec" has no transcript.
  - `:309` "daemon never answered" has no stderr.
  - `:384` "could not join the room" comes after up to 6 silent retries, has no CANNOT MEASURE label, and gives no output.
  - `:420-422` "the room never became readable both ways" is a precondition but not labelled.
  - `:487` `until` times out after 60 s with no stall measure.
  - `:179`, `:184`, `:186`, `:188`, `:230`, `:237`, `:240` and `:262-265`: spawn, write and wait `expect`s.
- `sync_pair.rs`:
  - `:44` `kill {sig}` assert, not labelled apparatus.
  - `:99`, `:165`, `:169` and `:217`: `expect("spawn …")`.
  - `:111-113` anchor spec, no transcript.
  - `:140`, `:179`, `:236`, `:238`, `:248`, `:267` and `:273`: staging asserts without CANNOT MEASURE.
  - `:399` swallowed IPC error (finding 3).
- `relay.rs`:
  - `:49` and `:242` unwraps.
  - `:59-81` spec parse `expect`s.
  - `:126` `circuits()` returns 0 (finding 3).
  - `:255-263` staging asserts.
  - `:355-357` and `:366` expects.
- `port_forward.rs`: `:199-207` staging asserts, and `:307-309` expects.
- `pty_driver.rs`: a driver that exits 1 from an uncaught Python exception (for example `re.search(...).group(0)` on `None`) has no verdict line. The proof then reports "stopped … by its faulthandler backstop, or from outside", which misnames a driver crash.

## Per-test table

RUNS uses the codes D, R, R-mac and T defined in "What runs where". All tests are `#[ignore]`d except those marked **(not ignored)**.

| File | Test fn | Runs | Class | Reason / exact fixes |
|---|---|---|---|---|
| a_backed_off_peer_is_retried_when_due_proof.rs | a_backed_off_peer_is_retried_when_due | R | INVALID | `:165` `read_at <= BOUND` (3 s after SIGCONT): the apparatus clock (10 ms IPC poll, SIGCONT) is never measured. `:170` `a_retried >= 2` is attributable and should become the claim. `:147-150`: u64 counter subtraction wraps in release, so a reset counter passes `>= 2`. Inherits H (sync_pair). Only proof of P8. |
| a_burst_past_the_slot_cap_is_queued_proof.rs | a_burst_past_the_slot_cap_is_queued | R | INVALID | `:298` 2 s and `:425` `LATE_BOUND` 5 s are latency bounds, measured through 40 IPC reads per pass and a `vox status` spawn per poll (`:414`). Assert `skipped == 0 && queued >= 1` (`:242`) instead. `:241` u64 wrap. `:213` `h.join().unwrap()`. Inherits H. Only proof of P2. |
| a_circuit_carries_an_ipv6_daemon_proof.rs | a_guest_on_an_ipv6_socket_reaches_its_host_through_a_relay_circuit | R | FIXABLE | Verdicts quote transcripts. Inherits H (world, relay `:49,:242,:355-357`). |
| a_circuit_carries_an_ipv6_daemon_proof.rs | without_the_split_the_same_pair_goes_direct | R | FIXABLE | `:82` `.expect("echo in the control")` gives no side and no transcript. `:87` relies on `relay.rs:126` `circuits()` returning 0 by default, so the test is vacuous if the status line is missing. Fix: distinguish "no status line" (CANNOT MEASURE) from 0. |
| a_cli_failure_tells_the_truth_proof.rs | a_cli_failure_tells_the_truth | R | FIXABLE | `:123` spawn panic, `:125` `expect("write stdin")`, `:165`/`:382` `expect("wait")`, `:220` tempdir and `:236` bind unwraps are unlabelled. `:453` ignores the tail-probe post result. `:541` `assert_eq!(claims, 5)` is always true. |
| a_cli_failure_tells_the_truth_proof.rs | a_holder_runs_without_its_control_socket | R | FIXABLE | `:563` `Command::new("id").output().unwrap()`, `:565` write and `:587` bind unwraps are unlabelled. `:692` `assert_eq!(held, 2)` is always true. |
| a_consent_cut_short_releases_nothing_before_it_proof.rs | a_consent_cut_short_at_any_commit_releases_no_post_sealed_before_it | R-mac | FIXABLE | `:392-396` counts "killed and bob never got the key" (the V210-88 defect) as `keyless` and skips it; only `MIN_KILLS` bounds this. `:355` `let _ =` discards the re-trust result. `:121-124` port bind-and-release race. `:177` `filter_map(ok())` silently drops rows. Superseded by `a_crash_after_a_consent` (duplicate). |
| a_crash_after_a_consent_still_delivers_the_key_proof.rs | a_crash_at_any_point_of_a_consent_still_delivers_the_key | R-mac | FIXABLE | `:455` checks `kills >= MIN_KILLS` only after the per-trial product asserts; it should come first. `:116-121` port race. `:173` drops unparseable rows. `:103-142` unlabelled expects. |
| a_daemon_follows_its_anchor_proof.rs | a_daemon_picks_up_an_anchor_that_moved_under_it | R | FIXABLE | `:199` "the anchor never wrote its spec" has no label or transcript. `:295` `.expect("a room id")`, `:307` `.expect("a port…")`, `:529` `expect("anchor status")`. `:440-456` retries the join 6 times, hiding a known defect (`:91-92`). |
| a_daemon_follows_its_anchor_proof.rs | a_daemon_follows_an_anchor_that_had_eight_addresses | R | FIXABLE | Same paths (shares `follow()`). |
| a_daemon_follows_its_anchor_proof.rs | a_bad_anchors_file_line_is_skipped_and_named | R | FIXABLE | Same paths. `:264-273` correctly separates the product verdict from CANNOT MEASURE. |
| a_daemon_reopens_its_rooms_proof.rs | a_restarted_daemon_holds_every_room_it_held_without_a_room_passphrase | R | FIXABLE | `:132` "never answered" does not say whether it was the first start (staging) or the restart (claim). `:195` `.expect("a room id…")` has no listing. `:60-64` kill and try_wait expects. `:110-123` unwraps. |
| a_dead_member_does_not_stall_the_room_proof.rs | a_dead_member_does_not_stall_the_room | R | INVALID | `:320` every post within `BOUND` = 1 s, and the clock includes a `vox room read` spawn per 50 ms poll (`:297`). Apparatus cost and runner stall are never measured; the defect is about 30 s, so size the bound to the mechanism or measure the read latency. `:297` ignores the read's `ok`. `:230-247` retries the join 6 times. `:132`, `:166`, `:221`, `:81` unlabelled. Only proof. |
| a_deleted_consent_counter_releases_nothing_proof.rs | a_deleted_consent_counter_releases_nothing_sealed_before_the_trust | R | FIXABLE | `:210-222` `expect("open alice's stopped store")`: a still-held redb lock panics unattributed and should be "CANNOT MEASURE: store still held". `:199` and `:260` unwraps. |
| a_displaced_relay_is_let_go_proof.rs | a_relayed_path_a_direct_one_displaced_is_let_go_after_its_grace | R | FIXABLE | `:74` `socks5_connect` unwraps (H). `:126` `None => {}` ignores refusals during the watch. |
| a_file_that_holds_the_identity_is_published_durably_proof.rs | a_file_that_holds_the_identity_is_published_durably | R-mac | FIXABLE | `:184` `!wrote && kept && opens` gives one message for three causes. `wrote` means staging was not achieved (CANNOT MEASURE); `kept`/`opens` are the product; split them. `:81-83` in-process `IdentityVault` decode unwraps. `:62`, `:165-187` unwraps. |
| a_first_direct_connection_is_prompt_proof.rs | a_first_direct_connection_completes_in_under_two_seconds | R | INVALID | `:214` is a 2 s max-of-12 bound with no emulator or stall timing. **`:135` loop can hang**: the guard uses the constant `answered`, and the `continue`s at `:138-143` skip the only `break`, so it runs to the watchdog (finding 5). Only R42-direct proof. |
| a_first_punched_connection_is_prompt_proof.rs | a_first_hole_punched_connection_completes_in_under_two_seconds | R | INVALID | `:479` is a 2 s bound; nat.rs's own forwarding lag is never measured. `:348` has the same constant guard (but `:361` breaks). `:105-109` port race. Only R42-punch proof. |
| a_first_relayed_connection_is_under_two_seconds_proof.rs | a_first_relayed_connection_completes_in_under_two_seconds | R | INVALID | `:142` (< 2 s) and `:172` `RESTART_WITHIN` 150 ms have no stall measure. Keep `:179` (superseded count) and `:185`, which are VALID mechanism asserts. `:101` labels a product echo failure "CANNOT PROVE". |
| a_fresh_process_is_taken_by_its_board_proof.rs | a_fresh_process_is_taken_by_its_board | R | FIXABLE | `:195-197` pushes an unstaged sample (no refusal) as a product failure; per the doc it should be CANNOT MEASURE. `:172` 7 s `CURED_WITHIN` has no stall measure. `:74-80` port race. |
| a_hostile_entry_does_not_stop_a_room_proof.rs | an_unclassifiable_entry_is_refused_and_the_room_syncs_on | R | FIXABLE | `:184` precondition `refused >= 1` comes after the claims at `:166`/`:180`. `:76` `reads()` treats a failing `vox room read` as "not yet". Inherits H (sync_pair). |
| a_hostile_entry_does_not_stop_a_room_proof.rs | a_stripped_payload_is_refused_and_the_real_entry_arrives | R | FIXABLE | `:254-281` STOP/CONT through `sync_pair:44` unlabelled. `:76` swallows read failures. `:290` precondition is worded as a claim. |
| a_hostile_entry_does_not_stop_a_room_proof.rs | a_message_lost_to_the_old_row_ids_is_reported | R | FIXABLE | `:349` ignores the read's `ok`, so `kept = 0` passes `:363` and is then misread at `:367`. |
| a_hostile_entry_does_not_stop_a_room_proof.rs | a_misbound_governance_entry_is_refused_and_the_room_syncs_on | R | FIXABLE | `:439` precondition comes after the `:421`/`:435` claims. `:76`. |
| a_join_is_not_hostage_to_one_member_proof.rs | a_room_is_still_joinable_when_the_first_member_tried_is_offline | R | FIXABLE | `:321-323` and `:274-278` turn product defect #217 ("authenticator invalid") into CANNOT MEASURE. `:114` ignores `ok`. `:253` expect. `:87-96` unwraps. |
| a_join_outlives_its_displaced_path_proof.rs | a_join_outlives_its_displaced_path | R | FIXABLE | `:80`/`:87` tempdir and `create_dir` unwraps. `:156` `try_wait().unwrap()`. `:159-164` 480 s `JOIN_WITHIN`: add the grind-floor elapsed time and circuit state so "guest hung" can be told from "box stalled". Inherits H. |
| a_large_room_reads_whole_proof.rs | a_room_past_one_frame_of_history_reads_whole | R | FIXABLE | `:76` quotes only the exit code; quote stderr. `:98-99` `assert_eq!` dumps 5 MiB with no stderr. `:112` bare unwrap. `:133-134` spawn tail. `:145-159` the 60 s tail deadline breaks silently and then fails as the bare `:168` `assert_eq!`. `:153` `expect("NDJSON row")` without the line. |
| a_lock_and_unlock_keep_the_network_proof.rs | a_lock_and_unlock_back_to_back_leave_the_node_networked | R | FIXABLE | **`tui_lock_unlock_join.py:55,63,68` label "the TUI never unlocked / said LOCKED" as APPARATUS (exit 2), and `:205` turns that into CANNOT MEASURE, which is a product failure.** `:165` guesses the room id from a token. `:151` `vox id` unlabelled. |
| a_lock_stops_a_join_in_flight_proof.rs | a_join_in_flight_when_the_node_locks_does_not_complete | R | INVALID | Per the doc at `:21`, the deciding check is `:291` `took < ANSWERED` (10 s), timed with the daemon under SIGSTOP and a pty TUI and no apparatus timing. `:285` and `:289` quote no transcript. Time the TUI's lock acknowledgement and add a same-clock control. Only proof. |
| a_long_room_reopens_proof.rs | a_room_past_a_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all | R | FIXABLE | `:133`, `:207-292` staging unlabelled. `:228` guesses the room-id token. `:251`/`:273` counts carry no stderr. `:309-318` report-only count (asserted by `a_newcomer_reads_the_whole_history`). |
| a_member_of_one_room_is_not_served_another_proof.rs | a_member_of_one_room_is_not_served_another_through_the_shipped_daemon | R | FIXABLE | `:101` "never answered" has no transcript. `:189` `sleep(3)` hopes staging happened instead of observing it. `:71-77`/`:200` `free_port` race. `:219` expect has no side. `:236`/`:273` "CONTROL failed" is not CANNOT MEASURE and has no transcript. |
| a_member_reads_only_what_follows_trust_proof.rs | posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read | R | FIXABLE | `:193-311` staging unlabelled. `:199` expect. `:380-395` arm A/B `assert_eq!` omit `daemons()`. |
| a_member_relays_what_it_learned_proof.rs | a_member_relays_what_it_learned | R | FIXABLE | `:248` 5 s after carol's SIGCONT: record when carol's socket first answers, so a stall is not blamed on bob. The ignore string asks for the timing lock, which CI does not use. Inherits H. |
| a_member_that_just_joined_is_not_refused_proof.rs | a_member_that_just_joined_is_not_refused_by_its_anchor | R | FIXABLE | The race is sampled, not forced: the doc at `:31-33` reports a single-path mutant green 2 of 2. `:249-252` 60 s under self-made `yes` load, with no transcript. `:88-94` `Load::drop` never checks the `yes` processes are gone. `:145`, `:178-241` unlabelled. |
| a_member_trusted_while_unreachable_proof.rs | a_member_trusted_while_unreachable_reads_the_posts_made_meanwhile | R | FIXABLE | `:228`/`:322` bare `assert!(ok)`. `:333-340` the deciding reds quote nothing, though `Daemon.1` captures the output; print it. `:147-151` unlabelled. |
| a_member_whose_connection_died_is_synced_again_proof.rs | a_member_whose_connection_died_is_synced_again | R | INVALID | `:289` 10 s `BACK_WITHIN` (fix about 0 s against about 20 s without) has no apparatus timing. The premise "connection declared dead" is never observed (`:48`). Only proof. |
| a_new_member_is_seen_promptly_proof.rs | a_member_who_joins_through_another_is_seen_by_the_third_within_seconds | R | INVALID | `:249` `seen <= 3 s` includes a `vox room roster` spawn per 100 ms poll, with no baseline. `:248`/`:249` carry no stderr (it is in `.err` files that are never read). Only proof. |
| a_newcomer_reads_the_whole_history_proof.rs | a_newcomer_trusted_before_every_post_reads_all_of_them | R | FIXABLE | `:222-288` staging unlabelled. `:243` guesses the token. `:329` omits the daemon stderr that `:321` includes. |
| a_node_dials_only_what_it_can_reach_proof.rs | a_guest_bound_to_v6_loopback_never_dials_an_ipv4_mapped_candidate | R | FIXABLE | `:117` `socks5_connect` (H). The deciding red at `:161` is good. |
| a_node_dials_only_what_it_can_reach_proof.rs | a_host_bound_to_v6_loopback_advertises_no_address_it_does_not_listen_on | R | FIXABLE | `:231-244` unwraps. `:343`/`:345` expects. `:347` socks (H). `:396` is good, with a control at `:390`. |
| a_pair_reads_each_other_after_a_restart_proof.rs | the_joiner_is_read_again_after_the_responder_restarts | R | FIXABLE | `:139-408` staging unlabelled. `:262` `b32_decode().unwrap()`. `:289` expect. `:435` is good. |
| a_pair_reads_each_other_after_a_restart_proof.rs | the_responder_is_read_again_after_it_restarts | R | FIXABLE | Same paths. |
| a_peer_that_serves_nothing_is_paced_proof.rs | a_peer_that_serves_nothing_is_paced | R | FIXABLE | `:102-110` deciding reds: add `last` and `alice_d.transcript()`. A stall can only produce a false green. Inherits H. |
| a_post_answers_promptly_while_a_peer_posts_proof.rs | a_post_answers_promptly_while_a_peer_posts | R | INVALID | `:372-380` p95 ≤ 100 ms and max ≤ 500 ms over whole spawned `vox room post` processes, with no idle-room or no-op-spawn baseline; the doc at `:14` records a 148 ms ubuntu red. `:363-371` publish counts are VALID. |
| a_profile_that_was_not_made_can_be_made_again_proof.rs | a_store_that_cannot_be_opened_leaves_no_half_made_identity | R | FIXABLE | `:174` `create_dir_all.unwrap()` and `:134` spawn expect are unlabelled. |
| a_profile_that_was_not_made_can_be_made_again_proof.rs | an_identity_made_over_a_leftover_store_unlocks | R | FIXABLE | `:237` unwrap. `:263` `assert_eq!(aside, 1)` should list the directory. |
| a_profile_that_was_not_made_can_be_made_again_proof.rs | a_vault_that_cannot_be_written_is_named_and_leaves_nothing | R | FIXABLE | `:307-346` reds quote no `o.stderr`. `:274-336` fs unwraps. |
| a_profile_that_was_not_made_can_be_made_again_proof.rs | a_vault_whose_directory_will_not_flush_leaves_nothing | R-mac (fn cfg) | FIXABLE | `:353-441` unwraps and expects. `:411-415` red has no `said`. |
| a_received_message_survives_a_post_after_restart_proof.rs | a_received_message_survives_a_restart_a_post_and_a_restart | R | FIXABLE | `:59-65` "did not leave within 30s" has no daemon stderr. `:57`/`:61` expects. `:166-207` staging unlabelled. `:185` expect. |
| a_relayed_host_restart_is_reached_again_proof.rs | a_relayed_host_that_restarts_is_reached_again_through_the_same_forward | R | INVALID | `:141` at most 10 s across 5 trials, with no apparatus timing. **The doc at `:5-11` says "red today, on purpose"**, which contradicts `:18-20`. `:89`/`:98` bare `assert_eq!`. Only proof. |
| a_relayed_pair_finds_a_direct_path_proof.rs | a_relayed_pair_finds_a_direct_path_once_one_becomes_possible | R | FIXABLE | `:188` is always true (`:156` records only within the bound). `:158` `socks5_connect` unwraps inside the retry loop (H). `:107` unlabelled. |
| a_retrust_does_not_inherit_a_withdrawn_key_proof.rs | a_retrust_does_not_inherit_a_withdrawn_key | R | FIXABLE | **`:232` labels a confidentiality breach (bob reads carol before trust) CANNOT MEASURE.** `:265-268` labels a delivery failure CANNOT MEASURE. `:219` bare `assert!(ok)`. `:270` has no transcript. `:153` kill unlabelled. `:53-58`, `:160`, `:202` expects. |
| a_rollback_survives_a_power_loss_proof.rs | a_rollback_leaves_a_runnable_vox_whatever_instant_the_power_goes | R-mac | FIXABLE | `:129-133` labels "rollback did not restore" (product) CANNOT MEASURE. `:112` expect. `:141` unwrap. |
| a_rollback_survives_a_power_loss_proof.rs | an_interrupted_rollback_is_finished_by_the_next_one | R-mac | FIXABLE | Boilerplate: `:247`, `:286-288`, `:323`, `:349` unwraps and expects. |
| a_rollback_survives_a_power_loss_proof.rs | the_recovery_path_is_bounded_durable_and_complete | R-mac | FIXABLE | `:417`/`:451` 20 s bounds have no apparatus timing. `:503-504`/`:537-538` label a failed rollback (product) CANNOT MEASURE. `:576-591` `pgrep -f "sleep 613"` kills by pattern, machine-wide. |
| a_room_admits_the_passphrase_and_authors_decide_readers.rs | a_room_admits_the_passphrase_and_each_author_decides_who_reads_them | R | FIXABLE | Minor: `:154`, `:164`, `:204` expects; `:273` `.expect("a room id")` without the listing. |
| a_room_not_on_the_board_is_named_proof.rs | a_join_to_a_board_without_the_room_names_the_board_and_the_remedy | R | FIXABLE | `:63`/`:66` unwraps. `:104` precondition not labelled. Inherits H. |
| a_rooms_own_anchor_is_redialled_proof.rs | a_rooms_own_anchor_is_redialled_after_it_restarts | R | FIXABLE | **`:150-155` `let _ = kill -STOP` is unchecked, so `:205` can go green without measuring (finding 4).** `:215` CONT unchecked. `relay.rs:366` unlabelled. 15/20 s bounds have no apparatus timing. |
| a_second_joiner_is_not_locked_out.rs | two_joiners_back_to_back_both_get_in_promptly | R | FIXABLE | Minor: `:96` unwrap and `:160` expect. The bound uses the product's own step timings (good). |
| a_shared_anchor_is_dialled_at_every_rooms_address_proof.rs | a_shared_anchor_is_redialled_at_every_rooms_address | R | FIXABLE | `:85-90`, `:250`, `:255`, `:278` expects. `:345` labels a join failure CANNOT MEASURE. `:206-217` absorbs 5 refusals. 20 s bound has no apparatus timing. |
| a_silent_stream_cannot_stop_a_node_proof.rs | a_member_holding_silent_sync_streams_does_not_stop_the_node | R | FIXABLE | `:386-391` 5 s per post with no quiet-baseline post (the defect is about 30 s, so the margin is wide but unmeasured). `:190-192` kill unchecked. `:80-305` unwraps. |
| a_slow_joiner_gets_in_or_is_told_why_proof.rs | a_joiner_slower_than_the_old_patience_gets_in | R | FIXABLE | `:236-240` the invite's `ok` is unchecked, so an empty link is reported at `:272` as a product refusal. `:234` expect. |
| a_slow_joiner_gets_in_or_is_told_why_proof.rs | a_joiner_slower_than_the_patience_is_told_why | R | FIXABLE | At least 485 s of grind inside the 600 s default watchdog: use `arm_for`. The same unchecked invite. |
| a_sync_failure_names_its_reason_proof.rs | a_sync_that_did_not_complete_says_why | R | FIXABLE | `:210` `let _ = vox_once(post)`. `:284-287` claim 3 is vacuous by the file's own doc. `:106` absence check depends on literal wording, with no positive control. `:97`, `:247` unlabelled. |
| a_taken_first_key_is_not_sent_again_proof.rs | a_taken_first_key_is_not_sent_again_after_a_restart | R | FIXABLE | `:390` control counts any stream, not the key-delivery path. `:216-218` kill unchecked. `:270-333` unwraps. |
| a_taken_first_key_is_not_sent_again_proof.rs | a_taken_first_key_is_not_sent_again_after_a_crash | R | FIXABLE | Same paths. |
| a_trust_check_does_not_stall_the_node_proof.rs | a_trust_check_does_not_stall_posts_and_reads_on_the_same_node | R | INVALID | `:222-237`: 1 s maximums and a 150 ms median slack, measured under 32 concurrent 256 MiB Argon2id clients the test starts itself, plus at least 2 spawns per sample. **`:42-51` `rss()` returns 0 when `ps` gives nothing, so the RSS bound at `:215` always passes.** Only proof. |
| a_tui_that_loses_the_create_race_names_it_proof.rs | a_tui_that_loses_the_create_race_names_it | R | FIXABLE | Boilerplate: `:42`/`:44`. Inherits H. |
| a_vox_address_cannot_stop_a_node_proof.rs | a_stranger_with_only_the_rooms_name_does_not_stop_the_node | R | FIXABLE | `:354-359` 5 s per post with no baseline. `:79-295` unwraps. `:264` expect. |
| a_watchdog_abort_leaves_nothing_running_proof.rs | inner_a_hung_gate_with_children | R | INVALID | `:45-47` returns early unless `VOX_WATCHDOG_PROOF_INNER` is set, so it is green on every `--ignored` run. It is a helper, so no property is lost; make it fail when run alone. |
| a_watchdog_abort_leaves_nothing_running_proof.rs | a_watchdog_abort_leaves_nothing_running | R | INVALID (as a product gate) | Proves `watchdog.rs`, not the product; `vox node` is only a placeholder child. Well attributed internally. Keep it as a harness self-check outside the release gate. |
| a_wholly_bad_anchors_file_is_refused_proof.rs | an_anchors_file_with_no_usable_anchor_is_refused | R | FIXABLE | Boilerplate: `:67-70`, `:106-128`, `:223`. |
| a_wrong_peer_cannot_wedge_a_dial_proof.rs | a_dial_whose_first_address_answers_as_somebody_else_goes_on_to_the_next | R | FIXABLE | Good: `:267` uses CPU-seconds to separate spin from wait. `:62-73` relay unwraps. `:193-194` probe-bind port race appears as a product timeout. |
| adapter_stream_proof.rs | a_consumer_that_lags_and_crashes_three_times_misses_nothing | R | FIXABLE (heavily) | `:173-212` bare asserts with no output. `:120`, `:125`, `:248`, `:252`, `:287-289`, `:401` expects on product output. `:301`/`:322` unwraps. `:378` `n == 1800` is always true. **`:274-277` the oracle is the same `vox_agentcomms::claim::fold` the product uses (circular).** The producer posts through in-process ipc, not `vox room post`. `:339-343`/`:405-408` preconditions not labelled. |
| agent_hook_proof.rs | the_hook_feeds_an_agent_its_room_in_either_harness_shape | R | FIXABLE | `:104` no daemon stderr. `:203-321` bare `assert!(ok)`. `:118`/`:416` expects. `:101-180` unlabelled. `hook()` at `:164` does not strip the harness session variables. |
| agent_hook_proof.rs | one_author_cannot_forge_another_and_a_backlog_is_bounded | R | FIXABLE | `:382`, `:416-420` expects on product output. |
| agent_rehearsal_proof.rs | two_agent_sessions_and_an_operator_share_one_room | R (silent on CI) | INVALID on CI, FIXABLE on the gate | **CI: `:178-184` silent `ok`.** Gate: `:146-155` never checks `opencode run`'s status, so a credential or network fault is reported as a product verdict (`:233`, `:262`, `:291`). It cannot tell "the model ignored context" from "the hook injected nothing". Inherits H (room). |
| an_agent_wake_is_safe_and_bounded_proof.rs | an_agent_wake_is_attributed_and_claims_and_loops_are_bounded | R | FIXABLE | **`:263`/`:310`/`:802` label a missing wake (the product defect under test) CANNOT MEASURE.** `:686-692` live half skipped silently on CI. `:254-506` windows of 60/10/15/20 s and `ttl 2` plus `sleep 4` have no stall measure. |
| an_anchor_stops_on_ctrl_c_proof.rs | an_anchor_stops_on_ctrl_c_when_a_tick_is_due | R | FIXABLE | `:65` 10 s bound (a 10x margin) with no stall measure. `:41` unlabelled. Inherits H. |
| an_anchor_that_restarts_is_redialled_promptly_proof.rs | an_anchor_that_restarts_is_redialled_promptly | R | FIXABLE | `:123` 10 s with no apparatus timing. `:80` `let _ = kill -INT`. `relay.rs:87-94`: a rebind failure appears as a timeout. |
| an_entry_that_was_not_asked_for_is_refused_proof.rs | an_entry_that_was_not_asked_for_is_refused | R | FIXABLE | **The negative claim at `:131` passes if `sync_pair:399` swallowed an IPC error.** `:131` has no bob transcript. Inherits H. |
| an_equivocation_is_detected_and_said_proof.rs | an_equivocation_is_caught_said_held_back_and_kept | R | FIXABLE | `:191-198` `listed()` returns empty when `vox status` fails, giving the red "does not list" at `:422-430`. `:548-557` sends pty APPARATUS/HUNG to the product arm. `:148`, `:82-161` unlabelled. |
| an_idle_node_stays_on_its_board_proof.rs | an_idle_node_stays_findable_on_its_board | R | FIXABLE | `:449-454` renewals in 5..=7 over a slept window (`:338`) whose actual length is never used; derive the range from the measured window. `:138`, `:122`. |
| an_idle_node_stays_on_its_board_proof.rs | a_round_to_one_anchor_does_not_put_off_the_others | R | FIXABLE | Same timing defect. `:398` CANNOT MEASURE is good. |
| an_ipv6_joiner_reaches_its_board_promptly_proof.rs | an_ipv6_only_joiner_reaches_its_board_within_two_seconds | R | INVALID | `:123` 2 s on the product's self-reported time, with no stall control; a descheduled process inflates it. R42 sub-claim with no other proof. `:63`/`:64` unlabelled. |
| an_ipv6_joiner_reaches_its_board_promptly_proof.rs | a_joiner_whose_address_names_only_gone_boards_reaches_its_own_within_two_seconds | R | INVALID | `:233` same 2 s bound. |
| an_unknown_control_request_says_so_proof.rs | an_unknown_control_request_says_so | R | FIXABLE | `:34`/`:36` `.expect("a frame length/body")`: a daemon that closes or stalls is a product red and should say so. `:67` has no transcript. |
| anchors_config_proof.rs | a_client_on_the_anchors_machine_needs_no_anchor_flag | R | FIXABLE | `:187`/`:190` expects. `:62`. `other_cfg` at `:168` is created and never used, so the negative control is missing. |
| atrest_argon2id_floor_proof.rs | the_vault_the_binary_writes_opens_only_under_the_adr_floor | R | **VALID** | Every red is CANNOT MEASURE or quotes parameters. Trivial unwraps at `:145` and `:174`. |
| attach_names_its_error_proof.rs | a_failed_attach_says_why_in_a_persons_words | **D (not ignored)** | **VALID** | Each red quotes the product's stderr (`:84`, `:93`, `:97`). |
| claim_lost_proof.rs | the_drain_says_once_when_a_claim_was_lost_and_why | R | FIXABLE | **`:68-71` the 2 s TTL races two `vox` spawns, and a slow runner gives a false product red.** Measure the elapsed time, or else CANNOT MEASURE. `:147`/`:171` have no context. |
| codex_trust_proof.rs | vox_trusts_its_own_codex_hook_and_nothing_else | R | FIXABLE | `:138-141`, `:166-167`, `:225`, `:237`, `:255` preconditions not labelled CANNOT MEASURE. `:86`/`:119` Codex API faults not labelled apparatus. `:229`/`:250` bare `assert_eq!`. |
| cross_process_join_proof.rs | two_agents_on_separate_processes_join_through_an_anchor_and_talk | R | **VALID** | `:279` and `:381` print the product error plus transcripts. Trivial unwraps only. |
| daemon_proof.rs | a_daemon_serves_agent_sessions_with_no_terminal_and_survives_sighup | R | FIXABLE | **`:267` sleeps 500 ms after SIGHUP before the post, so it can pass vacuously**; wait for a product acknowledgement. `Daemon::said()` (`:52`) is never used, so no red quotes the daemon (`:145`, `:238-280`). |
| daemon_shutdown_proof.rs | a_daemon_stops_on_sigterm_even_when_its_peers_have_vanished | R | FIXABLE | `:227` 10 s with no stall control. `:234` has no transcript. `:249-251` `alive()` on already-reaped pids, so pid reuse can give a false red. |
| drain_self_filter_proof.rs | a_drain_drops_only_its_own_session_on_its_own_harness | R | FIXABLE | The live half is skipped silently on CI (`:145-152`); `allow_unproven` is an exact match, so `opencode-model-miss` is not excused on CI. `:174` installs the plugin from the library constant, not the binary's output. `:222` `opencode run` status unchecked. |
| every_room_and_trusted_identity_lists_proof.rs | every_room_and_trusted_identity_is_listed_past_one_page | R | FIXABLE | Never checks that paging happened. If the test knob at `:62` is ignored, it passes. |
| failure_reasons_proof.rs | every_common_failure_names_its_cause | R | FIXABLE | **`:537-540` labels the host carrying an untrusted guest's connection (a security defect) "CANNOT MEASURE (7)" (finding 1).** `:307`, `:331`, `:336`, `:400` (no message), `:416`, `:465`, `:493` `assert!(!ok)` without `said`. `:381`. `:178` 90 s. `:91-373` unlabelled. |
| fetching_from_a_member_who_is_gone_does_not_stop_the_daemon_proof.rs | fetching_from_a_member_who_is_gone_does_not_stop_the_daemon | R | FIXABLE | `:370-375` 2 s per spawned post, with no pre-fetch baseline post timed the same way. `:189`, `:217`, `:302` have no transcript. `:107-153`, `:329`, `:348`. |
| file_exchange_proof.rs | a_file_crosses_between_two_agents_and_a_mismatch_is_refused | R | FIXABLE | `:226`/`:253` have no transcript. `:338` drops stderr. **`:382` `.expect("the collected file")`: the product said ok but wrote no file, and the red should say PRODUCT.** `:444`. |
| forward_binds_loopback_only_proof.rs | a_forward_refuses_to_bind_where_the_network_can_reach_it | R | FIXABLE | Inherits H only. `:118`. |
| install_sh_proof.rs | install_sh_installs_what_it_verified_and_refuses_what_it_could_not | **D (not ignored)** | FIXABLE | Minor. A blocked server is red ("unproven", `:452`) and can't pass silently. Unlabelled: `:194-294` including `:258` `.expect("sh ran install.sh")`. |
| it_just_works_with_a_daemon_running.rs | the_verbs_a_person_cannot_skip_work_while_a_daemon_holds_the_profile | R | FIXABLE | `:246-250` load-bearing claim 3 quotes nothing. **`:271-275` ignores the second `trust list`'s `ok`, so "entry gone" passes on a dead daemon.** `:312`. |
| no_consent_without_a_ring_entry_proof.rs | joining_grants_nothing_and_only_the_ring_releases_a_key | R | **VALID** | Controls are CANNOT MEASURE. `:364` guards against a zero read from a dead daemon. `:373` names the product. Setup unwraps only. |
| node_wide_blobs_are_sealed_by_the_vault_proof.rs | node_wide_blobs_are_sealed_by_the_vault | R (fetches v0.2.9) | FIXABLE | `:215`, `:220`, `:224` in-process reader unwraps can't say "product wrote a bad file" vs "reader incompatible". `:237`/`:270`. `:148` no transcript. `:756-759` plant unwraps. |
| nothing_local_leaks_to_another_user_proof.rs | an_offer_and_a_get_are_withdrawn_however_the_verb_ends | R | FIXABLE | `until` at `:302-316` labels product propagation ("offer to reach bob", `:441`) CANNOT MEASURE. `:780-784` quote no output. `:808`, `:820`, `:844` lsof unwraps. `:397`. |
| nothing_local_leaks_to_another_user_proof.rs | the_control_socket_is_private_and_a_client_refuses_one_that_is_not_its_own | R | FIXABLE | `:969` and `:970-974` mode/uid asserts have no message. `:1052-1056` quotes nothing. |
| nothing_local_leaks_to_another_user_proof.rs | an_accept_error_does_not_end_the_control_socket | R | **VALID** | Staging is CANNOT MEASURE (`:1112`, `:1120`). The verdict quotes output (`:1137`). |
| nothing_local_leaks_to_another_user_proof.rs | shell_setup_keeps_the_rc_files_symlink_and_mode | **D (not ignored)** | FIXABLE | `:1200` compound assert has no message. `:1167`. Overlaps `shell_setup_proof`. |
| nothing_local_leaks_to_another_user_proof.rs | a_room_passphrase_is_never_taken_from_argv_or_the_environment | **D (not ignored)** | FIXABLE | `:1266-1270` the control passes on any non-refusal failure (no identity, no room `aaaa`), so it never shows the file form gets past the check; and a refusal there is product, not CANNOT MEASURE. |
| one_want_cannot_stop_a_room_proof.rs | an_absurd_want_does_not_stop_the_room_it_names | R | FIXABLE | `:375`/`:386` 5 s per spawned post; use the 50 staging posts (`:249-255`) as the baseline. `:395` does not say whether the victim or raw_sync hung. `:357`/`:396`/`:283`. |
| opencode_plugin_proof.rs | a_real_model_reads_the_room_through_the_opencode_plugin | R (silent on CI) | INVALID on CI, FIXABLE on the gate | **CI: `:186-201` silent `ok`.** Gate: `:358-363` "the room never reached the model" doesn't separate the plugin injecting the codeword from the model failing to repeat it; assert the plugin log first. `:343`. |
| perf_r40_chat_latency_proof.rs | r40_a_message_between_two_online_nodes_arrives_in_under_a_second_direct | T | INVALID | `:323` every one of 25 samples under 250 ms, timed from a `vox room post` spawn. The only apparatus signal is `uptime` (`:204`, `:316`). The network figure at `:314` is printed, not asserted. Fix: per-sample no-op spawn timing, and assert the network time. `:20-22` names a nonexistent file. Only proof of R40-direct. |
| perf_r40_relayed_chat_proof.rs | r40_a_message_between_two_online_nodes_arrives_in_under_a_second_relayed | T | INVALID | `:327` 1000 ms on every sample, spawn included, with no apparatus timing. The relay assert (`relay.rs:131`) is good. Only proof of R40-relayed. |
| perf_r40_relayed_chat_proof.rs | r40_control_without_the_split_the_same_pair_is_direct | T | FIXABLE | **`relay.rs:126` `circuits()` defaults to 0, so the control is vacuous if the status line is missing.** It burns 25 samples it never asserts on. |
| perf_r41_tunnel_throughput_proof.rs | r41_a_tunnel_does_not_throttle_the_link_it_runs_over | T | FIXABLE (part fake) | **macOS CI: `VOX_PERF_REPORT_ONLY=WAN` sets `gated=false` (`:784-786`), so WAN can never go red and its fidelity assert (`:793`) is skipped.** 10G and Wi-Fi are `gated:false` everywhere (`:83`, `:90`). `VOX_PERF_ONLY` with no match measures nothing and passes (`:781`). Fidelity is calibrated before the transfer, not during it: record shaper lateness (`:167-172`, `:262-267`). `:705` labels a product failure CANNOT MEASURE. `:469`, `:531`, `:549`, `:586`, `:590`, `:595`, `:652`, `:730` unlabelled. |
| read_render_proof.rs | a_message_cannot_forge_a_row_in_read_or_tail | R | FIXABLE | `:57` tail's stderr goes to null, so if tail dies `:117` can't say so. `:61`/`:63`. `:103`/`:124` quote nothing. Inherits H (room). |
| remote_interrupt_proof.rs | an_urgent_message_from_another_node_interrupts_its_addressee | R | FIXABLE | `:108` has no stderr. `:245`/`:249`/`:317` quote nothing. `:220`/`:305` 20/45 s windows have no stall measure. `:294` labels a registration result CANNOT MEASURE. |
| result_unread_proof.rs | a_result_names_the_addressed_messages_its_session_has_not_read | R | FIXABLE | Harness only (H room). `:79`. |
| revocation_rotates_the_key_proof.rs | removing_one_member_rotates_the_key_and_keeps_the_others_whole | R | FIXABLE | The in-process attacker is by design, and its escalation is proved at `:572-584`. `:330-337` CBOR unwraps should say CANNOT MEASURE. `:386`, `:323`, `:526-561`. `:497` has no stderr. |
| room_of_three_keys_proof.rs | every_member_eventually_reads_every_other_bob_joins_first | R | FIXABLE | `:141` "never answered" with a 60 s patience (room.rs needed 240 s, V210-87) and no stderr. `:176`, `:235`, `:262`. `:277` 60 s. |
| room_of_three_keys_proof.rs | every_member_eventually_reads_every_other_carol_joins_first | R | FIXABLE | Same paths. |
| room_verbs_proof.rs | vox_room_speaks_to_a_node_it_did_not_start | R | FIXABLE | `:66` no stderr. `:149`/`:195` expects. `:213`, `:217`, `:228` quote nothing. |
| service_rehearsal_proof.rs | a_room_bound_service_carries_real_bytes_through_the_real_binaries | R | FIXABLE | `:227`, `:235`, `:254` give no proxy transcript. `:460`/`:464` echo expects are product verdicts with no transcript. `:543`. `:86`, `:171`, `:189`. |
| shell_setup_proof.rs | shell_setup_gives_a_new_shell_vox_on_path_and_working_completion | **D (not ignored)** | FIXABLE | **`:161-170` `zsh.completion_loadable` can never fail (lazy autoload).** Interactive `-i` shells have no per-call timeout. `:82`, `:95`, `:103`, `:207`, `:268`. Allow-unproven is honest: a missing shell is red. |
| simultaneous_posts_never_collide_proof.rs | simultaneous_posts_never_collide | R | INVALID (timing arm) | `:246` p100 ≤ 250 ms; the 5 ms poll loop's own lateness is never measured (`:154-182`). `:242` `busy_refused == 0` is VALID. Coverage of no-collide: `two_members_posting_at_once`. |
| simultaneous_session_race_proof.rs | two_members_who_open_sessions_at_once_converge_and_read_each_other | R | FIXABLE | `:271`, `:316`, `:322` bare `assert!(ok)`. The race being forced is never verified in this arm. `:256`, `:84-140`. |
| simultaneous_session_race_proof.rs | two_members_whose_hellos_are_both_lost_still_converge_and_read_each_other | R | FIXABLE | Same paths. `:337` CANNOT MEASURE is good. |
| skill_cli_proof.rs | every_verb_and_flag_the_skill_names_exists_in_the_cli | **D (not ignored)** | FIXABLE | Runs the binary. `:183-187` discards the failing `--help` output, so `:190` doesn't quote vox. `:49`. |
| syscall_recorder_sees_the_shipped_binary_proof.rs | the_recorder_sees_what_the_shipped_binary_does | R-mac | FIXABLE | An apparatus self-check. `:82-97` reds don't separate "the interposer missed it" from "vox stopped doing it". `syscalls.rs` `recorded` `unwrap_or_default()` turns a missing log into "saw nothing". |
| the_path_mtu_follows_the_socket_buffer_proof.rs | a_process_reports_the_1452_ceiling_exactly_when_its_buffer_is_short | R | FIXABLE | `:205` `checked == 3` is always true. `:156`/`:159` label a broken forward (product) CANNOT MEASURE. The always-8192 mutant stays green on macOS (`:49-51`). |
| the_prekey_ring_is_kept_up_while_the_node_runs_proof.rs | a_running_node_rotates_its_signed_prekey | R | FIXABLE | `:148`, `:162`, `:181`, `:194`, `:277` unlabelled. |
| the_prekey_ring_is_kept_up_while_the_node_runs_proof.rs | a_session_started_before_a_rotation_completes_after_it | R | FIXABLE | `:377`, `:384`, `:400` unwraps. `:419` labels "host never rotated" (product) CANNOT MEASURE. |
| the_prekey_ring_is_kept_up_while_the_node_runs_proof.rs | sessions_get_one_time_prekeys_past_the_whole_pool | R | FIXABLE | `:480` labels a join failure CANNOT MEASURE after 4 hidden retries. |
| the_tui_shows_the_room_truthfully_proof.rs | the_tui_shows_the_room_truthfully_and_consents_to_the_member_chosen | R | FIXABLE | An uncaught exception in `tui_room_truth.py` (`.group(0)`, `.split()[0]`) exits 1 with no verdict and is misreported as a faulthandler or outside stop (`:95-101`). `:105` "HUNG at" names no side. |
| tracker_rehearsal_proof.rs | workers_do_work_and_the_tracker_never_mistakes_an_observation_for_a_verdict | R (silent on CI) | INVALID | **CI: `:413-415` silent `ok`.** `:263-272` `never_past_acceptance` can never fail. Most asserts (`:538-761`) are on the test's own stub state, and every `w.turn` result is discarded (`let _ =`), so a red can't separate model, product and stub. `:789` bare assert. The work contract is covered by the `work_*` proofs; the stub's rules are not product. |
| trust_before_join_proof.rs | a_trusted_joiner_reads_what_the_host_posts_right_after_the_join | R | FIXABLE | `:246-251` bare `assert!(post.0)`. `:131`, `:182`, `:218`, `:242`. `:254` is good. |
| tui_member_names_proof.rs | the_tui_names_a_trusted_member_by_name_and_anyone_else_by_fingerprint_marked | R | FIXABLE | **`tui_member_names.py:83-99` sends product failures (create, join, trust, roster) to APPARATUS, which gives CANNOT MEASURE (`:35`).** Uncaught exceptions at `py:86-88` are misreported at `:36`. `:46` "hung" names no side. |
| tunnel_honesty_proof.rs | a_forward_carries_a_new_connection_after_its_host_restarts | R | FIXABLE | `:60` step-1 expect should be CANNOT MEASURE with a transcript. `:97`. |
| tunnel_honesty_proof.rs | removing_a_service_cuts_its_live_sessions_within_a_second | R | FIXABLE | `:141` 1 s bound with no apparatus measure; keep reading and report "cut late at X s" vs "never cut". `:116-124`. |
| tunnel_honesty_proof.rs | a_backend_reset_reaches_the_far_client_as_a_reset | R | FIXABLE | `:181` ambiguous side. `:169`. `world.rs resetting_service` unwraps in a spawned thread, where a panic doesn't fail the test. |
| tunnel_honesty_proof.rs | a_refused_forward_resets_the_application_and_says_why | R | FIXABLE | Minor: `:205`. |
| tunnel_honesty_proof.rs | a_refused_socks_connect_is_refused_in_the_reply_and_says_why | R | FIXABLE | `:252` `socks5_connect` unwraps (H). |
| two_backlogs_meet_proof.rs | two_backlogs_that_meet_both_cross | R | FIXABLE | `:321`/`:337` freeze durations are printed but never asserted under 30 s (staging). `:145` ignores the read's status. `:135`, `:90`. |
| two_fetches_at_once_share_one_dial_proof.rs | two_fetches_at_once_share_one_dial | R | FIXABLE | `:386`/`:456` 5 s around `Command::output()` with no control. **`:465-478` lsof status unchecked, so the #249 sub-claim can be vacuous.** `:268`, `:376`, `:396`. |
| two_members_posting_at_once_are_never_refused_proof.rs | two_members_posting_at_once_are_never_refused | R | FIXABLE | **`:114`/`:117` `busy_refused` `unwrap_or(0)`, so P6 can't fail if the field is gone.** `:373` 12 s through serial spawns. `:385` u64 subtraction wraps in release. `:155`, `:189`, `:268`, `:300`. Stale ignore string. |
| two_unlocks_of_one_v1_profile_lose_no_rows_proof.rs | two_unlocks_of_one_v1_profile_lose_no_rows | R (fetches v0.2.9) | FIXABLE | `:248` vault decode and `:220-239` redb unwraps: race corruption is a product failure but unattributed. `:263` `ok()` labels a post-race failure CANNOT MEASURE. `:511` `second_migrated` is never asserted, so staging is unproven. |
| update_proof.rs | vox_update_replaces_an_install_it_owns_and_refuses_the_rest | **D (not ignored)** | FIXABLE (part out of scope) | No silent pass, and `updater_is_broken_on_this_platform` (`:239`) can only block, which is red. `install_sh.curl_*` (`:318-336`), `journey.*` (`:499-529`) and `verify.*` (`:552-575`) measure curl or published artifacts, not this build. `:176`/`:463` report a network failure as "no stable release published". `:77`, `:162` and others unlabelled. |
| vox_ids_at_once_make_one_identity_proof.rs | vox_ids_started_at_once_make_one_identity_and_report_only_it | R | FIXABLE | Minor: `:90-112` spawn and wait expects. |
| whatever_holds_a_profile_answers_for_it_proof.rs | whatever_holds_a_profile_answers_for_it | R | FIXABLE | `:157` `checked == 2` is always true. `:139`. Inherits H (relay). |
| work_board_proof.rs | two_agents_split_work_and_only_one_holds_a_contested_resource | R | FIXABLE (serious) | **`:150-165` a 2 s TTL against `until` polling by spawning `vox` (finding 7).** `:81`/`:82`. |
| work_handoff_proof.rs | a_handoff_moves_ownership_by_fingerprint_and_every_node_agrees | R | FIXABLE | **`:294-300` a 3 s TTL race.** `:216`, `:254`, `:255`, `:286`, `:290` bare asserts. `:186`, `:105`. Stale ignore string. |
| work_op_proof.rs | a_retry_is_one_operation_and_a_conflict_is_explicit | R | FIXABLE | **`:87` `.expect("NDJSON")` in the reader thread: a panic is swallowed, and `:101` blames the product.** `:173-330` unwraps. |
| work_ref_proof.rs | a_work_reference_has_one_shape_and_an_attempt_id_is_seeded_from_the_log | R | FIXABLE | Minor: `:246` `assert_eq!` has no message. `:85`/`:87`. |
| work_renew_proof.rs | a_renewal_extends_exactly_one_acquisition | R | FIXABLE (serious) | **TTL windows race the harness: `:85-98`, `:98`/`:183`, `:133-136` (`unwrap` on `None`), `:150-190`.** Bare asserts at `:83`, `:88`, `:131`, `:148`, `:157`, `:158`, `:212`. |
| work_version_proof.rs | a_worker_on_another_version_is_refused_by_name | R | FIXABLE | `:195` never asserts the old binary's claim result, so a failure is blamed on propagation at `:200`. `:62-64` reuses a cached binary without rechecking its SHA. `:96` and `:179` unlabelled. |
| wrong_passphrase_writes_nothing_proof.rs | a_wrong_identity_passphrase_writes_nothing_to_the_profile | R | FIXABLE | `:226-232` the deadline is checked only between lines, so a silent live daemon blocks until the watchdog. `:217` stderr goes to null. `:47-97`, `:221`. |

## INVALID list (22), with coverage notes

| # | Test | Why INVALID | Covered elsewhere? |
|---|---|---|---|
| 1 | a_backed_off_peer_is_retried_when_due | 3 s latency, no apparatus clock | No. Assert the existing retry counter (`:170`) and it becomes VALID. |
| 2 | a_burst_past_the_slot_cap_is_queued | 2 s and 5 s latency through spawn and IPC polling | No. Assert `skipped == 0 && queued >= 1` (`:242`). |
| 3 | a_dead_member_does_not_stall_the_room | 1 s bound including a CLI spawn per poll | No. Size the bound to the mechanism (defect about 30 s) or measure the read. |
| 4 | a_first_direct_connection_is_prompt | 2 s bound, no emulator timing, and a loop that can hang (`:135`) | No. R42-direct would be lost. |
| 5 | a_first_punched_connection_is_prompt | 2 s bound, no NAT-emulator timing | No. R42-punch would be lost. |
| 6 | a_first_relayed_connection_is_under_two_seconds | 2 s and 150 ms bounds | Mechanism asserts `:179`/`:185` can stand alone; the timing claim would be lost. |
| 7 | a_lock_stops_a_join_in_flight | 10 s answer time is the only discriminator | No. |
| 8 | a_member_whose_connection_died_is_synced_again | 10 s bound, and the premise is never observed | Partly by two_backlogs_meet (different scenario). |
| 9 | a_new_member_is_seen_promptly | 3 s including a spawn per poll | No. |
| 10 | a_post_answers_promptly_while_a_peer_posts | p95 100 ms of whole-process wall clock; already red on ubuntu | Publish-count half is VALID; tail-latency claim not covered. |
| 11 | a_relayed_host_restart_is_reached_again | 10 s across 5 trials, and the doc says "red on purpose" | No. |
| 12 | a_trust_check_does_not_stall_the_node | 1 s and 150 ms under load the test itself creates; RSS bound always passes | No. |
| 13 | a_watchdog_abort…::inner_a_hung_gate_with_children | Always green when run alone | Helper; nothing is lost. |
| 14 | a_watchdog_abort_leaves_nothing_running | Tests the harness, not the product | Keep as a harness self-check outside the gate. |
| 15 | agent_rehearsal_proof | Silent `ok` on CI; unchecked `opencode run` status on the gate | Cursor and injection parts are covered by agent_hook_proof and an_agent_wake; the live-model claim is gate-only. |
| 16 | an_ipv6_joiner…::an_ipv6_only_joiner… | 2 s self-reported, no stall control | No (R42 sub-claim). |
| 17 | an_ipv6_joiner…::a_joiner_whose_address_names_only_gone_boards… | Same | No. |
| 18 | opencode_plugin_proof | Silent `ok` on CI | Gate-only. drain_self_filter's deterministic half covers drain filtering, not the plugin path to a model. |
| 19 | perf_r40_chat_latency (direct) | 250 ms per sample including spawn; only `uptime` as an apparatus signal | No. |
| 20 | perf_r40_relayed_chat (relayed) | 1 s per sample including spawn | No; the relay-path assert itself is VALID. |
| 21 | simultaneous_posts_never_collide | p100 250 ms with an unmeasured poll loop | `busy_refused` half is VALID; no-refusal is also covered by two_members_posting_at_once. |
| 22 | tracker_rehearsal_proof | Silent `ok` on CI; one claim cannot fail; asserts on a stub | The work-state contract is covered by work_board, work_op, work_handoff and work_renew. |

**Recommendation.** Do not delete any of the timing INVALIDs: each is the only proof of its property. Give each one an apparatus clock on the same timeline, so a red can say "the runner stalled for X ms" (CANNOT MEASURE) or "the product took X ms while the apparatus took Y ms" (PRODUCT). Where a counter already exists, assert the counter instead.

## Duplicated proofs

- `a_consent_cut_short_releases_nothing_before_it` is wholly contained in `a_crash_after_a_consent_still_delivers_the_key`: same staging, and `leaks.is_empty()` is asserted in both. The first also excuses V210-88. **Delete the first.**
- `a_long_room_reopens` and `a_newcomer_reads_the_whole_history` both stage 1,500 posts plus a cold join. The first only prints the newcomer's count; the second asserts it.
- "Two members posting at once are not refused" is proved by three tests: `simultaneous_posts_never_collide` (P1), `two_members_posting_at_once_are_never_refused` (P6) and `a_sync_failure_names_its_reason`.
- F12 "every member reads the others after a join" is proved by `room_of_three_keys` (2 tests), `trust_before_join` and `simultaneous_session_race` (2 tests), and it is re-asserted by `room.rs`'s readiness wait in every room proof.
- "A second process on a held profile is refused" is proved by `wrong_passphrase` (3), `whatever_holds` (1), and the BUSY text in `vox_ids` and `two_unlocks`.
- The losing claim is named in both `work_board` (2) and `work_handoff` (1). The `--op` retry is checked in both `work_op` (1) and `work_ref` (6). Per-session cursors are checked in `agent_hook`, `agent_rehearsal` and `an_agent_wake`. Claim-lapse reporting is checked in both `claim_lost` and `an_agent_wake` (4).
- `shell_setup_keeps_the_rc_files_symlink_and_mode` overlaps `shell_setup_proof`.

## Can pass silently in CI's configuration

1. **Silent `ok` on CI.** These fail-open with no output under `VOX_PROOF_ALLOW_UNPROVEN=opencode`:
   - `opencode_plugin:186-201`
   - `tracker_rehearsal:413-415`
   - `agent_rehearsal:178-184`
   - the live half of `an_agent_wake:686-692`
   - the live half of `drain_self_filter:145-152`
2. **Always green.**
   - `inner_a_hung_gate_with_children:45-47` is always green.
   - R41's WAN link is report-only on macOS CI. The 10G and Wi-Fi links are report-only everywhere.
3. **Pass on a failed read or a missing value.**
   - `relay.rs:126` `circuits()` defaults to 0.
   - `sync_pair.rs:399` `texts()` returns empty on error.
   - `a_trust_check` `rss()` returns 0.
   - `two_members_posting` uses `busy_refused` `unwrap_or(0)`.
   - `two_fetches` never checks lsof's status.
   - `it_just_works:271-275` ignores `ok`.
   - `a_hostile_entry:349` ignores `ok`.
4. **Unchecked signal.** `a_rooms_own_anchor:150-155` does not check whether SIGSTOP took.
5. **Not compiled on ubuntu.** macOS-only files compile to 0 tests on ubuntu and print nothing.
6. **Knobs that could leak in.**
   - `VOX_PERF_ONLY` with no match makes R41 measure nothing and pass. CI does not set it; the gate unsets it.
   - `work_version` with `published-release` allowed passes silently. It is not set on CI or the gate.
