# On-demand proof selection

`python3 scripts/proofs.py --changed BASE --plan` shows the flows reached by a diff. Remove
`--plan` only when those outcomes are authorized to run. `--full --plan` shows an explicit
full-suite selection; `--full` requests the actual suite. This command is never invoked by
CI, a release gate, or a hook. No proof is added.

`--optional` includes optional proofs. Each omitted optional prints `OPTIONAL PROOF NOT RUN`.
Manual privileged LAN apparatus is inventoried but says `CANNOT MEASURE`; this command never
uses sudo. App methods and LaunchProof run through the existing guest VM driver.

A room-ask-only diff selects two supported portions of existing journeys:

- `app:FirstRunProof/testSessionsAreDrivenWhereTheyAreShown#room-ask`: minimum private-account,
  joined-room setup and the existing Choose/Create/decline repo/worktree assertions. Session
  approval, composer/draft and stop assertions are not replayed.
- `rust:vox-tui:agent_hook_proof:a_session_works_in_the_room_its_start_directory_is_mapped_to#room-ask`:
  minimum owned daemon, actual unmapped hook, public pending ask, decline, and next-session
  suppression. Other mapping, join and room-news portions are not replayed.

Use `--changed HEAD --only EXACT_ID` for an explicit supported flow. `--only`
requires an explicit mode (`--changed BASE` or `--full`); it is not a standalone mode. Unsupported step names fail before a
run; a whole journey is never advertised as a single step. Other existing journeys remain
whole-flow selections until an actual minimum-staging adapter exists. Unmapped source changes
select conservatively and print the unknown paths; this is not a precise dependency graph.

Results live in Git's worktree-local `proof-evidence/results.json`. A pass records its actual
exit status, log, commit, and fingerprint of relevant behavior, setup and apparatus inputs.
An unchanged pass is retained with that evidence; a whole-binary SHA is not a fingerprint.
A previous red remains pending and is never automatically relaunched. To retry a repaired flow,
provide `--repair FLOW=DIAGNOSIS.json` with these fields:

```json
{
  "failed_log_sha256": "SHA256 of the recorded failed log",
  "diagnosis_evidence": "/absolute/path/to/the/actual/investigation.log",
  "cause": "The diagnosed product or apparatus failure",
  "repair_commit": "Full committed repair SHA"
}
```

The command validates the failed log, nonempty investigation evidence, repair ancestry, and
an actual relevant source/setup change. A reason string alone cannot authorize an unchanged
retry. The human review remains responsible for whether the diagnosis explains the failure.
The original PRODUCT, APPARATUS and CANNOT MEASURE lines stream unchanged into output/logs.

`--since-last-full` reports commits, areas and affected proofs without executing anything.
A last-full baseline records an explicitly requested run and its complete/incomplete outcome;
an omitted optional or unmeasured manual proof never becomes a fabricated full pass.

Existing results can be imported without execution using `--record-receipt RESULT.json`.
The receipt must bind an existing log, its SHA256, the full source commit, the exact command
and optional step, exit status, and flow ID, with `schema: "vox.proof.result/1"`. The log must
contain the selected Rust test's actual name and one-test passed count, or the selected app
method's actual passed XCTest result. Zero selected tests never produces retained evidence.
A failure is classified from its selected test's terminal panic/XCTest error, not incidental
PRODUCT text earlier in the log. Receipts record observations; their authors must supply genuine
execution provenance. This command cannot authenticate who originally ran a copied log.

The old `vox-ffi/tests/notices_are_sentences_proof.rs` is deleted: its entire sole test
started an in-process `VoxNode` and inspected an internal listener array, contrary to ADR-018.
It had no shipped-binary or actual-app leg. It is not retained as an informational check,
CANNOT MEASURE inventory item, or replacement gate. Existing app journeys still exercise
visible room creation and room notices; this deletion does not claim a new notice proof.
Rust commands use features actually declared by their selected package. An optional result's
receipt must name the expanded `optional-proofs` command that executed the real proof, rather
than its stand-in.

Room-ask retention binds CLI and app inputs separately. Native Swift and VM-driver changes
do not invalidate the CLI-only step; Rust dependencies name the hook/status/decline boundaries, rather than every Rust source. An explicit
room-ask diff still selects both adapters, and each decides whether its prior pass is retained.

Product dependencies use module-level granularity: an unrelated function in a reached
host, actor, or channel module can invalidate the observation. This is not a claim of
function-precise product dependency analysis; proof methods and local apparatus are isolated.

The measured app room-ask adapter at `53006a5f` passed its actual selected XCTest in
51.819 seconds: the nested app driver exited zero. Its enclosing old command exited one
because it incorrectly treated an unrelated skipped LaunchProof as failure; the corrected
parser uses the actual selected test result. The CLI adapter's measured pass is bound to
`2e266787`. Genuine logs can be imported on corrected-driver-only copies of these sources
to demonstrate unchanged-flow retention without replaying either feature proof.

The current-main composition changes no production source. It preserves current native
helpers and the full Session privacy journey, which the room-ask selector explicitly skips.
This composition does not inherit unchanged fingerprints blindly: newer Ready/Locked CLI
behavior and app menu apparatus change relevant inputs. Those differences are reported,
not concealed by rebinding old observations as new runtime evidence. No integration-only
fixer-green replay is required or claimed.

## Version and conversation identity proofs (ADR-052 RG-10)

The targeted release proofs use private profiles and the shipped `vox` executable.
`update_proof` takes `VOX_PROOF_NEXT_BINARY`, a genuinely compiled `test-knobs`
`vox` with the workspace version's first character replaced by `9`; binary string
patches are not a release fixture. Its two selected functions are:

- `a_client_uses_another_package_version_with_the_same_control_protocol`
- `a_claim_is_still_held_after_the_package_version_changes`

`the_daemon_and_its_nodes_proof` runs the generated native extension through a
Node.js event driver, with real Vox hooks and its availability watcher:

- `a_conversation_refuses_a_rebuilt_node_under_the_same_name`
- `a_conversation_reports_one_reconnecting_line_when_its_daemon_restarts`

Run each explicitly with
`cargo test --release -p vox-tui --features test-knobs --test FILE FUNCTION -- --ignored --exact --nocapture`
under the execution environment's required build slot. The node-rebuild proof stops
the old daemon before replacing the node directory; it does not prove safety of
store rewriting across a replaced directory (RG-10 item 3).

The former package-version refusal acts in `work_version_proof` are removed.
`claims_use_their_rules_and_keep_the_v0430_package_stamp` reads the actual board
after differently stamped signed claims: other claim rules have no effect, while
the package-only `0.4.30` stamp still holds its claim. Operation/retry and renewal
wire fixtures now carry the same `claims` stamp as the CLI. Their sending sessions
are registered through the public hook before the operation acts. The separate
`an_agent_session_is_checked_from_both_sides_proof::the_doctor_explains_incompatible_claim_rules`
act expects advice about matching claim rules, not matching package versions; it
does not depend on the full journey's Claude wiring or process-provenance staging.

## A materialized accepted join reopens after a crash

A verified join saved with its room wrap and reopen keys completes its retained
admission handoff at startup. It then follows ordinary room reopening, including
settlement and delivery of consented keys. An acceptance with no saved room still
needs the person's join passphrase; a refused or abandoned join is not restored.

The existing complete syscall crash sweep is
`a_crash_after_a_consent_still_delivers_the_key_proof::a_crash_in_a_consent_whose_member_key_is_held_still_delivers_it`.
Run it explicitly in the required build slot:
`cargo test --release -p vox-tui --features test-knobs,optional-proofs --test a_crash_after_a_consent_still_delivers_the_key_proof a_crash_in_a_consent_whose_member_key_is_held_still_delivers_it -- --ignored --exact --nocapture`.
It kills the serving daemon at each store boundary of the join and following
consent, restarts it, and requires the member to read the next post.
