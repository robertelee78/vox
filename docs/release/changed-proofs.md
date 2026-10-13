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
