# Target-owned updater: execution plan

Authority: [ADR-014 M-29, M-29a and M-29b](../adr/ADR-014-macos-client.md#5-packaging-install-and-update), with ADR-015 §17's unchanged transport, ownership and platform-trust rules.
Work item: [#1090](https://github.com/robertelee78/vox/issues/1090), key `robertelee78/vox:ADR-014:S5:update-alone-app-handoff`.
Delivery target: v0.4.13. This document is the design and execution sequence, not implementation or delivery evidence.

## Problem and boundary

An old updater that installs its replacement and invokes new code afterward still owns the dangerous part of the transaction. It can strand the new installation before that code is reached. A successful retry is recovery evidence, not proof that this architecture is correct.

The normal cadence is document/task update, independent plan review, execution, then independent review of the executed result. Candidate `21501b3e1102a4c98a498d5cc2b255285b803931` and its prior review/runtime receipts are retained inputs. They are not approval of this plan and are not permission to merge or publish ahead of those gates.

## Design

### 1. Installed process: bootstrap only for a newer release

- Resolve the running installation and its installer-owned channel. Refuse a source or unowned install with actionable guidance.
- Select the release once. Download its standalone updater into an owner-private temporary directory, enforce the record's size/digest and existing platform trust checks, and close the writable descriptor before execution.
- Explicitly invoke that verified executable's internal update entrypoint with a bounded request containing the canonical installed executable, selected channel/target/version and verified release record. Preserve Unix pathname bytes. The child validates the request and its own identity; no plugin hook, environment recursion flag or side effect of `--version` serves as control transfer.
- Keep temporary storage alive while the child runs. Forward output and propagate its exit status. After transfer, perform no transaction mutation in the old process.

### 2. Target process: one owner for the transaction

- Acquire the existing installation lock before recovery or mutation. Revalidate install/channel ownership under the lock; compare the selected target with the installed helper's real version, not the temporary engine's version.
- Run retained recovery under that same owner. Successful recovery does not suppress an available newer upgrade. Read the installed state again before deciding what remains.
- Fetch the app record and archive from the already selected release tag. Require exact version agreement and the app helper's size/digest to match the selected standalone engine. Retain the existing same-Developer-ID/notarization requirements.
- Reuse the existing atomic publication and journal machinery. Capture the exact running app/process start identity, profile and HOME/XDG environment, and daemon startup authority before stopping anything. Preserve data and rollback authority. Do not retarget another installation or substitute the updater's profile.
- Attempt independently possible daemon and app handoffs; checkpoint each successful component. A required daemon must be serving the installed version and remembered nodes must be Ready before completion. Preserve an originally absent optional daemon and a closed app.
- Report publication, handoff and cleanup outcomes truthfully. Retain incomplete state and exact operation/path diagnostics; never delete ambiguous state to obtain a green result. Refresh shell/agent integration within this owner, not through an old-process completion callback.

### 3. Local and standalone paths

- Checking reports availability without mutation, execution of a downloaded updater, recovery, or app/daemon restart.
- Rollback is local and restores the retained version using the same ownership, recovery and handoff invariants.
- An unavailable release lookup or engine download may permit installed-code local repair before control transfer. Report repaired retained work separately and preserve failure for an unavailable upgrade. Do not fall back to an old installation transaction after the target has run.
- Standalone installation reuses the already downloaded/verified target engine; it does not fetch a second copy. Preserve atomic replacement and local rollback on Linux. No new signature scheme is part of this work.

## Execution and related tasks

|Order|Existing task|Work and completion boundary|
|---|---|---|
|1|#1090; parent #433 and ADR root #429|Commit the amended ADR and this plan, regenerate exact source bindings, and reconcile the existing task/Project. Keep the task Designing until plan review accepts the immutable plan.|
|2|#1090|Obtain independent Opus review using OMP's Anthropic connection. Address concrete findings and resubmit changed plan bytes before execution.|
|3|#1090|Compare the retained candidate with the accepted plan. Reuse conforming code, correct deviations, migrate every caller and remove obsolete post-install delegation. No compatibility shim or new CI gate.|
|4|#1090; #453 and #993 as preserved invariants|Exercise the affected real-binary journeys below. Reuse source-bound observations where logic and claim match; repeat a proof only for smoke or an actual relevant change. Record apparatus failure separately from a product result.|
|5|#1090|Obtain a separate independent review of the final immutable implementation and the exercised evidence against the accepted plan. Prior source acceptances do not bypass this gate.|
|6|#1090|After implementation acceptance and existing CI, merge, publish signed/notarized artifacts, verify the public first-hop upgrade and reconcile delivery. No task is delivered merely because code or the plan merged.|

[#453](https://github.com/robertelee78/vox/issues/453) retains its historical atomic-bundle delivery; its obsolete ask-to-restart wording is to be reconciled to M-29/M-29b, not treated as delivery of this new behavior. [#993](https://github.com/robertelee78/vox/issues/993) and [#987](https://github.com/robertelee78/vox/issues/987) remain constraints on one launchable app and safe retained bundles; their historical delivery is not retroactive updater-ownership acceptance. No duplicate stories are needed for phases of the same user outcome.

## Operator acceptance

Every launched Vox process uses scratch `VOX_DATA_DIR` and `VOX_CONFIG_DIR`. Native app work runs in the dedicated scratch macOS guest, not against the operator's installation/profile. No sudo, security-setting changes, profile reset, new harness or artificial timing/CPU limits.

|Scenario|Consumer-visible result and discriminating evidence|
|---|---|
|Bootstrap-capable A → newer B|Observe B's explicit updater process before installed A changes, with source-bound lock acquisition before mutation. One invocation installs B, restores Ready service, relaunches the exact app/profile and retains the exact saved message. An open lock descriptor alone is not proof of exclusivity.|
|Refusal before publication|Bad/unavailable target or an unusable staged path does not change the running app, Ready service or saved data. Record the actual refusal, not a source-text or mock assertion.|
|Committed update with genuine cleanup refusal|New installation, Ready service and app handoff complete where independently possible, but the overall command fails with the remaining operation/path and retained repair state. Never label this a total success.|
|Required daemon or app launch fails|Command fails and names the failed component. After removal of only the scratch obstruction, offline repair completes only unfinished work, without repeating an already completed handoff or reversing a committed rollback.|
|Engine unavailable with retained work|Local repair remains possible; repaired work does not turn the unavailable newer upgrade into success. Preserve both failures if repair also fails.|
|Clean upgrade, rollback, closed/unrelated app|Version, exact saved message and Ready node survive each affected transition; the closed owned app stays closed and an unrelated app's launch identity is unchanged.|
|Standalone and check|Check leaves the installed version unchanged. A subsequent update installs the target and restores the real service using one target-engine download; existing local rollback remains available.|
|Signed public delivery|Use untouched, digest-verified public prior artifacts and normal trust checks. Observe replacement app identity/profile, installed version, Ready node and exact saved message; inspect published signing/notarization receipts.|

Retain complete relevant command output, exit codes, source/asset identities and whitelisted profile observations. Never publish credentials or whole process environments. No unit or in-process library tests; use existing shipped-binary journeys or uncommitted operator spikes under ADR-018.

## First-hop and evidence limits

Public v0.4.12 never contained the new bootstrap call. Its first upgrade still executes its old updater. No destination release can change that already-running process retroactively. The public-prior journey validates that first hop separately; it does not establish target ownership before publication.

The new architecture is to start with the first bootstrap-capable release. A genuinely compiled two-version fixture can establish that execution boundary before publication; it must retain its actual source, versions and controlled-trust labels. Ad-hoc signing and loopback fixtures do not establish Developer ID/notarization or public-origin trust. A rejected Darwin non-UTF-8 filename staging attempt is not Linux runtime evidence. The original historical EPERM syscall remains unidentified; no inference is to be presented as its cause.

## Review gates

Plan review is to return Accept or concrete blocking findings against immutable ADR/plan/task bytes, including first-hop scope, recovery ownership, smallest design, acceptance coverage and task/source consistency. Execution remains paused until that verdict is accepted.

Implementation review is a separate verdict against the final source and real observed results. CI, plan approval, historical release delivery, or a successful retry cannot substitute for that review or for the signed-public delivery boundary.
