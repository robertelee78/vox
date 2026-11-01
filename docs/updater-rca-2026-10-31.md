# Updater RCA: repeated incomplete delivery through v0.4.13

Work item: [#1090](https://github.com/robertelee78/vox/issues/1090), `robertelee78/vox:ADR-014:S5:update-alone-app-handoff`.

Status: investigation report, not implementation acceptance. The operator's installed update remains incomplete. #1090 is reopened in Designing / At risk. No subsequent corrective release is established by this report. The earlier [2026-10-30 RCA](updater-rca-2026-10-30.md) remains historical evidence; its successful journeys do not close this incident.

## Conclusion

Three releases were accepted against a broader updater promise than the evidence established. The corrections addressed real handoff, recovery and reporting defects, but did not eliminate a required filesystem operation that can fail after the new app is installed. The operator encountered that remaining window in the public v0.4.12 to v0.4.13 upgrade.

The current product returns an error rather than concealing this failure. That is more truthful, but it still fails the requirement that one `vox update` complete without operator troubleshooting. Installing the new app and making its daemon Ready are not complete update success when required backup retirement remains unfinished.

The denied operation is now known: renaming the retained bundle's `Contents/Info.plist` to `Contents/Info.plist.kept`. The specific macOS policy that refused it is **not established**. File ownership, later metadata observations, provenance records, a TCC request, and a successful update in another environment do not identify that policy. This report does not prescribe permission changes or label TCC as the cause.

A separate live-profile incident also exposed split daemon/store generations and a socket-ownership defect. It explains why managing the orphan required care; it did not cause, and removing the orphan did not fix, the incomplete update.

## 1. Authority and evidence

The operator requires the same invocation to acquire the verified target-version updater before installed-state changes, complete installation and any required app/daemon handoff, and report the final result. The operator subsequently clarified that returning an incomplete installation and asking them to troubleshoot is not acceptable: the update must finish itself, or leave the existing installation intact if it cannot.

The normal cadence remains ADR/task update, independent plan review, execution, then separate independent result review. This RCA supplies findings and corrective acceptance requirements. It is not approval of a new transaction design or permission to bypass those reviews.

Published release source identities were resolved from local release refs. The inspected v0.4.12 and v0.4.13 `bundle.rs` files were hashed and matched to these exact release blobs:

| Release | Commit | `crates/vox-tui/src/update/bundle.rs` blob |
|---|---|---|
| v0.4.11 | `a95d1dcf8b410c4e5223d7afe6effc7abe92ddfa` | `d8acd0b6e16e0db132b5e1d8daccc6faaed7f2d3` |
| v0.4.12 | `8693dd65f4422fb67f91135987e94900cb935cd1` | `4c3e6981ad9d2be77e1fe917e40efafa9f292358` |
| v0.4.13 | `753b17529c96efa84b6c89a3236b0348aff54559` | `d2348c9f0a06221fa8fd0969088c0b0169829cd5` |

Primary evidence includes the operator's command output and screenshots; retained update journals and prior signed-public upgrade receipts; read-only filesystem, process, inode and scoped OS-log observations; and the scratch shipped-binary socket experiment described below. The earlier RCA distinguishes its controlled immutable-directory reproduction from the operator's unidentified original refusal.

Initial research reports cited positions from the wrong checkout. Those reports were rejected and corrected before this RCA. They are not current-source evidence. Source positions below refer to the linked immutable release commits, not an assumed branch or language-server index.

## 2. What happened across the releases

### v0.4.11: publication succeeded before the command's operational obligations did

The operator's v0.4.10 updater installed v0.4.11 and then returned generic `Operation not permitted (os error 1)`, accompanied by a LaunchServices cleanup note. Read-only inspection found the new active app, the previous bundle and a retained publication journal. The exact denied operation was not present in the error and was not recovered from scoped logs.

A controlled real-binary experiment later demonstrated a genuine product failure: an immutable directory in an older scratch bundle caused post-exchange cleanup to fail before the required daemon cutover. The installed helper was then newer than the live daemon. That experiment established an ordering defect, not the operator's original OS trigger.

The operator's successful retry was recovery evidence. Treating it, or a successful guest journey, as proof that the installed incident could no longer occur was incorrect.

### v0.4.12: recovery and diagnostics improved; the whole contract was not established

The correction retained startup/profile intent, checkpointed required handoff components, improved failure context and distinguished an unsuccessful unregister from a genuinely absent LaunchServices record. Real scratch journeys covered update, rollback, required-daemon and app-launch refusals, offline repair, saved data, closed/unrelated apps and stale registration removal. These were useful, bounded results.

The operator's actual update still printed the old caller's LaunchServices note and extensive setup bookkeeping. The absence of an app-handoff confirmation was not proof of a handoff. The operator then identified the architectural error: the installed updater was still the transaction owner, with new code reached afterward. The implementation had solved a post-install delegation problem instead of the requested pre-install transfer of transaction ownership.

### v0.4.13: target ownership landed, but the operator still got an incomplete transition

The new architecture introduced a bootstrap that downloads and verifies the selected target engine and invokes its `update-apply` entry point before mutation. Compiled bootstrap-capable A-to-B fixtures established that target code could hold the installation lock while A was still installed. This is distinct from the first public upgrade: the already-running public v0.4.12 updater did not contain that bootstrap call. Installing v0.4.13 cannot retroactively change its caller.

The operator's public upgrade installed v0.4.13 and reported its remembered nodes Ready. It then returned:

```text
Vox 0.4.13 is installed; transition incomplete: Vox 0.4.13 is in place, but the replaced Vox.app was not set aside: cannot rename /Applications/.Vox.app.previous/Contents/Info.plist to /Applications/.Vox.app.previous/Contents/Info.plist.kept: Operation not permitted (os error 1); run `vox update` again to finish, and until then open Vox as /Applications/Vox.app; run `vox update` for local repair
```

Many unchanged skill-file and shell/plugin setup lines preceded the failure. A `Next: run vox status` instruction appeared before the final incomplete result. That is a failed update with some completed components, not a successful update made acceptable by a final warning.

The source of the first public caller and the source of future target-owned transactions must not be conflated. The v0.4.12 caller performed the public first-hop transaction. The v0.4.13 target engine nevertheless retains the same relevant publication-before-retirement ordering. The architecture correction therefore does not, by itself, remove the demonstrated failure window.

## 3. Confirmed software causes

### C1. A required operation remains after the publication boundary

In the [v0.4.12 caller](https://github.com/robertelee78/vox/blob/8693dd65f4422fb67f91135987e94900cb935cd1/crates/vox-tui/src/update/bundle.rs#L340-L384), the updater prepares a transition, stops the captured app and calls `publish`. Publication exchanges the active/staged app, places the replaced app at `.previous`, and only then calls `set_aside`.

The [v0.4.13 target engine](https://github.com/robertelee78/vox/blob/753b17529c96efa84b6c89a3236b0348aff54559/crates/vox-tui/src/update/bundle.rs#L549-L623) has the same critical sequence. `set_aside` unregisters the retained bundle and renames its plist. Its failure is returned as an accumulated post-publication error. The caller still attempts handoff and setup, then reports an incomplete transition. The required retirement has neither succeeded nor been undone to an intact prior installation.

This explains the observed combination: new app installed, new daemon Ready, old bundle not fully retired, command unsuccessful. Renaming a signed app's plist is an actual filesystem mutation; checking ordinary writability does not prove that the later operation will be authorized.

Moving the transaction to new code fixed ownership, not atomic completion of the entire contract. Moving the plist rename earlier without a reviewed recovery design is not automatically safe either: renaming the active app's plist would make it non-launchable before the new installation was committed.

### C2. Progress and maintenance output are emitted without a final-outcome boundary

Both update implementations print `updated` and the retained-backup path before accumulating retirement and handoff failures. Daemon restart code emits next-step advice independently of the final transaction result. The retirement layer and its caller each add repair instructions, producing the duplicated instruction in the operator's error.

The [v0.4.13 setup wrappers](https://github.com/robertelee78/vox/blob/753b17529c96efa84b6c89a3236b0348aff54559/crates/vox-tui/src/update.rs#L1425-L1489) forward child stdout and stderr wholesale. Unchanged-file messages therefore dominate the update output. A setup child failure becomes a broad repair note; the wrapper does not return an integration result to its caller. `skill_said` infers coverage from file presence rather than the refresh result.

The required correction is truthful aggregate reporting, not deleting the final error or discarding useful diagnostics. Completed installation, completed handoff, incomplete retirement and incomplete integrations are different facts. The final result must own success and next-step advice; a partial operation must not read like overall completion.

### C3. Daemon pathname ownership is not filesystem-object ownership

Read-only observations found two daemons behind the same profile pathname. PID 28556, UDP 64518, held an unlinked lock and four unlinked node stores, each with link count zero. PID 32601, UDP 59001, held the replacement lock and current store files with different inodes and link count one. The app and normal CLI were using the newer daemon. The failing invite named the older daemon's board and port.

An advisory lock on an unlinked inode does not lock the replacement file created at the same pathname. This is not evidence that two processes acquired the same inode's lock. It is evidence that pathname reuse permitted separate live generations. The observations do not identify the process or operation that removed/replaced the old files. The operator confirmed the old data had intentionally been discarded; no recovery or migration claim is made.

The [shipped `IpcServer::drop`](https://github.com/robertelee78/vox/blob/753b17529c96efa84b6c89a3236b0348aff54559/crates/vox-core/src/node/ipc.rs#L6349-L6370) unconditionally removes its recorded socket pathname. It does not verify that this pathname still refers to its own socket. A normal shutdown of the old generation can therefore unlink the current daemon's socket.

This was reproduced once with the actual shipped binary and entirely scratch data/config directories. An empty old daemon was started; its scratch account directory was moved aside intact; a new daemon was started at the original path. Its socket delivered a live greeting. Normal SIGTERM of the old daemon exited zero while the new daemon remained alive, but the new control-socket path disappeared. This is a reproduced software defect, not an inference from two PIDs. Both owned scratch daemons were stopped afterward. No real profile was exercised in that reproduction.

For the operator's separate cleanup, only the explicitly authorized, reverified orphan was force-stopped to avoid that destructor. The newer daemon remained Ready and the current lock inode was unchanged. That mitigation did not complete the app update.

### C4. Release acceptance did not enforce the operator's whole outcome

The engineering/lead failure was accepting narrower observations as satisfaction of the complete updater contract. Specific escapes were:

- Post-install delegation was initially treated as equivalent to transfer before mutation. It is not.
- Successful update, rollback and repair journeys were credited beyond their exact artifact/environment and failure-state coverage.
- A controlled immutable-directory refusal explained one reachable defect, but did not identify or eliminate the operator's OS refusal. The distinction was written down without remaining a meaningful limit on closure.
- Version output and Ready nodes were allowed to dominate the success narrative even though required retirement could still fail afterward.
- Bootstrap-capable fixtures and an untouched older public caller proved different first-hop claims. Correctly documenting that distinction did not establish that the actual first public caller would complete all required filesystem work on the operator's host.
- Proof consumers were mapped too late during implementation. Fake-version fixtures, missing engine assets/records and wording-only assertions caused avoidable build/review cycles. Genuine consumer journeys ultimately replaced those claims, but the late discovery prolonged the correction.
- Issue/milestone closure and the assistant's repeated “done” statements preceded the operator's clean end-to-end outcome. Independent reviews and green CI did not warrant that extrapolation. The lead owns the acceptance and communication error.

## 4. What remains unknown

### The original v0.4.11 refusal

The exact denied operation/client/path was lost in the original generic error. Later recovery and representative replay cannot recover it. The controlled immutable-directory case must not be relabeled as that original cause.

### The v0.4.13 backup-plist denial policy

The operation and both paths are known. Later read-only metadata showed owner-writable directory modes, ordinary file modes, zero immutable flags on inspected paths, the original plist present and the `.kept` destination absent. ACL inspection returned no ACL text and errno 2; that is not proof that every applicable access policy was absent. Provenance/MACL attributes were present.

Scoped OS-log queries around the update returned assessment/provenance and registration-path activity, but no authoritative attribution of this denied rename. This does not prove that no denial occurred. A prior TCC `SystemPolicyAppBundles` request is not a denial. No evidence justifies “grant Full Disk Access,” change SIP, run as root, remove attributes, or change ownership as the fix.

The missing prerequisite for a cause-specific platform fix is evidence of the actual enforcement/authorization path, or a demonstrated supported installation model that completes the required operation under equivalent protection. Until then, a permission-specific remedy is speculation.

### Profile replacement and invite provenance

Different open/current inodes are confirmed; who replaced them and the exact original invite-generation moment are not. The Linux attempt received an answer from the advertised board saying it had no room record. That is not a demonstrated Linux connection failure. The transcript does not distinguish which advertised LAN/public route carried that successful connection. The invite contained alternative addresses for one board identity, not an independent anchor. Removing the orphan does not explain the original plist denial.

## 5. Corrective design and acceptance requirements

These are requirements for the next reviewed plan, not claims of implemented fixes.

1. **Define the complete commit boundary.** Required backup non-launchability, trusted rollback retention, installation, any required app/daemon handoff, integrations and final reporting must have explicit outcomes. A fallible retirement step after an irreversible install cannot be dismissed as optional housekeeping.
2. **Resolve the retirement/authority design before another release.** The plan must choose and demonstrate a supported operation/retained representation or a safe journalled transaction that meets finish-or-preserve behavior. It must preserve a launchable active app and trusted rollback contents through every crash state. Neither a writability preflight nor disabling the active plist early is an adequate design by itself. Automatic reversion must not corrupt data already written by the newer version.
3. **Keep the target-owner correction and its delivery boundary honest.** A bootstrap-capable source-to-target journey must observe target ownership before mutation. The upgrade from an untouched older public caller is separate evidence. No destination artifact can retrofit a call into a running older process.
4. **Make final output authoritative and concise.** Report the final update result once; suppress unchanged bookkeeping; retain concrete operation/path errors. Failed integrations must propagate as scoped outcomes, not be silently converted into successful refreshes. Do not emit an overall-success next step before required components finish.
5. **Fence daemon cleanup by ownership.** An old generation must not unlink a successor's socket or otherwise disturb its service. Normal profile replacement/deletion paths and login-item waiting/shutdown behavior need a source-bound ownership plan. Do not silently recover discarded profiles, reset data, or claim that an orphan caused unrelated faults.
6. **Review the source and the observed result separately.** Bind both to exact immutable source/artifact identities. Acceptance must list what ran, what the operator saw and what remains unproved. CI success is not a substitute. A successful retry establishes recovery only.

The real-use acceptance is to extend existing journeys, not add unit tests, CI gates, arbitrary timing claims or harness mechanisms. It must exercise the changed consumer boundaries: actual version-changing update/rollback; exact app/profile and saved-data preservation; required retirement success or intact pre-commit refusal under relevant platform protection; interruption/recovery without repeating completed handoffs or reversing committed rollback; concise final success/failure; and successor socket survival after predecessor exit. Distinguish PRODUCT failures from APPARATUS staging faults. Do not re-run existing greens without smoke.

The exact denied rename has not been reproduced in an equivalent scratch environment. The prior immutable-Resources experiment is not that reproduction. The operator is not to be asked to retry or troubleshoot the real installation as a substitute for resolving this acceptance gap.

## 6. Actions actually completed and retained evidence

Completed for this investigation: exact-release source binding; corrected research provenance; read-only failed-path metadata and scoped-log inspection; reconstruction of release/acceptance history; one shipped-binary scratch reproduction of the socket-ownership defect; and this RCA. No new product fix or release is established. Frozen room-Leave source changes remain separate and unaccepted.

Two independent read-only factual reviews found no blockers in the source-causality and acceptance/reporting slices respectively. Neither review is implementation acceptance or a finding that the OS denial policy is known.

The socket spike used the installed v0.4.13 helper with both profile variables directed to scratch directories. Its SHA-256, `d388cda032c25f0c04019a9e42bda2e9d6eb96df8bb24f30a2b9332623e24de6`, matches the [published v0.4.13 standalone record](https://github.com/robertelee78/vox/releases/download/v0.4.13/stable-aarch64-apple-darwin.json). The retained receipt records the resolved executable and both scratch PIDs.

Local evidence is retained under `/private/tmp/vox1007-practical-42qu344_/`:

- `v0413-operator-update-refusal-and-noise.md`: original operator outcome and scope.
- `v0413-rca-release-source-provenance.json`: release commits and matching inspected bundle blobs.
- `v0413-plist-rename-readonly-metadata.json` and `v0413-plist-rename-policy-window.json`: failed-path metadata and scoped historical-log observations.
- `v0413-live-join-two-daemon-open-stores.json`: open/current inode and link-count evidence for the two live generations.
- `v0413-discarded-profile-orphan-cleanup.json`: explicitly authorized orphan-only mitigation and preserved newer-daemon outcome.
- `v0413-rca-orphan-socket-spike.json`: actual scratch daemon starts, live socket observation and zero-exit predecessor shutdown removing the successor's path.

These files are local receipts, not a claim of publication or product acceptance. The original installed app/profile was not modified by this RCA investigation. No operator update or join was repeated; no permissions, platform security settings or real profile data were changed; no sudo was used.
