# v0.4.11 updater incident: partial publication and misleading backup cleanup failure

Work item: #1090, `robertelee78/vox:ADR-014:S5:update-alone-app-handoff`. Corrective delivery: v0.4.12, without replacing already-published v0.4.11 artifacts. The source and real-binary correction evidence are recorded below. The operator's exact original denied syscall remains unidentified; it is not attributed to the controlled reproduction.

## Incident and impact

The operator ran the installed `vox update` from v0.4.10 after v0.4.11 was published. It printed:

```text
note: LaunchServices did not release /Applications/.Vox.app.previous (exit status: 1); tried again at the next update or rollback
Vox 0.4.11 is available on stable (this is 0.4.10)
vox: I/O error: Operation not permitted (os error 1)
```

Read-only inspection found v0.4.11 already installed as `/Applications/Vox.app`, v0.4.10 retained as `.Vox.app.previous`, and a `.Vox.app.publishing` journal targeting v0.4.11. The previous bundle still had its original Info.plist; an older bundle in the journal already had Info.plist.kept. The updater had progressed past filesystem exchange but had not completed its promised operational handoff. No evidence establishes lost room data. The assistant did not run Vox against the operator's profile, alter the real installation, change permissions or security settings, or use sudo.

The operator's retry succeeded: CLI and daemon reported v0.4.11, remembered nodes were Ready, and skills/plugins refreshed. The LaunchServices failure note persisted. Retry success establishes recovery, not correction. The operator explicitly rejected completion, and #1090 was reopened; its earlier acceptance is not evidence that this incident is fixed.

## Timeline and evidence boundaries

| Step | Primary observation | Meaning |
|---|---|---|
| Prior acceptance | A rebuilt v0.4.10-source app/helper and compiled 9.4.10 fixture used controlled ad-hoc signatures and the existing loopback/test-knobs apparatus in an isolated guest. A separate, later untouched signed-public0.4.10→0.4.11 journey preserved app profile, Ready node and saved room. | Proved those distinct journeys, not artifact/environment equivalence or all protected `/Applications` failure states. |
| Release | v0.4.11 was published at 2026-10-31 05:37:54 UTC; milestone19 and #1090 were recorded delivered. | Delivery happened; it did not make the subsequent reported defect impossible. |
| First operator failure | Exact output above; post-failure installed layout and retained journal were inspected read-only. | A fatal command failure after installation was real. The command did not retain its exact denied operation/path/client. |
| Operator retry | Successful current-version update in approximately3seconds, with remembered nodes Ready and the same LaunchServices note. | Recovery succeeded; false/inconclusive cleanup reporting remained. No original syscall was recovered from this retry. |
| Initial diagnosis | Scoped logs, ownership/flags/ACL metadata and directory-only durability calls were inspected. | No immutable flags were observed on inspected real directories; directory fsync and F_FULLFSYNC succeeded when inspected. These later successes do not identify the earlier failure. |
| First representative replay | Original signed public updater ran once at `/Applications` in macOS26.6.2, SIP disabled. Exit0; saved room preserved; warning reproduced; EPERM not reproduced. | Non-reproduction, with a material security/environment limitation. |
| Fresh security-enabled replay | Original signed0.4.10→0.4.11 ran once at direct `/Applications/Vox.app` in macOS27.2(26B123), SIP and authenticated root enabled. Exit0 in9.73seconds; app PID1018→1081; exact scratch profile, Ready node and saved room survived. Warning reproduced; EPERM not reproduced. | SIP being enabled does not by itself reproduce the incident. SSH-origin execution and guest build still differ from the operator's terminal and host build26B5091g. |
| Controlled real-product failure | Original signed0.4.10 updater ran with an intentionally immutable0755 Resources directory inside an older retained scratch bundle. Exit1 in4.09seconds with the same genericEPERM; active helper became0.4.11, but its status command refused the still0.4.10 daemon. Retained0.4.10 client remained Ready and read the exact saved room message. | Demonstrates the shipped committed-publication/handoff defect using real binaries and a real filesystem refusal, not mocks or a source assertion. The injected immutable flag is not established as the operator's original trigger. |
| Discriminating syscall diagnostic | A throwaway Rust program called the same std::fs::set_permissions(mode|0700) on that0755 immutable scratch directory: OS1 PermissionDenied. read_dir succeeded. `/bin/chmod u+rwx` returned0 because it did not establish that an equivalent syscall was attempted. | Identifies the controlled failure mechanism and an unnecessary metadata mutation. This diagnostic is apparatus, not a separate product proof or historical root-cause claim. |

The exact first command timestamp was not captured. An absolute22:49–22:54 local-time log query contains Gatekeeper evaluation/provenance records for us.vox.app at22:50:07, but no denied operation. A separately observed sandboxd TCCAccessRequest for SystemPolicyAppBundles is a request, not a denial or attribution of cause.

## Causal findings

### 1. Proven product cause: publication was treated as if handoff could wait for housekeeping

In shipped v0.4.10 `update::bundle::publish`, after `renameatx_np(RENAME_SWAP)` installs the new active app, the function still performs fallible directory sync, replaced-bundle placement, older-bundle retirement/removal and journal cleanup. An error from these operations returns before the caller's daemon restart and integration/handoff sequence. The controlled real-product failure demonstrates the consumer consequence: installed0.4.11 against a live0.4.10 daemon, with a generic failure and no automatic cutover.

The journal preserves some filesystem layout, but not the original app's restart intent/profile. The old helper cannot invoke a newly installed delegate after it has already aborted. A new release cannot retroactively change that running v0.4.10 parent.

Even when the new delegate runs and returns failure, the old v0.4.10 parent's `run_skill_install()` can reduce the unsuccessful child status to a harness-setup note instead of failing the command. Parent exit zero therefore does not prove app handoff. The delegate also requires the parent executable at this installation's exact `.previous/Contents/Helpers/vox`; a parent retained under `.partial` is not authorized. The correction must not weaken these ownership checks to work around already-running old code.

Current v0.4.11 already attempts `transition_failed()` handoff for publication errors. It is inaccurate to say every current publication failure bypasses handoff. Independent review nevertheless found current recovery sweeping/cleanup could return before handoff, journal cleanup preceded handoff completion, unreadable version files were interpreted as empty strings, and rollback had insufficient committed-state recovery reporting. These are part of the correction, not evidence about which original syscall failed.

`writable()` also unconditionally called set_permissions even when a directory already had owner read/write/search bits. The controlled syscall diagnostic proves this avoidable call can fail. The correction must avoid needless chmod, while still truthfully reporting real removal/permission failures.

### 2. Proven reporting flaw: unsuccessful unregister was conflated with an unmet cleanup obligation

`set_aside()` calls `lsregister -u` before checking whether Info.plist was already disabled. On the observed host, a scratch folder containing only Info.plist.kept and no registration returned exit1/OSStatus−10814. Both signed guest updates reproduced the warning despite completing their handoff.

Plist absence alone is not proof of no stale registration. A separate guest diagnostic explicitly registered a scratch Vox path, disabled its plist and observed: the raw LaunchServices database retained the record; NSWorkspace's available-applications query omitted it; exact-path `lsregister -u` successfully removed it. A later unregister of the absent record returned exit1. Thus neither a plist-only guard nor a negative NSWorkspace availability query is a valid stale-record cleanup oracle.

The correction must retain exact-path unregister for stale records and independently establish raw-record absence before considering an unsuccessful unregister satisfied. Execution/query/parse failure remains unknown, not absence. It must not restore a backup's plist merely to make unregister accept it, reset the database, or hide real failures. The raw dump is diagnostic data and must not be emitted wholesale or read into unbounded production memory.

### 3. Proven observability defect: the fatal error discarded its operation and path

The original output contains only AppError::Io's OS error. Multiple post-exchange operations can produce it, so post-failure layout and genericEPERM do not identify the original syscall. The real profile and relevant retained paths must not be mutated to manufacture a cleaner explanation.

The exact original OS refusal remains undetermined. Inspected metadata and scoped historical logs did not recover it; later fsync success, retry success, the mere TCC request, the initial guest's disabled SIP and the controlled immutable-folder reproduction do not establish the historical trigger. No claim is made that the operator needed permission changes, approved a prompt, or had immutable flags.

### 4. Additional recovery defect found during corrective verification

A real daemon-start refusal stopped the previous daemon while app relaunch succeeded. A subsequent candidate repair incorrectly treated the now-missing daemon as optional and could finish the transition without restoring service. That candidate success was rejected before release.

The corrected journal captures whether a daemon was running, its existing startup authority, listen address, anchors and attached node names before stopping it. Recovery must restore a required missing daemon and confirm its release and remembered-node readiness before checkpointing completion. An originally absent daemon remains optional: an incomplete unused node must not make an otherwise unnecessary daemon handoff fail. No passphrase, whole argv or arbitrary environment is persisted.

## Corrected candidate: observed runtime evidence

Updater logic through `9c86b03ffccfa906f6e61ffed28144a883ca5737` received two independent exact-source acceptances. Strict workspace/all-target Clippy passed. The logic was compiled at v0.4.11 for the existing updater apparatus and at the real workspace version v0.4.12 for the candidate helper; the native app was also built at v0.4.12. No version string was substituted in a binary.

The following were exercised with real binaries in the fresh macOS 27.2 guest with SIP and authenticated root enabled. App fixtures used controlled ad-hoc signatures; the existing loopback release transport and compiled-out-of-release post-swap abort knob were used where stated. These observations are not a notarized corrective-artifact attestation.

| Scenario | Observed product outcome |
|---|---|
| Before-publication refusal | An empty staged directory was conservatively refused because executable use could not be established. The running app identity, Ready node and exact saved message remained unchanged. This did not establish an immutable-folder syscall failure before publication. |
| Native v0.4.11→v0.4.12 update | The app process was replaced, the daemon served v0.4.12 and the node was Ready. The app retained its exact data/config/HOME profile and absent XDG overrides; the original saved message remained readable. |
| Required missing daemon | A genuine immutable daemon-directory refusal failed the command. After only that obstruction was removed, offline repair started the required absent daemon and restored Ready service before reporting success. |
| Optional absent daemon | A separate scratch profile with incomplete node facts updated successfully without starting a daemon or disturbing the profile that was serving the saved room. |
| Committed rollback with daemon refusal | The rollback installed v0.4.11 and independently relaunched the app, but returned failure for the refused daemon start. It explicitly said not to repeat `--rollback`. Offline repair restored service without reversing again or relaunching the already-completed app. |
| App-only refusal | Removing execute permission from only the controlled running app produced a real LaunchServices relaunch failure. The daemon remained Ready. Restoring that exact permission and repairing offline relaunched the app without restarting the completed daemon. |
| Closed/unrelated installation | Updating a closed installation did not open it. The other running installation retained its exact PID, launch identity and bundle path. |
| Retained backups and stale registration | Normal current-version updates completed without the false LaunchServices failure. A genuine raw record for the disabled retained backup was present before the product ran and absent afterward; this proved removal, not warning suppression or reliance on NSWorkspace availability. |
| Interrupted publication | The existing post-exchange abort knob left the new helper installed while the previous release still served the saved room. The normal new helper recovered the real journal offline. |
| Unreadable recovery authority | Removing a required field from only the scratch journal made repair refuse with the journal path and parse error. The old release continued serving the exact saved message; the original journal bytes were then restored as apparatus. No unreadable state was silently deleted. |
| Interrupted recovery with cleanup refusal | With an older retained Resources directory still immutable, recovery first made the v0.4.12 daemon Ready, then failed truthfully on the exact older-bundle removal path. After only that flag was removed, offline cleanup completed without another exchange, daemon restart or app relaunch. |

The original signed v0.4.10→v0.4.11 failure and the corrective native journey remain distinct evidence. Earlier source `1ebc3217962542dcd67e4c332b0d09dfa8212e0a` also demonstrated captured-app/profile preservation under the original controlled older-bundle obstruction; the final source added and exercised the required-daemon correction above.

Setup failures were not counted as product failures or greens: a missing loopback standalone record, an incorrect native deployment target, a nonexistent inspection-command path and an apparatus parser that initially omitted raw registry address suffixes were corrected before their respective claims were accepted. Successful product operations were not repeated merely to fix subsequent inspection.

Receipts and complete console observations are retained under `/private/tmp/vox1007-practical-42qu344_/v0412-*`; the source-bound runtime ledger is `v0412-final-runtime-verdict.json`. No real host installation/profile or platform security setting was changed. These checks do not recover the original host's denied syscall or retroactively change an already-running older updater.

## Why acceptance missed this

- Success-path app/daemon/profile proofs were overgeneralized to the installed updater's failure-state guarantee.
- The earlier isolated guest and scratch app location were not established as equivalent to the operator's protected installation. The initial guest had SIP disabled; this is an evidence gap, not proof of causation.
- A repeated error-looking LaunchServices note was treated as nonfatal because commands succeeded, without proving the cleanup obligation was either met or genuinely pending.
- Filesystem publication and runtime cutover were not separately asserted under a real post-exchange filesystem refusal.
- Generic filesystem errors prevented retrospective identification of the failed operation.
- The assistant initially treated the operator's successful retry as resolution and left the delivered work Done/At risk. That was wrong. The operator's rejection prompted actual reopening rather than redefining success.

No claim is made that green CI, source review or the test apparatus itself proves the user's feature. No new CI gate, unit/in-process test, CPU cap or artificial product timeout is part of this correction.

## Corrected behavior and delivery boundary

The source candidate uses the existing install lock and journal, not another transaction system. It persists unambiguous source/target bundle identity and exact owned handoff intent before stopping an app or exchanging bundles; committed installation, per-component handoff completion and cleanup completion are separate. Rollback executables and journal authority are retained on unfinished work. Unreadable/ambiguous recovery state is refused rather than deleted.

After publication, independently possible authorized daemon restart and app relaunch are attempted before optional older-bundle deletion can end the operation. Each completed component is checkpointed so local repair does not redo it. Only whitelisted nonsecret profile fields and exact app identity are captured; passphrases and arbitrary environment are excluded. Exact-parent/install/lock delegate authorization is preserved. Completed journals are atomically retired before recursive disposal, so partial disposal cannot turn an incomplete record into legacy recovery authority.

Filesystem failures identify the attempted operation, affected path(s), underlying OS error and committed state. An incomplete rollback directs local repair, not another `--rollback` that would reverse the installed result. Local repair completes pending obligations without another exchange or release-network dependency. Genuine unresolved cleanup is reported and retained, not silently discarded.

The table above records the exercised correction claims, not an exhaustive failure matrix. Independent source review and Clippy support the candidate but are not substitutes for those product observations. Old-v0.4.10 caller behavior is attributed separately; a new artifact cannot repair a parent that has already returned before invoking it, and that parent's exit status alone is not handoff evidence.

Signed/notarized publication and a real upgrade from the untouched public prior artifact are the final delivery boundary. Their source-bound receipts belong to the [v0.4.12 release](https://github.com/robertelee78/vox/releases/tag/v0.4.12) and [#1090](https://github.com/robertelee78/vox/issues/1090), not to an assumption that the controlled ad-hoc fixture was equivalent. v0.4.11 remains a historical published artifact; it is not overwritten to hide the incident.
