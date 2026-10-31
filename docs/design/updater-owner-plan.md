# Target-owned updater: intact-bundle replacement plan

Authority: [ADR-014 M-29–M-29c](../adr/ADR-014-macos-client.md#5-packaging-install-and-update), with ADR-015 §17's unchanged release-origin, ownership and platform-trust requirements.
Work item: [#1090](https://github.com/robertelee78/vox/issues/1090), key `robertelee78/vox:ADR-014:S5:update-alone-app-handoff`.
Status: proposed correction; independent Anthropic Opus plan review is required before product edits. No new release is authorized by this plan. Published v0.4.11–v0.4.13 assets remain immutable. The next delivery tag must be recorded separately before release work.

## 1. Problem and researched decision

The installed update committed the new application before making its retained predecessor non-launchable. Renaming the predecessor's signed `Contents/Info.plist` then failed with EPERM. Reporting that failure was truthful, but installation plus a repair instruction did not satisfy the one-command update contract. Target-version ownership fixed a different ordering problem; it did not remove this failure window. The OS authorization decision that denied the operator's exact rename remains unknown. The [incident RCA](../updater-rca-2026-10-31.md) distinguishes that unknown from confirmed transaction and acceptance defects.

The concrete reference is released Sparkle 2.10.1, not an assumed API:

- [`SUPlainInstaller.m`](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Autoupdate/SUPlainInstaller.m) installs intact bundles through same-volume staging and atomic exchange where supported; its fallback attempts restoration when the final move fails. It does not disable a retained backup by editing its plist.
- [`SUFileManager.m`](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SUFileManager.m) obtains `NSItemReplacementDirectory` through `NSFileManager` and implements same-volume moves and atomic exchange. Its filesystem strategy, not its internal transaction class, is the reference for this correction.
- [`SUInstallerProtocol.h`](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Autoupdate/SUInstallerProtocol.h) cannot report cleanup failure through `performCleanup`; the installer rejects downgrade in its initial phase.
- The [released CLI](https://sparkle-project.org/documentation/sparkle-cli/) and [`SPUUpdater.h`](https://github.com/sparkle-project/Sparkle/blob/2.10.1/Sparkle/SPUUpdater.h) select and download through Sparkle's feed lifecycle. They do not accept Vox's already-pinned local artifact, external journal owner or authenticated offline rollback request.
- Apple's [`NSUpdateSecurityPolicy`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsupdatesecuritypolicy) documents same-team update authorization and optional policy customization. The observed helper and both application bundles already carry the same Team ID. Neither adding a policy nor changing signing metadata is therefore an established remedy for this incident.

**Decision proposed for review:** retain Vox's verified target-version transaction owner, adopt the researched intact-bundle/same-volume replacement pattern through supported macOS filesystem interfaces, and replace launchable backup bundles with verified archives. This is Sparkle-informed installation, **not Sparkle framework integration**. Do not vendor or fork its private installer, add a second transaction owner, invent upstream hooks, introduce a new signing key, or remove Vox's rollback/journal guarantees to fit its public API. The earlier drop-in-framework recommendation is withdrawn on the source evidence above. Plan review must explicitly assess this choice; library reputation is not acceptance evidence.

Linux and its standalone publication mechanism remain unchanged. No plist mutation is an authorization strategy. No sudo, Full Disk Access request, SIP/TCC change, ownership workaround or operator repair step is part of this design.

## 2. Owners and concrete implementation boundary

### Installed command

Retain the bootstrap already shipped in v0.4.13: select a newer release once; download the selected standalone engine into owner-private storage; enforce its size, digest, canonical version and platform trust; close writable handles; explicitly invoke its bounded internal update entrypoint; retain temporary storage and propagate the final child exit status. Preserve Unix pathname bytes. The old caller must not publish, restart components, run plugin completion hooks or reinterpret child success afterward.

### Target engine

The verified target `vox` owns the existing installation lock continuously across revalidation, recovery, snapshot preparation, publication, restoration, handoff and final reporting. It downloads the app from the selected release tag, requires matching app/helper versions and the helper digest from the selected standalone record, and keeps existing Developer ID/notarization validation. No second engine download, latest-release reselection or old-engine fallback after transfer.

`crates/vox-tui/src/update/bundle.rs` remains the transaction owner. Introduce only the archive/journal state needed for this cutover. Reuse existing process-start identity, app/profile capture, daemon startup intent, component receipts and ownership checks. Do not build a parallel installer service or general transaction framework.

Add a small macOS-only Objective-C filesystem bridge compiled into the verified Rust engine through `crates/vox-tui/build.rs`; it is not another executable or service. Its two operations are `NSFileManager`'s `URLForDirectory:inDomain:appropriateForURL:create:error:` with `NSItemReplacementDirectory`, and `removeItemAtURL:error:` for an exact journal-owned bundle. The former must return a private same-volume path; the latter must preserve the native operation/path/error. Pass filesystem byte paths and caller-owned bounded result/error buffers across FFI; expose no lock, trust, journal or handoff decisions. Use SDK declarations, a pinned existing `cc` build dependency and Foundation linkage only on macOS. Retain the existing `rustix` atomic exchange; refuse unsupported exchange before installed mutation instead of adding a two-rename fallback.

The independently reproduced daemon cleanup defect is also in scope: in
`crates/vox-core/src/node/ipc.rs`, capture the created control socket's filesystem identity
and unlink it on shutdown only if the pathname still identifies that socket. Do not change
profile replacement/reset semantics or stop the operator's daemon. A real two-generation
scratch journey must show the successor remains reachable after predecessor shutdown.

## 3. Rollback representation and trust

Use one durable rollback archive beside the owned installation, with a small owner-private record identifying its actual version, byte size, SHA-256 and captured signing identity. Stage its replacement under the existing journal-owned private directory; never overwrite the last good archive before replacement authority is durably recorded. Use existing archive tools and bounded streaming hashing, not an in-memory bundle copy or a new archive format.

Snapshot the complete installed signed application without editing it. Before publication, round-trip the archive into private same-volume replacement storage and verify the complete restored bundle, its helper version and original Developer ID. A successful archiver exit alone is not proof of a usable rollback. Record the verified archive and sync the payload/authority before stopping components or replacing the installation. This extra read/extraction establishes the promised offline recovery copy; it is not an incidental gate.

Restoration verifies the retained archive digest/size, exact embedded version and signed bundle against its retained original identity. A previously authenticated local installation is rollback authority, not an untrusted new download; restoration must not require a release lookup or a fresh online notarization request. It must not weaken authentication of newly downloaded releases. An invalid, missing or ambiguous archive is a precise refusal, never a reason to reset data or silently discard state.

Explicit rollback exchanges the selected restored application into place and snapshots the version it replaces as the next rollback archive. Repeating `--rollback` therefore remains an explicit version-changing choice. A subsequent ordinary update or recovery must never reverse an already committed rollback implicitly.

## 4. Transaction sequence and crash recovery

Persist enough authority to distinguish source bundle, verified candidate, original rollback archive, proposed rollback archive, replacement-directory paths and exact process/profile intent. Validate canonical ownership and source/target identities under the install lock at every destructive boundary. Reject unexpected paths, symlinks, changed identities and conflicting journals without deletion. Journal writes and renames require their existing durability fences.

Extend the existing `.Vox.app.publishing/transition.json`, not a second journal. Record an explicit
filesystem phase (`Prepared`, `Stopped`, `Exchanged`, `Retiring`, `Restoring`,
`FilesystemCommitted`, `HandingOff`), the verified source archive, retained previous archive
authority, and any fresh restoration bundle's identity **before** exchanging it. Resolve a crash
between exchange and its receipt from the already recorded source/target identities; no phase
flag alone proves that a rename happened. Use `.Vox.app.rollback.zip` and its owner-private
authority record as final rollback storage; proposed and superseded archives remain under the
owned publishing directory until promotion/restoration is durably resolved.

|Stage|Required work and durable meaning|
|---|---|
|Prepare|Authenticate candidate, capture original startup intent, create and round-trip-verify the source rollback snapshot, preserve previous rollback authority, and record all owned paths. Installed app/service remain unchanged.|
|Stop|Stop only the captured owned app and required daemon, with existing PID/start-identity fencing. Record the stopped state. A closed app and originally absent optional daemon stay absent.|
|Exchange|Atomically exchange the complete candidate and active bundle on the same volume. Record actual source/target filesystem identities. Do not start the new app or daemon yet.|
|Retire|Preserve the verified source snapshot as the next durable rollback archive; unregister only exact displaced/staged application paths using the existing exact-path mechanism; remove displaced application trees as whole bundles without changing signed contents. Confirm no displaced application remains selectable as Vox.|
|Commit filesystem|Only after publication, rollback-archive authority and required retirement are complete may the journal authorize new-version handoff. No new-version profile write is permitted before this boundary.|
|Handoff|Restore the captured daemon authority and exact running-app profile/HOME/XDG environment. Required remembered nodes must become Ready; originally closed and unrelated apps remain untouched. Persist each component receipt independently.|
|Integrate and finish|Refresh shell/agent integration, aggregate scoped outcomes, retire the completed journal, and print one authoritative final result. Success/next-step advice follows required completion.|

**Any exchange, archive-promotion or required-retirement refusal before filesystem commit:** automatically restore the verified source installation, previous rollback authority and captured original startup intent before returning failure. Removal may have partially changed the displaced tree: do not swap a damaged tree back; restore from the already verified archive into fresh private same-volume storage and verify before exchange. Do not launch the rejected version or permit it to write profile data. Report the original operation/path failure plus any restoration failure, not a generic retry instruction. Confirm the restored installed version, required service and exact profile before stating that restoration succeeded.

**Crash before filesystem commit:** the next installed command resolves recorded physical identities under the lock and finishes source restoration; it must not infer commit from pathname existence. Keep both recoverable payloads if identity or restoration cannot be established. No new app is launched by a stale journal.

**Crash after filesystem commit or a handoff failure:** preserve the committed installation and resume only unfinished component work. Do not automatically downgrade after the new version may have written profile data. Report an unsuccessful required handoff truthfully, without calling publication alone completion. An unavailable newer download may still permit installed-code local repair; completed repair remains distinct from the unavailable upgrade.

Temporary removal must not be relabeled optional when it leaves another launchable/selectable application. A failed restoration remains a failure with retained recovery authority; no design can promise a successful write on an unavailable or permanently read-only filesystem. The user must not be told to do ordinary retirement/repair manually to turn a failed update into success.

## 5. The existing incomplete installation

The operator's v0.4.13 installation already ran and may have written current-version data. Recovery must not automatically roll it back to v0.4.12 merely because its older retirement step is incomplete.

Under the install lock, recognize the existing journal's source/target identities and component receipts. Preserve the active version/profile and original startup intent. Convert a confirmed retained predecessor into the verified rollback archive before retiring its exact directory; never repeat `Info.plist` mutation. A legacy disabled backup may be copied into private staging and reconstructed there only if its exact known layout and original signature can be verified; never edit the retained original in place or accept an invented version. Unknown/ambiguous states remain preserved and explicitly refused.

Do not discard completed journal records, real backup payloads or current room/profile stores to get a clean run. Retire old on-disk authority only after equivalent verified archive authority is durable. This bounded recovery of the current reported failure is in scope; general prior-version data migration is not.

The legacy public v0.4.12 caller cannot retroactively execute the newer bootstrap. Attribute its first hop separately. The already bootstrap-capable public v0.4.13 caller can transfer to a corrected future engine; verify that real caller, not a rewritten historical fixture.

## 6. Final output contract

Keep child integration commands' verbose output out of the normal update stream. Reuse their existing structured changed/unchanged/error results where available; do not infer success from copied files. Normal success is one concise installed-version/handoff result, with rollback information only when useful. No unchanged skill-file list, plugin refresh chatter or shell completion inventory.

Collect the final transaction result before printing daemon next-step advice or installation success. A failed required component must identify that component; a refused filesystem operation must retain operation, path and underlying error. If automatic source restoration succeeds, say the update failed and the previous installation was restored. If restoration fails, state that separately and preserve the journal. Do not print the same local-repair command at multiple layers. Quiet subprocess handling must not turn a nonzero/spawn error into success or hide partial integration results.

## 7. Ordered execution chunks

These are source-bound implementation tasks on the existing #1090 outcome, not duplicate feature stories or additional CI gates. After plan acceptance, add this exact checklist to #1090 and bind the active attempt to the reviewed ADR/plan commit.

|Order|Task and affected surface|Completion boundary|
|---|---|---|
|1|Archive rollback authority: `bundle.rs`, existing archive/trust utilities, optional minimal macOS filesystem bridge/build hook|Verified complete signed archives replace launchable backup directories; archive rotation and offline version-changing rollback preserve data and prior authority on refusal.|
|2|Pre-handoff filesystem transaction: `bundle.rs` publication, recovery and component ordering|No new-version startup before required retirement; real refusal restores the source automatically; interrupted states recover by recorded identities, not existence. Remove obsolete plist-retirement code/callers.|
|3|Recover the reported current incomplete state: existing journal reader and recovery paths|A staged genuine v0.4.13 incomplete transition is completed without manual cleanup, silent data deletion or automatic downgrade after current-version use.|
|4|Concise truthful CLI/app output: `update.rs`, existing shell/skill/plugin result interfaces and native Update action as affected|One final authoritative result; precise scoped errors; no unchanged bookkeeping or premature success advice. No unrelated shell/plugin redesign.|
|5|Ownership-fenced daemon endpoint cleanup: `crates/vox-core/src/node/ipc.rs`|A predecessor's normal shutdown leaves its successor's replacement socket reachable; unrelated profile/reset behavior is unchanged.|
|6|Migrate affected real-binary proof consumers and operator documentation|Extend existing update journeys for archive rollback/retirement and automatic restoration. Delete obsolete plist-mutation, fake-version and wording-only assertions; no new harness or unit/in-process tests.|
|7|Signed candidate artifacts: existing `release.yml` manual-dispatch mode and signing/assembly scripts|Unmerged exact-source normal candidate and separately labelled two-version source fixtures are signed/notarized without publishing; normal release gating and credential boundaries remain unchanged.|
|8|Run signed scratch journeys and discriminating inverses; obtain Anthropic Opus result review through OMP|Final immutable source and complete observed evidence accepted independently. A plan verdict, CI green or prior release does not substitute.|

Independent implementation work may be delegated only after the archive/journal ownership interface is fixed; one owner integrates coupled bundle/recovery edits. Run affected checks once after integration, not mid-flight in each worker.

## 8. Acceptance and evidence

Every started Vox process sets both scratch data and config roots. Native work uses the dedicated macOS guest, not the operator's installation/profile. No live-profile retry, manual permission change, new CI gate, artificial CPU cap or timing bound. Each red names PRODUCT behavior or APPARATUS staging failure. Reuse existing journeys; do not rerun an unchanged green without smoke.

|Journey|Consumer-visible verdict and retained evidence|
|---|---|
|Signed bootstrap-capable A → newer B|One `vox update` invocation transfers to B before installed mutation, finishes required retirement, preserves the exact app profile and saved message, restores Ready remembered nodes, exits zero, and emits concise final output. Observe actual source/target identities; an open lock FD alone does not prove exclusivity.|
|Offline explicit rollback and upgrade again|With release access unavailable, rollback changes to A, restores Ready service and exact saved data/profile, and preserves B for a subsequent explicit rollback. Recovery never silently reverses the committed choice.|
|Real pre-commit retirement/publication refusal|A genuine scratch obstruction makes the filesystem step fail. The command automatically restores A and its service/profile, preserves the exact saved message and prior rollback authority, and exits nonzero. B never runs against that profile. Remove only the obstruction; a normal invocation then completes.|
|Interrupted exchange and archive rotation|Using the existing interruption apparatus where applicable, stop the real owner at a real transaction boundary, then invoke the installed binary normally. Confirm the correct complete application, usable saved message, offline rollback and no stale app selection; never assert internal maps or source text.|
|Actual legacy incomplete journal|Stage the real existing journal/bundle layout, including an already-used active version and retained predecessor. A normal corrected invocation repairs it and completes the requested update without manual cleanup, silent profile changes or automatic downgrade.|
|Closed/unrelated app and required component failure|The closed owned app stays closed; an unrelated installation retains its PID/start identity. Required daemon/app failure is nonzero with precise component diagnostics; local recovery resumes only unfinished work.|
|One launchable application|Dock/identifier launch resolves to the active installation; displaced/staged copies are not selected. Rollback authority is an archive, never a disabled signed app. Pair the existing identifier/retirement journey with a real publication/retirement inverse that fails its own user assertion, not setup.|
|Output and integration|Observe real changed/unchanged integration runs and a real scoped failure. Assert the actual final outcome and exit status; no wording inventory or internal forwarding test.|
|Predecessor shutdown|Start real scratch daemon generations on replacement socket inodes; stop only the predecessor normally and show the successor still answers the installed CLI with its same node/profile. This is the previously reproduced product defect, not an internal inode-value assertion.|
|Unchanged Linux/standalone/check boundary|Only run callers whose changed code is reached. Check remains read-only; Linux standalone behavior and lossless Unix paths are preserved. Do not duplicate its already-green unrelated journeys.|

Build/signing uses the existing `.github/workflows/release.yml` and `scripts/sign_notarize_release.sh` / `sign_notarize_app.sh`, not local credentials or a new release. The existing dispatch currently requires exact-main CI and its publish job assumes a tag, so it cannot produce an unmerged reviewed candidate unchanged. Add an explicit **candidate-only manual dispatch mode** to that already registered workflow. Restrict it to the exact repository, repository-owner actor, a branch ref and an explicitly supplied immutable SHA matching the checkout; fail these checks before credentialed steps. It must reuse `apple-release`, expose only read permissions, upload named candidate artifacts and receipts, and skip Linux packaging and the entire publish job. The normal tag/main-CI release path must remain unchanged. Read-only environment metadata confirmed `apple-release` exists but has no required-reviewer or branch restrictions; do not describe nonexistent approval protections or modify its policy.

Candidate mode must produce a normal-feature candidate and separately labelled non-shipping test-knob fixtures from actual source: prior v0.4.13 at its immutable tag commit and the reviewed newer candidate source/version. Use separate build directories and existing signing/notarization/assembly scripts. Test-knob artifacts must not enter `package-release.sh` or release uploads; its refusal remains enforced. Do not rewrite signed helpers, fabricate versions or use stand-in notarization receipts. Both source-fixture versions must be genuinely compiled and signed/notarized; retain their feature selection and exact hashes. This manual artifact-production mode is not a new CI proof or release gate. Its first credentialed dispatch is itself a prerequisite to the signed journeys, and a failed dispatch/signing/notarization is APPARATUS, not a product green.


Retain exact source commits, actual compiled versions, feature selection, artifact digests, signing/notarization receipts, commands, exits, complete relevant output and whitelisted profile/process observations. A controlled-origin signed source fixture establishes its exercised filesystem/authorization behavior, not public-origin delivery. The untouched signed public-prior → normal signed candidate upgrade remains a separate delivery claim, after implementation acceptance and explicit release authorization.

## 9. Review gates and task/source reconciliation

1. Update ADR, design and all related source-bound tasks first. Keep #1090 Designing / At risk; preserve historical deliveries on #453, #987 and #993 while replacing obsolete mechanism/acceptance text. Root #429 and section #433 must point to the new source bytes. Regenerate source quotations from the committed ADR; do not hand-copy line numbers or reset unrelated source drift.
2. Anthropic Opus, invoked through OMP's stored provider connection with no credential export, reviews the exact immutable ADR/design/task packet. Review must assess the non-framework decision, native API boundary, archive trust and rotation, partial-delete restoration, crash states, current incomplete-state recovery, output, signed-artifact feasibility and every acceptance row. Resolve concrete blocking findings before product edits.
3. Chunk and execute the accepted design, retaining conforming shipped bootstrap/handoff code rather than rewriting it. Product work must not begin merely because documentation was committed.
4. Anthropic Opus separately reviews the final immutable implementation and actual runtime evidence. No acceptance-by-file-presence, installation-only green, successful retry, CI result or prior verdict closes the updater contract.
5. Merge/publication is separate work after that verdict and the existing checks. Published artifacts remain immutable; never present this proposed plan or a source-fixture run as a fourth completed corrective release.
