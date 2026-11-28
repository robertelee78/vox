# Optional proofs: the troubleshooting kit

These are real proofs. Each drives the shipped `vox` as a person would and asserts what the person sees or gets. But each one is too heavy, needs a live model, or times something that only a real machine can measure honestly, so **none of them blocks anything** (decider, 2026-10-01: "Fully optional"). They block neither CI nor `scripts/release-gate.sh`.

They are kept "at the ready for troubleshooting". When a user reports one of the symptoms below, run the matching proof.

## How they are kept

- **One switch.** vox-tui's cargo feature is `optional-proofs`. `heavy-proofs` is an alias for it, kept for branches that still name it.
- **Without the feature they are loud, not silent.** Each optional test is compiled only with the feature (`#[cfg(feature = "optional-proofs")]`). Without it, a stand-in of the same name takes its place, in the module `optional_proof_not_run`. One macro makes the stand-ins: `not_run!` in `crates/vox-tui/tests/support/optional_proof.rs`, which every optional file invokes with its optional tests' names.
  - In a build **without** `optional-proofs`, a listing (`-- --ignored --list`) shows `optional_proof_not_run::<test>`, never nothing. Never list a build **with** it workspace-wide (see the ban below).
  - A run without `--ignored` shows it `ignored, OPTIONAL PROOF NOT RUN: enable with --features optional-proofs …`.
  - A run with `--ignored`, as in CI and `scripts/release-gate.sh`, prints `OPTIONAL PROOF NOT RUN: <file>::<test> needs --features optional-proofs …` past the test harness's capture, and passes. An optional proof blocks nothing.
  - An optional half of a blocking file is a separate test, so the blocking half still runs.
- **With the feature they run for real.** Nothing is excused, and `VOX_PROOF_ALLOW_UNPROVEN` is not read by any of them.
  - A missing prover fails as `CANNOT MEASURE`, naming what is missing. A missing prover is `opencode`, its login, or a network.
  - A product failure fails as the product's verdict.
- **CI compiles them on every run and never runs them.** The CI step is "Compile optional proofs (not run; troubleshooting kit)": `cargo test --release -p vox-tui --features optional-proofs --no-run`, with `-D warnings`. A change that breaks one is caught at once, not on the day it is needed.

### First post after leaving and rejoining (ADR-052 RG-6)

`a_room_can_be_left_and_ended_proof::a_node_that_left_rejoins_and_posts_at_once`
leaves, rejoins once, posts immediately, and requires the other member to read that post.
Run with `--features test-knobs,optional-proofs --test a_room_can_be_left_and_ended_proof a_node_that_left_rejoins_and_posts_at_once -- --ignored --exact --nocapture`.

`an_unheard_departure_keeps_the_left_copy_until_a_member_returns` takes the only
other member offline, checks the bounded refusal and retained-copy words, then brings
the member back and requires a once-only rejoin and immediate post to be read.
`a_waiting_rejoin_does_not_hold_independently_deferred_other_room_commands` holds
only the other room's local receiver and requires its independently deferred post,
read and trust command to answer before the waiting rejoin. Run either with the same
command, substituting its exact name; both need `test-knobs`, and the held-receiver
act needs an exclusive proof slot.
`creator_end_wound_down_while_away_clears_the_verified_checkpoint` keeps the node that
left stopped until the creator has ended the room and both members have closed it, then
requires its rejoin to be told the room has ended and its checkpoint to be cleared.
`a_waiting_rejoin_is_answered_when_its_left_copy_is_deleted` leaves a room while its only
other member is offline, steps the leaver's product clock past the room's idle end, starts a
rejoin that waits on the unheard departure, deletes the ended left copy with `vox room leave`,
and requires the waiting join to be answered as an ordinary join, never "shutting down". It
needs `test-knobs` and is run with the same command, substituting its exact name.

### Reading during a daemon restart (ADR-052 RG-9)

The daemon journey stages a real restart with its old node's stop held by a file. A room read,
status, room list and node list issued in the socket gap wait for the single replacement.
A separate act kills the unmanaged restarter during that held stop and observes a serving
replacement before any client that could start a daemon. Both use private profile roots.

```sh
cargo test --release -p vox-tui --features test-knobs \
  --test the_daemon_and_its_nodes_proof \
  a_room_read_during_restart_waits_for_one_replacement -- --ignored --exact --nocapture
cargo test --release -p vox-tui --features test-knobs \
  --test the_daemon_and_its_nodes_proof \
  a_restart_caller_killed_during_stop_leaves_a_daemon_serving -- --ignored --exact --nocapture
```

### Room-by-room computer trust (ADR-052 RG-3)

The trust journey in `nodes_of_one_daemon_proof.rs` uses scratch computers and
the real `vox` commands. A departed room must not strand the node's saved keyring;
adding a paired node must not refuse another room's posts or link. The held-room
proofs pair the departing computer and trust the requester independently. A causally
held withdrawal refuses only that room's posts and sender keys, then resumes without
a restart or another policy event. Manual removal also retains its room's withdrawal
stage while refreshing permissions, rather than repeatedly starting that withdrawal
over; the existing manual-removal and through-log re-trust journeys cover this path.
Posts that meet a new computer revision before native publication retain their
original command queue credit until the saved keyring is current; their room's
withdrawal fence still decides whether they may be written.
The consent cursor survives every page. A newer trust list restarts only that room's
reconciliation. Every failed trust turn uses the existing one-second retry while
ordinary room governance continues; the saved manual command reports incomplete
withdrawal rather than waiting for a permanent fault. Installing a keyring refreshes service reachers,
independent of room withdrawal. A new manual grant dials the requested member and
waits for its existing owed-consent pass before acknowledging the command.
A closed room with saved withdrawal debt defers authoring Session refresh until its
preparation trust stage has withdrawn the old reader. It can then open, without
weakening the record or key fences; the existing closed-room removal proof covers it.
The post-race act uses the existing text-publication hold to change the durable
revision before the original post is admitted; the same command must succeed and
its shipped JSON read must show exactly one copy. At a held withdrawal, a pending
computer application receipt is judged by other-room post/read progress until the
receipt is consumed, not by which independent task publishes its marker first.
The post proof first shows that both removed and surviving readers could read, then
counts completed other-room exchanges until its own post is accepted, then waits for
the surviving reader and ten completed exchanges before checking that the
removed reader sees no post after withdrawal. To stage a key queued before withdrawal,
set `VOX_PROOF_RG3_QUEUED_KEY=1` for the held-key proof; it uses the existing pairwise
key hold and retains the same user-facing no-key assertion.
The focused manual-removal act counts accepted/read other-room posts while the saved
removal finishes; it judges the terminal result after at most 100 such observations,
not after an elapsed wait. Its projection-stage mutant must fail that counted claim.

Run each named proof separately, with exclusive build-slot ownership for the hold:

```sh
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test nodes_of_one_daemon_proof \
  a_trust_change_skips_a_left_room_and_additions_refuse_no_posts -- --ignored --exact --nocapture
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test nodes_of_one_daemon_proof \
  an_unfinished_room_refuses_only_its_own_posts_then_finishes -- --ignored --exact --nocapture
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test nodes_of_one_daemon_proof \
  an_unfinished_room_releases_no_key_until_its_withdrawal_finishes -- --ignored --exact --nocapture
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test nodes_of_one_daemon_proof \
  a_post_racing_a_trust_revision_is_saved_once -- --ignored --exact --nocapture
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test nodes_of_one_daemon_proof \
  a_saved_manual_removal_finishes_while_another_room_posts -- --ignored --exact --nocapture
```

### Computer removal (ADR-052 RG-8)

The pairing journey in `nodes_of_one_daemon_proof.rs` also covers saved room choices:
`computer_removal_resumes_its_saved_room_choices_after_restart`,
`computer_removal_keeps_rooms_without_offering_removed_nodes`,
`computer_removal_reconciles_absence_before_a_fresh_join`,
`computer_removal_checks_a_locked_nodes_rooms_when_it_opens`,
`computer_removal_names_a_room_without_a_local_admin`,
`computer_removal_offers_only_a_fresh_basis`,
`a_fresh_admission_survives_a_still_pending_computer_eviction`, and
`computer_removal_evicts_before_old_trust_can_be_called_new`.
Run one name at a time with
`cargo test --release -p vox-tui --features test-knobs,optional-proofs --test nodes_of_one_daemon_proof <name> -- --ignored --exact --nocapture`.
The restart and absence acts use causal holds and require an exclusive proof slot.
Removal choices are local state saved atomically with the unchanged three-field signed
computer removal event. An event with no local choice keeps room memberships. Choices,
completion and rooms checked on first unlock share the existing computer snapshot;
unfinished work uses the room's existing one-second governance retry, not a separate
removal worker or journal.
A pending eviction finishes without evicting a node this computer presently trusts
again, individually or through its current computer group. The finished row disappears
from status. A fresh admission alone is not enough in a room closed at removal: the
saved removal has no room-feed frontier with which to date that admission.
"Trusts again" counts only once this node has applied the current computer policy; until
then the row retries on that same deadline and stays pending in status.
`computer_removal_evicts_before_old_trust_can_be_called_new` runs a governance turn while
the removal's policy send is held. Its mutants, selected with `VOX_MUTANT_FX28`:
`stale-removal-window` lets only that turn past the policy gate (expected green);
`stale-removal-window-unchecked` also drops the applied-policy condition (expected red).
Each accepted removal also keeps this computer's existing-node offer obligations and
per-room basis cutoffs in that same snapshot. Until a room's cutoff is captured it
offers none of that computer's nodes; afterwards only pre-removal bases are suppressed.
A deliberate fresh join or consent is offered normally. Closed rooms capture before
their first exchange on reopening; a node created after the removal inherits nothing.

### Linux kernel-keyring proofs

The dedicated typed-unlock, restart and unavailable-keyring journeys must run as a disposable
container user, with `VOX_PROOF_DISPOSABLE_KEYRING=1` set by the container runner. Use a fresh
UID and check `keyctl show @u` before and after each proof. A killed proof can leave a test key
until reboot and use that UID's key quota; remove the container and its user after the run.
For example, inside a disposable Linux build container as its fresh, dedicated UID:
`keyctl show @u; VOX_PROOF_DISPOSABLE_KEYRING=1 cargo test --release -p vox-tui --features test-knobs --test the_daemon_and_its_nodes_proof a_linux_typed_unlock_survives_another_sessions_daemon -- --ignored --exact --nocapture; keyctl show @u`.
The container runner must check the two keyring listings even if the proof fails.

Other proofs that type a Linux unlock or setup can also store a test key in the user's keyring.
They remove their own keys on normal exit, but a killed proof can leave one. Inspect with
`keyctl list @u`; after identifying the exact `us.vox.node:<digest>` for the scratch node,
remove only that serial with `keyctl unlink <serial> @u`. Do not clear the user's keyring.

### Managed daemon recovery (ADR-052 RG-9)

The optional Linux systemd journey in `the_daemon_and_its_nodes_proof.rs` supplies a minimal
`Restart=on-failure` user unit with private profile roots, then removes it. Vox ships no
systemd unit or manual enrollment instructions. A managed daemon stopped by a signal exits 71
after clean shutdown; explicit product Stop exits 0. The journey checks recovery independently
of client auto-start.

```sh
cargo test --release -p vox-tui --features optional-proofs,test-knobs \
  --test the_daemon_and_its_nodes_proof \
  a_systemd_user_unit_recovers_foreign_signals_and_honors_product_stop \
  -- --ignored --exact --nocapture
```

Run it only inside its disposable `vox-rg9-…` container with a real systemd user session and
`VOX_PROOF_SYSTEMD_CONTAINER` naming that container. There is no `vox daemon stop` subcommand;
the proof sends the existing public control Stop request.

The macOS guest journey loads the bundle's shipped launch agent with scratch bindings and
boots it out even on failure. This establishes keep-alive behavior, not signed SMAppService
enrollment or approval; those belong to the release journey.

For the recovery-only guest journey, first build the helper in a shared build hold, then run:

```sh
python3 scripts/app-proofs-vm.py --recovery-vm /absolute/prebuilt/vox \
  apps/macos/Bundle/LaunchAgents/us.vox.daemon.plist /absolute/receipt-directory
```

This route requires the existing stopped `vox-app-proofs` guest, snapshots supplied artifacts,
does not resize it, and leaves it stopped. It stages a private node, requires a launchd-owned
replacement before any healing client, checks `vox status`, and sends public control Stop.

The same prebuilt runner's `--restart-vm` route kills a real `vox daemon --restart` caller
while its old node's stop is held by a file. It requires one launchd replacement before any
healing client, the daemon's own clean SIGTERM-stop words, and a successful status on that PID:

```sh
python3 scripts/app-proofs-vm.py --restart-vm /absolute/prebuilt/vox \
  apps/macos/Bundle/LaunchAgents/us.vox.daemon.plist /absolute/receipt-directory
```

Build with `test-knobs` for the hold. It uses the same scratch bindings and always boots out
the owned job and stops the guest. A login-item restart is one `launchctl kickstart -k`;
the shipped job gives its daemon 35 seconds to finish stopping. It restarts a loaded job, not
an absent one. A failed request is reported with launchctl's error.

### macOS update recovery (ADR-014 M-29a)

For a newer release, `vox update` downloads and verifies its updater before transferring the
same invocation to it. The target owns the transition lock, retained local recovery and the
new installation. Repair does not suppress an available newer upgrade. If release lookup or
engine download is unavailable, installed code can still finish retained local work; that
repair is reported separately from the failed upgrade. `--check` remains read-only and
`--rollback` remains local. A repair of a committed rollback must not exchange the bundles again.

The existing controlled bundle and daemon journeys require `VOX_PROOF_NEXT_BINARY` to name a
genuinely compiled next-version helper, built with `test-knobs`; for workspace version
`0.4.14`, their existing next-version convention is `9.4.14`. A `--version` script or patched
version string is not a next-release binary. Their release fixture serves that exact signed
helper and tag-pinned app records. Native app launch/registration claims remain in the signed
guest journey below; the controlled CLI bundle fixture does not establish them.

The prebuilt `--bundle-vm` route runs the existing controlled update journey in the stopped
`vox-app-proofs` guest. Supply the genuinely compiled next-version helper and the prebuilt
`update_proof` executable from the same source state:

```sh
VOX_PROOF_NEXT_BINARY=/absolute/vox-next \
VOX_PROOF_UPDATE_HARNESS=/absolute/update-proof \
VOX_PROOF_BUNDLE_AFTER_SWAP=1 \
python3 scripts/app-proofs-vm.py --bundle-vm /absolute/prebuilt/vox \
  apps/macos/Bundle/LaunchAgents/us.vox.daemon.plist /absolute/receipt-directory
```

Build the helper and proof with `test-knobs,optional-proofs` before the guest execution.
The journey holds before exchange, kills the updater's process group, reads the saved room,
then interrupts the published update before the manager request and uses ordinary `vox update`
to finish the existing journal. It also reads during the manager's held stop, including an
explicit `vox daemon --restart` whose caller is killed. All processes, the launch agent and
profile belong to scratch; the outer runner boots out the job and stops the guest on failure.
Take `/tmp/vox-guest.lock` for each run, releasing it only after the guest is stopped.

`VOX_PROOF_BUNDLE_PRECOMMIT=1` selects the existing abort-after-exchange condition and checks
that the old daemon keeps serving and ordinary offline recovery restores the original release.
`VOX_PROOF_BUNDLE_UNMANAGED=1` instead runs the existing controlled-bundle update with its
client-started daemon and no login item.

The CLI preserves a stopping refusal's daemon PID internally and confirms login-item ownership.
It observes one replacement without starting a daemon. The whole wait has one cap: launchd's
printed exit timeout plus minimum runtime plus the existing ten-second greeting patience.
Phase changes never reset it. A missing, disabled or inactive job ends the wait, as does the
run count passing the first replacement without a greeting. Missing or changed manager fields
fall back to the old fixed ten seconds. End-of-wait advice describes the current state;
a deliberately stopped job does not promise a future replacement.
When no socket answers, commands also check whether the matching account's login item has a
spawn pending. They wait for it rather than advise starting a daemon that would race launchd.
`vox status` uses this same admission before its daemon-only node inventory.
A prompt hook recognises a restart from the unmanaged restart lock, a daemon's typed stopping
refusal, or a matching pending login item. It spends one existing ten-second registration
patience, measured from hook entry, on the replacement's greeting, registration, node and
selected room preparation, and this turn's room news. At that bound it gives the existing
next-turn deferral without advancing the news cursor. A cold start keeps its existing 500ms
probe/start path and immediate preparation response. An unfinished login-item check starts
nothing and tells the agent to retry next turn, not to restart a daemon that may not exist.
An unrecognised manager layout keeps the existing cold-start fallback; it is not evidence
of a restart. The managed command wait says the login item will start or replace the daemon.
The restart/news act in `the_daemon_and_its_nodes_proof` posts from another member, checks
same-turn delivery with a held and a killed restarter, then holds replacement attachment
past the hook patience and checks truthful deferral followed by next-turn news.
The native OMP preparation uses the same restart/node/room wait; a bounded deferral completes
its existing envelope/decision exchange and consumes no room news. Saved decisions still finish
without rereading daemon state. The existing guest pending act also checks `vox status`, and
`VOX_PROOF_HOOK_STOP_DETECTION=1` checks hook detection while the managed daemon is still stopping.
The guest `--restart-vm` route accepts `VOX_PROOF_SHIPPED_DEFAULTS=1` with
`VOX_PROOF_PENDING_START=1`: the shipped job has only its helper path adapted, and uses the guest
user's default roots. The act preserves and restores any prior guest root. `VOX_PROOF_SLOW_HOOK_CHECK=1`
holds only the check (`test-knobs`) with no loaded job and checks the real hook's truthful answer;
`VOX_PROOF_ROOT_PRECEDENCE=1` also creates and lists distinct nodes through XDG, environment and
explicit root precedence. Product and manager root resolution share `vox-core::node::paths::roots_with`.
The managed-client wait is built and proven for the macOS login item only. Linux keeps its
existing immediate stopping refusal; there is no new systemd progress observer. Vox ships no
user unit. The existing disposable Linux proof supplies `Restart=on-failure`, `RestartSec=1`.
There is no wire-frame change: an older daemon gives its existing refusal, and an older client
keeps its existing behavior.

The same prebuilt managed route stages absent manager fields and removes the owned job while
the client waits; the real client's exit1 must name the stopped daemon and missing replacement:

```sh
VOX_PROOF_REMOVE_MANAGER=1 VOX_PROOF_MANAGER_FIELDS_ABSENT=1 \
python3 scripts/app-proofs-vm.py --restart-vm /absolute/prebuilt/vox \
  apps/macos/Bundle/LaunchAgents/us.vox.daemon.plist /absolute/receipt-directory
```

On that same `--restart-vm` route, `VOX_PROOF_FAIL_REPLACEMENT=1` occupies a private listen port
and makes subsequent managed launches use it; the real daemon exits before greeting, and
the waiting client must end with the failed-replacement words rather than follow a respawn loop.
`VOX_PROOF_PENDING_START=1` issues `vox daemon --detach` during a young job's scheduled spawn;
it must use the one login-item generation, never create a competing daemon.

Build with `test-knobs` for this field-absence staging, which changes no product wait rule.
An unpaused read can reach the replacement while its room prepares saved history and exit1
with `that room is preparing its saved history`. This act keeps the waiting read live through
the manager's phases, then holds it only after the replacement's greeting and before Use.
It waits on the public saved-room result and releases that same read. Preparation observations
and greeting-to-readiness intervals are printed; no room-readiness product behavior is changed.

`VOX_PROOF_LOGIN_ITEM_NEWS=1` on the `--restart-vm` route (helper built with `test-knobs`) is
RG-9's proof that a prompt typed during a login-item restart gets its news in that turn. A second
scratch account on the guest joins a room and posts. The login item's daemon is replaced only
after `ps` shows it has run past launchd's printed minimum runtime. It is replaced in three ways:
by SIGKILL, by `vox daemon --restart` (one `kickstart -k`), and by the update's handoff (the same
`kickstart -k` after the helper is swapped for a re-signed copy). A real hook is typed while
launchd replaces the daemon, before the replacement greets. It must carry the other member's
message in that turn, with exactly one launchd run added. The arm also stages launchd's
throttle: the replacement is killed as launchd spawns it. launchd prints `spawn scheduled` and
spawns again only once the minimum runtime since that spawn has passed. A prompt typed at that
kill and answered before any replacement greets must give the next-turn deferral, and the next
turn must carry the message. That turn's staging has about half a second between the hook's
answer and the replacement's greeting; on a loaded host it can stop as APPARATUS, which is not
a product verdict. Not staged here: peers that do not answer while the old daemon stops, a
Keychain prompt after an update, the first launch of a freshly installed signed helper, and an
item registered through `SMAppService`.

There are two mutants. `VOX_MUTANT_HOOK_RESTART_IMMEDIATE=1` (forwarded to the hook) fails the
crash turn's same-turn assertion. That prompt finds no socket and takes the hook's
restart-admission path. The knob does not reach the `vox daemon --restart` turn, whose prompt
meets the old daemon still stopping and follows the restart in `restart_refusal`. That turn's
mutant is an uncommitted source edit: in `crates/vox-tui/src/agent_hook.rs`, `restart_refusal`,
remove the macOS-only statement that adds `pending_login_item(account)` to `restarting`, build
the helper with `test-knobs`, run the arm, and put the statement back.

`VOX_PROOF_GAP_TIMELINE=1` instead prints a millisecond timeline of each restart kind, three
samples each, and asserts nothing about latency. `VOX_PROOF_GAP_SPIKE=1` with it compares
launchd's throttled spawn with a second `kickstart` and with `ThrottleInterval 1`.

Item 46's cached-flag clause has NO change in this release. A genuine native-app probe found
the captured AppKit flag stale after quit, while the fresh lookup returned nil and the kernel
process was a zombie. Current `still()` already guards this divergence through its nil check.
A force-quit probe found the fresh flag still false/non-nil while the paused process stayed live.
Neither requested unguarded divergence was produced; the owner's original trigger remains
UNKNOWN. Whether RG-9 closes with this clause unbuilt is the owner's decision.


On macOS, daemon restart recognizes a kernel zombie state or native process-lookup `ESRCH`
as stopped even if the terminal or service-manager parent has not reaped the PID yet.
A live process, permission refusal, or unknown query failure is still waited for; this does
not change the existing shutdown bound.

Before filesystem commit, the updater preserves and round-trip-verifies the source as an
authenticated rollback archive. It quits the captured app and exchanges intact bundles while
the old daemon still serves. A login item is replaced by one manager-owned `kickstart -k` after
retirement; without a login item the captured daemon is stopped after exchange. The displaced
tree is retired before new-version startup. A precommit refusal restores the source from its
verified archive, not a possibly partially deleted tree. A postcommit handoff failure resumes
unfinished work without an implicit downgrade.

A signed update/identifier-launch/rollback measurement must retain both release bundles'
original signed helpers, verify the restored signature and unchanged signed plist, inspect exact
LaunchServices records, and observe the bundle actually selected by identifier. An ad-hoc fixture
or rewritten helper cannot establish that claim. Perform registration work only in a dedicated
proof guest; clean only this run's exact scratch bundle and extension paths.

Run the optional signed journey in that guest:

The unmodified proof requires a logged-in GUI session, `python3` on `PATH` for its existing
loopback release server, and `/usr/bin/swift` for its native launch observers. A pristine macOS
restore image does not include Command Line Tools. Supplying a real private Python runtime is
apparatus setup; a run that substitutes precompiled copies of the existing Swift observers must
be reported as a derived spike, with its source/dispatcher hashes, not as the unmodified proof.

```sh
VOX_DATA_DIR=/absolute/scratch/data VOX_CONFIG_DIR=/absolute/scratch/config \
VOX_PROOF_PREVIOUS_SHIPPED_APP=/absolute/signed-prior/Vox.app \
VOX_PROOF_SHIPPED_APP=/absolute/signed-candidate/Vox.app \
VOX_PROOF_LEGACY_PRODUCER_APP=/absolute/signed-old-producer/Vox.app \
cargo test --release -p vox-tui --features optional-proofs,test-knobs \
  --test update_proof -- --ignored --exact \
  an_update_and_rollback_leave_one_launchable_vox --nocapture
```

For current-source recovery evidence, assemble a genuine native prior bundle and a newer
candidate from the same source with only the workspace-version delta. Both helpers must be
built with the existing `test-knobs` feature: publication and its interruption now belong to
the downloaded target, so a knob compiled only into the prior or test runner cannot stage it.
The journey checks the supplied helpers as an apparatus precondition. Developer ID sign and
notarize both complete bundles before supplying them; change neither after signing. Record
the source delta, versions, feature selections, artifact digests and Apple's receipts.
The legacy producer is a separately source-bound old updater artifact, with a version strictly
between the prior and candidate, signed and notarized with its original helper. It must support
the existing test-knob release transport. Without `VOX_PROOF_LEGACY_PRODUCER_APP` the ordinary
update/rollback cases still run, but the old-journal cases are not exercised. Record the old
source revision, build features, exact artifact digest and notarization receipt independently.

This source-bound interruption proof is not normal-artifact release-trust evidence. Record
the untouched public-prior → normal public-candidate upgrade separately, using the published
release endpoint and normal signature checks. Before publication, controlled loopback target
execution requires test-knobs and cannot establish normal-artifact delivery. An older public
caller without the bootstrap still cannot establish pre-publication target ownership.

The existing journey drives `install.sh`, the physically installed helpers, an open app's
retirement and replacement, identifier launches, two version-changing offline rollbacks, and
real interruption immediately after exchange followed by offline source restoration. Its
consumer assertions require the saved message and Ready remembered node after each transition.
The `stopped-app` case wedges the open app (SIGSTOP: a hung main thread answers no quit
request) before `vox update`, and requires the update to complete, to say `Vox.app did not
quit on request; it was stopped`, and to leave one running replacement; the ordinary case
requires `Vox.app quit on request` (the decider, 2026-11-11: `vox update` always updates).
The interrupted case also substitutes a separately copied, still-signed bundle and requires
the installed updater to refuse it. It then restores the original object, preserves the
original journal bytes, perturbs its two diagnostic device fields in scratch, and requires
successful recovery and real profile use. This is object-substitution and device-perturbation
sensitivity evidence, not evidence of a reboot or volume remount.

For retained device-number recovery, preserve the genuine old updater's original journal and
source/artifact receipts. Use an old producer, not a current build with a changed version or a
handwritten journal. Stage its committed archive-bearing handoff with the app already complete
and daemon incomplete, then invoke the installed old helper's ordinary `vox update` against a
newer corrected signed engine. Record both profile roots, selected artifacts, command output,
the saved node fingerprint and room identity, existing message read, and a new post/read. Observe
the historical app handoff separately from any later legitimate update handoff. A scratch-only
device-field perturbation is an apparatus sensitivity check, not evidence of a reboot/remount.
With the old producer supplied, the journey holds the scratch node's UDP address after the
old daemon releases it, so the real producer can retain a failed daemon handoff. It confirms
the native app handoff, quits that replacement, and checks recovery does not launch another
app. It runs once with the unmodified journal and once with a scratch-only device perturbation;
the latter also exercises corrupted archive and signature refusals and a changed readoption
target. Failure to occupy the address or obtain the required journal is APPARATUS, not proof.
Run invalid archive, changed receipt, copied-object and different-volume refusals separately;
retain their state and distinguish product refusals from staging failures. A rollback recovery
must also be measured offline against its locally retained prior archive.

Run the real precommit filesystem-refusal/partial-delete restoration and genuine already-used
legacy incomplete-journal scenarios separately under the same signed trust and scratch rules.
Pair one-selectable-app evidence with a genuinely compiled/signed nonshipping retirement
inverse; it must fail the named product assertion, not setup, trust verification or cleanup.
Plist-renaming inverses are obsolete: current rollback authority is an authenticated archive.

## Manual checks (Vox.app, macOS): run by a person before tagging

No automated proof reaches these, so a person runs each of them before a release that ships Vox.app is tagged (ADR-014 M-33). A manual check is **never** reported as proven by automation, and nothing here passes because a proof was green. Each check is either run and recorded, or the tag waits.

Run them on an Apple Silicon Mac with macOS 13 or later, using **the signed, notarized release candidate**: install it with `install.sh`, never a debug build. Use a scratch data root (`VOX_DATA_DIR` and `VOX_CONFIG_DIR` set to fresh directories) and a second node in another scratch data root as the peer. Never use a real data root.

| Check | What the person does | What they must see |
|---|---|---|
| `manual.login_item` | Open Vox.app for the first time and accept its request to keep the daemon running. Open System Settings, General, Login Items. Quit Vox, log out, and log back in. | The first-run request says what the login item does: Vox keeps your rooms reachable while you are logged in, even with the app closed (M-8). Login Items lists Vox as allowed in the background. After logging back in, with the app still closed, the peer can read a post this node's room received. Vox > Turn Keep Running Off, chosen while Vox runs, removes Vox's login item from Login Items (it no longer runs at login); Vox > Keep Running While Logged In puts it back, asking for approval again, and offers to keep the attached node at once: type its passphrase and choose Store in Keychain; the node then shows as kept in `vox node list`, and stays attached after Vox quits. |
| `manual.keep_running` | Open Vox.app for the first time and choose Keep Running. Pick a node that has a passphrase; type it, turn on "Store the passphrase in the Keychain", and attach. Quit Vox. Restart the Mac, log in, and leave Vox closed. Then open Vox again and quit it, and repeat with the toggle off. | With the toggle on, the form says that anyone who can unlock this Mac's login keychain can then attach the node (ADR-028 K-10). With it off, it says that your rooms are reachable only while Vox is open. With it on: after quitting, `vox node list` shows the node attached and `(kept)`; after the restart, with Vox still closed and no prompt shown, it is attached again and the peer can read a post this node's room received. With it off: quitting detaches the node. |
| `manual.lan_helper` | In Vox.app, open a room and choose Allow the LAN Helper. Approve the helper in System Settings when it asks. First, without sudo, build the check's mutant: a `vox` whose LAN helper skips its uid check (in a scratch worktree, change `if uid != owner` in `serve_one`, `crates/vox-tui/src/lan_cli.rs`, to `if false && uid != owner`, then `cargo build --release -p vox-tui --bin vox`). Then, from the repository, run `sudo scripts/family-lan-proof.sh --registered-helper /Applications/Vox.app --owner-mutant <that vox>` (it uses the helper launchd runs, and starts only the mutant's helper of its own, on a socket in its scratch directory). Last, choose Remove the LAN Helper. | Before approval, the app says what approval grants: one root process that creates network interfaces for Vox and nothing else (M-12). System Settings lists the helper for approval. After approval the family LAN is offered, and before approval it was not. The script prints `PASS  owner: the registered helper serves only uid <yours>, who owns Vox.app; root and nobody were refused` and `PASS  mutant: check 0 goes red against a helper with its uid check skipped (root was answered)`, then passes its LAN checks 1 to 7 with no `sudo vox lan helper`. This holds when another copy of Vox.app registered the helper before. Remove the LAN Helper stops the helper: `launchctl print system/us.vox.lanhelper` finds no service, and the family LAN is no longer offered. |
| `manual.notification_under_focus` | Turn on a Focus, such as Do Not Disturb. From the peer, post an ordinary message, and then an urgent message addressed to this node. | Each notification is local and grouped under its room, and its message text is hidden by default (M-23, ADR-028 R-10). The ordinary message waits behind the Focus. Record whether the urgent one came through: M-23 allows it to be time-sensitive but does not require it. |
| `manual.share_extension` | **The one check run in the decider's own Mac login, not a scratch data root** (the decider, 2026-10-06): the extension is launched by the system, not from a shell, and is sandboxed to `~/Library/Application Support/vox`, so it only ever uses that login's own node. Make one small file named as a test file (for example `vox-share-extension-test.txt`, a line of text). In Finder, choose Share, then Vox, for that file; choose one of your own rooms, and send it. Then share the same file with the Finder Services item "Share to Vox Room". Afterwards stop both shares: `vox share stop <room> vox-share-extension-test.txt`. | The file appears on the room's timeline as a share with that name, and a member's node pulls it (M-24, ADR-028 F-1). After the stop, `vox share list <room>` no longer lists it. |
| `manual.quick_look` | Pull a file the peer shared. Open it from its card. | It opens in Quick Look from the card, after verification (M-24, ADR-028 F-11). |
| `manual.menu_bar_extra` | At first run, leave the menu bar extra off. Then turn it on in Vox.app. | It is off until turned on (M-22). Once on, it shows the node's state and its keyring window (for example `keyring open 23m`), rooms with messages addressed to this node, the services shared to it with copy buttons, its own shares with stop, and live tunnels (ADR-028 A-3, K-9). |
| `manual.update_keychain` | The decider's first real update of a Vox that remembers nodes: from a Developer ID signed and notarized release with nodes attached and remembered (a passphrase typed once), run `vox update` to the next signed release. | No Keychain window of any kind appears (no access prompt for the new binary, no "Keychain Not Found"), and `vox node list` shows every remembered node attached afterwards, with nothing typed. The fresh-user journey cannot measure this: in scratch the old and new `vox` are one binary, so its code signature never changes (it measures `J7.update.attached` and `J7.update.no_keychain_prompt` on a scratch keychain file). |

### Recording a run

Before the tag, the person who ran the checks adds one line per check to the release's tracking issue, in this form:

```
manual.<check> — v<version> candidate <sha> — run by <who> on <date>, macOS <version> — seen | not seen: <what was seen instead>
```

A `not seen` is a defect in this release. It is fixed before the tag, never carried forward (AGENTS.md, Releases). A check nobody ran is recorded as not run, and the tag waits.

## The fresh-user journey: run before every tag

One optional proof is run before every release tag, as the manual checks are: `fresh_user_journey_proof::a_fresh_user_gets_from_install_to_an_agent_working_in_a_room` (v0.4.3). It blocks no CI run. The person tagging runs it on an Apple silicon Mac with `claude`, `codex`, `opencode` and `tmux` on `PATH`:

```
cargo test --release -p vox-tui --features optional-proofs,test-knobs --test fresh_user_journey_proof -- --ignored --exact a_fresh_user_gets_from_install_to_an_agent_working_in_a_room --nocapture
```

It takes a scratch HOME and data root with no node, no keychain item of Vox's and no Vox wiring in any harness, and walks the whole journey with the shipped binaries: `install.sh` from a loopback release of this build, `vox setup` answered at a terminal as a person answers it, Claude Code, Codex and OpenCode started in a stub repo (each confined, offline, against the stand-in model), what each session says is missing and the one command for it, the repo's room asked of the person and bound, trust both ways with drive, an agent's post read by the person, an interactive Claude Code session found, driven and renamed from Vox, a daemon restart and `vox update` that keep every node attached and every skill and hook in place, the next action named at the end of every flow, and every hook path answered in under 1 s with one sentence. It prints every claim with its verdict, `PRODUCT`, `APPARATUS` or `CANNOT MEASURE (precondition unmet)`, and is red until every claim passes. Record the run on the release's tracking issue as a manual check is recorded (`journey.fresh_user — v<version> candidate <sha> — …`); a red is a defect in this release, and the tag waits.

## Running one

- Run from the repository root, on a machine doing its ordinary work.
- Run **one test at a time**, by its exact name, as each row shows.
  - There is no default elapsed watchdog. A progressing proof is allowed to take as long as its
    work takes; its product and structural assertions decide whether it passed or wedged.
  - For an unattended run, the operator may set a positive `VOX_TEST_WATCHDOG_SECS` emergency
    timebox for the whole test binary. If it expires, the helper gathers diagnostics and cleans
    descendants, but the result is only `NO RESULT`/`CANNOT MEASURE`, never a product or release
    verdict. Two tests run together would share that explicitly chosen emergency timebox.
- The first run compiles vox-tui with the feature. Later runs reuse the build.
- Every command here also enables `test-knobs` (#300): several optional proofs stage with a `VOX_TEST_*` knob, which only a `test-knobs` build of `vox` reads. Without it, such a proof stops at `CANNOT MEASURE` naming the knob.

"Time" is the release run's `finished in` from CI run 36830124620 (2026-10-01, ubuntu and macOS runners), the last run before these proofs left CI. The two figures are ubuntu / macOS. It is a guide, not a bound. A row says "not timed" when CI never ran that proof for real: CI had no model account.

## Session paging at scale (ADR-034 FR-6)

`a_large_room_reads_whole_proof::a_hundred_thousand_entry_session_opens_in_one_second_with_bounded_memory`
records 100,000 entries through a real daemon, then opens the Session from a separate app-client
process. It reads every page with a four-page viewport: newest and each older page must arrive in
under one second, and both processes must stay under 50 MiB resident. It is optional, was **not
run** for the paging change, and blocks neither CI nor release. CI compiles it. Run on demand:

```sh
CARGO_BUILD_JOBS=2 cargo test --release -p vox-tui --features optional-proofs --test a_large_room_reads_whole_proof a_hundred_thousand_entry_session_opens_in_one_second_with_bounded_memory -- --ignored --exact --nocapture
```

## Agent retry ownership (ADR-052 RG-4)

The optional acts in `agent_hook_proof` drive the generated, shipped OMP extension with
`support/omp_turn_host.mjs`, the existing recorded-reproduction host stand-in, not a model.
Each process uses scratch data and config roots. Run one exact act in release with
`--features test-knobs,optional-proofs -- --ignored --exact <name> --nocapture`:

- `a_native_omp_conversation_survives_a_decided_turn_restart`: physically pauses the replacement
  daemon during a held turn; later room news must appear once in the same conversation.
- `a_native_omp_turn_without_a_decision_stays_uncertain`: preserves the undecided refusal.
- `a_native_omp_conversation_finishes_a_decision_after_a_room_move`: holds a real saved
  attention receipt across an operator room move; the next hook finishes it and new-room news
  is shown once. The old Session must be reported ended before that hook.
- `a_native_omp_conversation_finishes_a_decision_after_a_session_resume`: ends and resumes the conversation's
  Session in its original room while a decided receipt is pending; the next hook finishes and
  later news is shown once.
- `nine_restarted_sessions_wait_for_registration`: nine real hooks contend on the kernel lock.
- `a_sibling_room_post_is_accepted_after_policy_installation`: holds real sibling startup across policy
  installation and the room-startup boundary. A post made during the policy hold is kept (neither
  refused nor shown) and is accepted and shown after the release; a sibling room operation is
  accepted after policy installation, and the pending native Session opens after release without
  another hook. Its verdict uses the product's response, not a count of status polls.
- `a_linked_worktree_gets_its_repository_offer_and_names_map_authority`: checks both hook riders.
- `a_native_omp_decided_turn_does_not_retry_a_permanently_refused_identity`: a decided turn's
  late exit meets the node rebuilt under a new identity; the refusal is said once, never promises
  reacquiring registration, and no later hook runs against the rebuilt identity.

`key_package_proof` also includes `a_governance_refresh_is_a_retryable_read_refusal` and
`an_abandoned_key_request_is_selected_again`, run with `test-knobs`. The latter abandons one
real selected log package before Open; the returning offline member must still read the
sender's post while direct key sends remain held. No in-process node or live model is used.

The same file's `keys_reach_an_offline_member_through_an_always_on_member` and
`a_key_through_the_log_releases_what_a_direct_one_does` require the offline reader to read
six posts across a sender-key rotation through a room member it has not trusted. Current,
authenticated room membership permits carrying the opaque sealed package; only trust in
the package's author permits installing its key. Restoring the carrier-trust gate in
`actor/key_body_scan.rs` makes the offline-member assertion red. The existing "Nor by the
log" arm of `no_consent_without_a_ring_entry_proof` covers an untrusted author, with its
M5 mutant removing the author-trust filter.
The direct-versus-log act also requires the log path to retain its exact offline delivery
while the consent's own governance fold refreshes. Measured from that refresh to B reading
all six, this took 3.426 seconds with the continuation and 33.729 seconds after dropping it:
ordinary maintenance eventually recovered the durable debt. The act prints elapsed time
without a PRODUCT bound. It requires A to finish B's log delivery without another failed
reach after D reads all six; dropping the continuation makes that structural assertion red
without weakening the six-post equality.
The offline-member act waits for the author's renewed consent after rotation and for
the carrier's role-complete receipt before the author stops. It reads current consent
from one idempotently repeated addressed post's reach report and the feed positions
from `vox status --json`; it does not mistake a second failed dial for that receipt.

## Busy-room newcomer and paging (ADR-052 RG-1, #1315)

`a_newcomer_reads_the_whole_history_proof` includes two variants of the same busy-room
journey. They are optional while RG-2 through RG-4 remove the reproduced admission, trust
and key-delivery failures; an optional red is not a release waiver. They use four scratch
computer daemons (X hosts six earlier joiners and its personal sibling; Y hosts slow
author `y1`; Z hosts fast author `z1`; W hosts a personal sibling and later `n-new`),
one anchor process, and three OMP Session stand-ins, all on `y1` (no model). The paused
variant checks the serving daemon's PID against its held daemon lock, observes its stopped process state,
and pauses it for 1.5 seconds in every 3 seconds. The delayed variant isolates the slow
member on IPv6 loopback, with its IPv4 anchor reached through the existing userspace
forward; its only outgoing path delays each datagram 350 ms. It requires both the
forward's probe and a product-reported RTT of at least 300 ms before the newcomer joins.

The 3,000-row seed is split concurrently between `y1` and `z1`. X's personal node pairs
its computer with Y, Z and W before the room is created on Y; no explicit all-pair trust
is added. Each pairing waits for both partners to report confirmed; their policy revisions
are local counters and are not compared across computers. Only the exact
`computer peer refused the request: node: this computer's policy changed while pairing; review again`
refusal starts a fresh invitation and review, with three attempts total (the initial review
plus two fresh reviews). Every refusal is printed with its attempt number; exhausting all
three is APPARATUS staging and quotes all refusals. Any other pairing failure remains
PRODUCT immediately. Both busy-room variants share this staging.
The three authors are `y1`, `z1`, and `n-old1` (the latter starts after its
join). Three OMP Sessions on `y1` alternate 400-character user/reply steps at one per second.
Every post is a separately started process, offered on a one-second schedule without
waiting for the previous answer. Several posts can therefore be in flight against the slow
member at once: this is a heavier load than the old rig, which waited for each answer,
not merely a cadence difference. Offered times and acknowledged times are recorded
separately; offered gaps must stay within 750–1250 ms. The slow author's acknowledgement
lag is measured, not bounded. The slow condition is active before six earlier joins
through fast `z1`, with ten seconds between the first five and thirty seconds after the sixth.
W creates `n-new` only then; computer revisions and trust are sampled after two seconds,
and it joins after eight seconds through a fresh fast-`z1` link. A refused join of any
joiner is immediately recorded as RED PRODUCT, never a staging failure, and is not retried.
The proof attempts every remaining joiner once where staging allows, including the newcomer,
and records `refused k of 7 joins` with every refusal's words.
After admission every admitted earlier member and the newcomer offers one post per second.
Only acknowledged posts count toward the 100-post red in either direction and convergence.
The shared room apparatus strips inherited `PI_` and `OMP` session variables as well as
the other harness markers; each stand-in supplies only its own Session environment.

A recorded through-slow-member run refused `n-old2` after 44.5 seconds: the member paused
1.5 seconds in every 3 seconds did not complete its exchange (`peer sent no complete frame
in time`). Receipt: `/opt/vox-evidence/v0431/rg-1/review-r1/faithful-paused.log:13101-13108`.
That observation is not the five-second seat-question veto RG-2 changes. The journey
routes all earlier joiners and the newcomer through fast `z1` to exercise that distinct rule.
On today's product the journey has also shown posts refused with `computer trust changed
while this command was being applied` after the newcomer's node is created on a paired
computer: these are the words ADR-052 records for C-3, but which rule refused them here has
not been traced (this journey removes nobody).

Run one named variant, in release, without `test-knobs`:

```sh
cargo test --release -p vox-tui --features optional-proofs \
  --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact \
  a_busy_room_newcomer_reads_every_member_with_a_paused_member --nocapture

cargo test --release -p vox-tui --features optional-proofs \
  --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact \
  a_busy_room_newcomer_reads_every_member_with_a_delayed_path --nocapture
```

Set `VOX_PROOF_SHIPPED_BINARY` to the absolute path of an untouched release helper to
drive that asset instead of Cargo's helper. Every process still gets scratch
`VOX_DATA_DIR` and `VOX_CONFIG_DIR`. `VOX_PROOF_RG1_EVIDENCE` selects the existing
directory under which scratch profiles are created; `VOX_PROOF_KEEP_DIRS=1` retains them.
Capture stdout and stderr: receipts include every command, status and doctor snapshot,
first-event marks counted in acknowledged posts, and every paging cursor. These marks are
independent observations, not an assumed sequence of prerequisites:

- `contiguous_verified`: status reports the author's verified contiguous position past
  the marker's acknowledged feed fence. It can be false while a sparse copy is retained,
  and says nothing about decryption or showability.
- `mutual_room_trust`: the author's doctor reports mutual room trust. This is sufficient
  evidence of the room grant being applied, but is not a prerequisite for a shown post.
- `no_key_owed`: the author's status reports no sender-key delivery owed. This can mean
  the room is unsettled or a package was committed but not fetched. It does **not**
  establish that the recipient holds the key.
- `shown`: the exact post is present in the recipient's real paged read. Only this mark
  establishes that the person can read it.

The red prints all observed and unobserved marks rather than choosing a “first missing”
step from an assumed order. Both-ways completion depends on `shown` only; a lagging doctor
or delivery report cannot keep an otherwise complete room from finishing.

The reader follows the **stderr** `older messages not shown` footer until it finds the
requested row or reaches the room's start. Its own real-binary self-check plants the
first row in a 5,000-row room:

```sh
cargo test --release -p vox-tui --features optional-proofs \
  --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact \
  the_busy_room_reader_finds_the_first_of_five_thousand_rows --nocapture
```

The named reader mutant is the same command with `VOX_PROOF_RG1_NO_PAGING=1`: it removes
older-page reads in the proof, not the product, and must turn the first-row assertion red.
The busy-room journey's apparatus failures say APPARATUS. A refused join quotes the
product as RED PRODUCT and names the joining member; the final verdict counts refused joins.
After admission, 100 acknowledged post-join posts with none displayed is RED PRODUCT in
either direction, with all marks reported. If a member has no acknowledged post, 100 answered
offers (acknowledged plus refused since join) produce a red saying how many were refused
and that none was acknowledged. The acknowledged post set is fixed by each offer's join phase, not a sliding
newest-post window. GREEN additionally requires every member's post shown both ways and
every acknowledged post on every member after the authors stop; errors from the final
in-flight commands are checked after those commands finish. Pause-thread and serving-daemon
liveness are checked before join verdicts, during the timeline and during convergence.
After authors stop, ten answered `--history older` demands without a smaller missing-post
set produce RED PRODUCT naming the member and a missing post. Sampler pages record even
refused reads without deciding the verdict or stopping the sampler.
No elapsed watchdog decides a product verdict.

After all admission attempts, a refused newcomer ends the run with every recorded failure;
an admitted newcomer continues into the timeline and convergence with only admitted members,
while refused posts remain recorded and their authors keep offering posts.
The final verdict is RED PRODUCT for any refused join, post or command, or failing tail observation,
and GREEN only when none occurred and every acknowledged post is shown on every admitted member.
If refreshing the fast member's link is refused, retain that refusal and use its already-successful
link for the newcomer; do not retry the refused command or change the admitting member.

For an **apparatus smoke only**, add `VOX_PROOF_RG1_NO_PAUSE=1` to the paused-variant
command. It disables the serving-process pause so the
post-admission code can run on the shipped helper. Its product red or green is never a
verdict on an ADR requirement; record which post-admission branches it actually reaches.

Coverage remains limited: no direction has ever become shown, so the `shown`/`shown_post`
success paths, the all-directions-shown loop end, the stopped-authors loop (including its
demand-count and refusal branches), and GREEN have never run. Neither have the
refused-newcomer branch under this code, the refused-link fallback, the tail's error
branches, a tail with a member refused at admission, or the all-posts-refused bound.
The first candidate that gets past the 100-post red is these shown-dependent branches'
first run; an APPARATUS fault or a hang there is a defect of this proof to fix, not the
candidate's failure.

## Readers on slow or interrupted paths (ADR-052 RG-6; needs `test-knobs`)

`a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back` has its own mutant:
`VOX_MUTANT_NO_PROMOTION=1` (ADR-054 M3, given to the returned reader's daemon only) promotes no
head a peer committed, so the reader stays on the author's head from before it left and shows
none of the posts it missed; that act must then fail PRODUCT on its no-progress rule ("the
returning reader's shown count stopped at …") with the reader daemon's engagement line printed
as `[RG-6 mutant]`.

The relay act: an author posts twice a second, 300
times, to a reader whose only path is a relay circuit with 75 ms each way on every member's hop
(a userspace forwarder); green when the reader shows every acknowledged post. A red names how many
the reader shows and holds. Its `two` arm,
`a_delayed_relay_keeps_up_with_two_authors_each_posting_twice_a_second`, has two members post that
way at once over the same path (four posts a second for the reader); it is green when the reader
and each author show every post of each author, and a red names those counts per author. Run each
quiet.

```sh
cargo test --release -p vox-tui --features optional-proofs,test-knobs --test key_package_proof \
  delayed_relay::a_delayed_relay_keeps_up_with_a_two_per_second_author -- --ignored --exact \
  --nocapture
cargo test --release -p vox-tui --features optional-proofs,test-knobs --test key_package_proof \
  delayed_relay::a_delayed_relay_keeps_up_with_two_authors_each_posting_twice_a_second -- \
  --ignored --exact --nocapture
```

## The proofs

### Live model (needs `opencode` on PATH, logged in: `~/.local/share/opencode/auth.json`)

> **BANNED until fix-handoff-b's launcher move (`8f53fb2f`, #301) is accepted, and then run only when the decider asks, and only through its sandbox:**
> - **Four binaries, by name:** `agent_rehearsal_proof`, `drain_self_filter_proof`, `tracker_rehearsal_proof`, `opencode_plugin_proof`. Never run them, in any build or profile, with or without any feature, as a whole binary or one test of it.
> - **`an_agent_wake_is_safe_and_bounded_proof` built with `optional-proofs` or `live-model-sandbox`.** Without either feature it is an ordinary blocking proof and may run.
> - **No workspace-wide run of an optional-proofs build**, not even `--list`. Running any *other* single named test binary built with `optional-proofs` (the R41, R42 and anchor-restart rows below) is fine.
>
> On a tree without that move they start a live model with no sandbox whenever an opencode login exists. Their rows below say **DO NOT RUN** and carry no command.

**Ad hoc, on demand only** (decider, 2026-10-02): nobody runs one of these unless the decider asks, and none is ever part of CI or the release gate. When one is run:

- **Models:** only `claude -p`, `codex exec`, or OpenCode with `opencode/kimi-k3`. Never the free model. Every proof below defaults to `opencode/kimi-k3`; `VOX_PROOF_OPENCODE_MODEL` overrides it.
- **Only `--features live-model-sandbox` starts a model.** `optional-proofs` alone compiles these proofs and prints `OPTIONAL PROOF NOT RUN` for each.
- **Sandbox:** a live model gets a shell, and on 2026-10-02 an unsandboxed one read other agents' private files and sent them to the provider. Every OpenCode these proofs start runs through `tests/support/oc_sandbox.rs`:
  - macOS `sandbox-exec`, reading only the system, the OpenCode and `vox` binaries, the run's sandbox root and the run's own vox profiles, and writing only the root;
  - a throwaway `HOME`, and a fixed environment: the system's `PATH` (plus a proof's own recording shim), no `USER`;
  - a canary in the real `HOME`: every profile is probed against it before any turn, and every turn's output is checked for it;
  - a copy of OpenCode's own provider credential alone;
  - the canary and the copy removed on every exit.

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `agent_rehearsal_proof::two_agent_sessions_and_an_operator_share_one_room` | Two AI sessions and a person in one room don't see each other's messages, or a session sees its own posts echoed. | **DO NOT RUN** (banned, see the block above). No command until the ban is lifted. | opencode + login (`opencode/kimi-k3`) | not timed; minutes of model turns |
| `opencode_plugin_proof::a_real_model_reads_the_room_through_the_opencode_plugin` | An OpenCode agent never sees what was posted to its room. | **DO NOT RUN** (banned, see the block above). No command until the ban is lifted. | opencode + login | not timed; one or two model turns |
| `tracker_rehearsal_proof::workers_do_work_and_the_tracker_never_mistakes_an_observation_for_a_verdict` | Agents working an item through a room confuse the tracker: a claim, `blocked`, `failed` or `result` row is lost, or an observation is taken for a verdict (ADR-021, M21.8). | **DO NOT RUN** (banned, see the block above). No command until the ban is lifted. | opencode + login; live model turns | not timed |
| `agent_hook_proof` (whole binary; a blocking proof, not an optional one) | An agent's harness is not fed its room by `vox agent hook`, is fed the same messages twice, or one author's lines pass for another's. Listed here because it is often taken for a live-model proof: it starts only `vox`, never a model. | `cargo test --release -p vox-tui --test agent_hook_proof -- --ignored` | nothing beyond `vox` | not timed here |
| `an_agent_wake_is_safe_and_bounded_proof::a_live_model_is_shown_the_framed_attributed_wake` | An urgent message reaches the agent's model unattributed, or looks as if it came from the operator. | **DO NOT RUN** (banned, see the block above). No command until the ban is lifted. | opencode + login | not timed; two model turns, each up to 180 s |
| `drain_self_filter_proof::a_live_models_post_is_dropped_only_from_its_own_sessions_drain` | An OpenCode agent is fed its own posts back, or loses another session's posts. | **DO NOT RUN** (banned, see the block above). No command until the ban is lifted. | opencode + login; the model must run one shell command it is asked to (a model that won't is reported `CANNOT MEASURE`, not a product red) | not timed; two model turns |
| `codex_live_proof::a_live_codex_turn_reads_the_room_only_through_a_trusted_hook` | A Codex agent never sees its room although `vox agent trust codex` succeeded, or sees it without the trust grant (ADR-020 M19.11-live, #169). Uses `codex exec` and the operator's Codex sign-in: a copy of `~/.codex/auth.json` alone (nothing else from `~/.codex`), 0600, in an isolated `CODEX_HOME` under `sandbox-exec`, removed on exit; it refuses to start within an hour of Codex's eight-day token refresh. The agent's own node `codex-proof` is made with `vox node create` and its hook is `vox agent hook --node codex-proof`. `VOX_PROOF_STOP_BEFORE_CODEX=1` runs every step before Codex (node, daemon, room, codeword, both homes, the sandbox probe, the printed hook drained under the sandbox) and starts no Codex. | `cargo test --release -p vox-tui --features live-model-sandbox --test codex_live_proof -- --ignored --exact a_live_codex_turn_reads_the_room_only_through_a_trusted_hook --nocapture` | `codex` on PATH, signed in with ChatGPT | not timed; two model turns |
| `claude_live_proof::a_live_claude_turn_reads_the_room_only_through_what_its_node_trusts` | A Claude Code agent never sees its room through its node's hook, or sees a person its node does not trust (ADR-020, D10 #408). Uses `claude -p` and the operator's Claude Code sign-in: the proof reads the login keychain's `Claude Code-credentials` item itself and hands the sandbox the access token alone (`CLAUDE_CODE_OAUTH_TOKEN`); the refresh token never enters, nothing of `~/.claude` is copied, and the sandbox is shown unable to read the keychain. Refuses with under 15 min of token left (run `claude` once). Three nodes in one daemon (`person`, `claude-t` trusting them, `claude-u` not), each agent wired by `vox agent plugin claude --node` into its own `CLAUDE_CONFIG_DIR`. `VOX_PROOF_STOP_BEFORE_CLAUDE=1` runs every step before the sign-in is read (nodes, daemon, room, trust, codeword, both config dirs, the sandbox and keychain probes, each printed hook drained under the sandbox) and starts no Claude Code. | `cargo test --release -p vox-tui --features live-model-sandbox --test claude_live_proof -- --ignored --exact a_live_claude_turn_reads_the_room_only_through_what_its_node_trusts --nocapture` | `claude` on PATH, signed in (keychain) | not timed; two model turns |
| `claude_live_proof::a_live_claude_session_is_followed_answered_and_interrupted_from_vox` | A live, interactive Claude Code session is followed, answered and interrupted from Vox (ADR-029 SC-1, DR-1, DR-3, DR-4; #540, #545, #544): Claude Code runs in a pane of a scratch tmux server (socket under the run's root, never the operator's), the server and the pane both confined by the live-proof sandbox with tmux's install read-only; its node (`claude-a`, wired by `vox agent plugin claude`) trusts `person` with drive, and the room map maps the work directory to the room. The person's `vox room session` shows the prompt and the approval Claude Code asks for, `--approve <ref>` makes Claude Code run the call (the file exists) and the Session read "approved here", and `--interrupt` interrupts a long reply as Esc does. Same sign-in route as above (the access token alone). Stops as APPARATUS, typing nothing, at any sign-in or trust screen. `VOX_PROOF_STOP_BEFORE_CLAUDE=1` stops before the sign-in is read. | `cargo test --release -p vox-tui --features live-model-sandbox --test claude_live_proof -- --ignored --exact a_live_claude_session_is_followed_answered_and_interrupted_from_vox --nocapture` | `claude` on PATH, signed in (keychain); `tmux` | not timed; two short model turns (Haiku) |
| `codex_live_proof::a_live_codex_session_is_mirrored_and_driven` | A live, interactive Codex session does not reach its Session, or cannot be answered or interrupted from Vox (ADR-029 SC-1, DR-1, DR-3; #541, #544). A sandboxed `codex app-server` and a plain `codex` TUI in a pty (`tests/pty/live_tui.py`), which joins it; the operator's prompt needs an approval, which `person` gives with `vox room session --approve`; then `--say` types a `sleep 120` turn and `--interrupt` stops it. The sandbox writes only the run's root and the run's own app-server socket and lock under `/private/tmp/codex-daemon-$UID`. Uses a copy of `~/.codex/auth.json` alone, as the row above. Never types into a sign-in or trust screen: APPARATUS. | `cargo test --release -p vox-tui --features live-model-sandbox,test-knobs --test codex_live_proof -- --ignored --exact a_live_codex_session_is_mirrored_and_driven --nocapture` | `codex` on PATH, signed in with ChatGPT | about 75 s; two model turns |
| `opencode_live_session_proof::a_live_opencode_session_is_mirrored_and_driven` | A live, interactive OpenCode session does not reach its Session through Vox's plugin, or cannot be answered or interrupted from Vox (ADR-029 SC-1, DR-1; #542, #544). A plain `opencode` TUI in a pty, confined by `support/oc_sandbox.rs`, its project carrying what `vox agent plugin opencode --node oc-proof` prints and `bash` set to ask; `person` approves the operator's command with `vox room session --approve`, then `--say` and `--interrupt` as above. Waits for the plugin to load before typing (APPARATUS if it never does). Not `opencode_plugin_proof`, which is banned. | `cargo test --release -p vox-tui --features live-model-sandbox,test-knobs --test opencode_live_session_proof -- --ignored --exact a_live_opencode_session_is_mirrored_and_driven --nocapture` | `opencode` on PATH, logged in (`~/.local/share/opencode/auth.json`); model `opencode/kimi-k3` | about 45 s; two model turns |

### Real harnesses on a stand-in model (macOS; no model, no network beyond loopback)

These start the real harness programs, but no model: each turn goes to a stand-in server on `127.0.0.1` (`crates/vox-tui/tests/support/model_standin.py`) that records what the harness sent and answers "ok". Each harness runs under `sandbox-exec` with the live-model sandbox's file rules (`oc_sandbox::offline_profile`), a canary in the real `HOME` probed first, and no network but the stand-in's port and the run's own Unix sockets. It runs in a scratch `HOME` holding only what `vox agent skill --install` and `vox agent plugin <harness>` put there. The only key is a made-up one for the stand-in, and nothing drives a login or setup screen. They are not live-model proofs, so they need only `optional-proofs`.

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `skill_cli_proof::each_harness_loads_the_pack_and_is_asked_for_the_repos_room` | An agent never sees the Vox skill (`vox-agent-comms`) although `vox agent skill --install` ran: the harness does not find the pack where it was put, or refuses its front matter. Or a session started in a repo the room map does not name is never asked for the repo's room (ADR-029 RB-5), or is asked without the `vox room join <link> --node <node> --bind <dir>` command filled in. Or a harness with no node never says so: its first session, from the skill alone (there is no hook yet), does not run `vox agent status` and say the harness has no node with the `vox agent setup` command; and once `vox agent setup` has run, the next session's status does not say the node is attached and give the room ask. Two turns each of `claude -p`, `codex exec` and `opencode run`, against a stand-in model that does what the skill's description says. OpenCode runs without its Claude Code compatibility, so Claude Code's copy of the pack cannot stand in for OpenCode's own. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test skill_cli_proof -- --ignored --exact each_harness_loads_the_pack_and_is_asked_for_the_repos_room` | macOS; `claude`, `codex` and `opencode` on `PATH`; `/usr/bin/python3` | about 150 s on a Mac (OpenCode's second turn waits about 130 s on its own npm install of the plugin folder's dependencies, which the offline sandbox refuses); not timed in CI |
| `fresh_user_journey_proof::a_fresh_user_gets_from_install_to_an_agent_working_in_a_room` | Anything between "I installed Vox" and "my agent works in my room and I can steer it": the skill missing after install or update, setup's names or passphrase, hooks to merge by hand, nodes detached after a restart or an update, the room never asked of the person, a Session not found, a rename not shown, a flow that ends without naming the next step, a hook that is slow or says too much. Run before every tag (see above). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test fresh_user_journey_proof -- --ignored --exact a_fresh_user_gets_from_install_to_an_agent_working_in_a_room` | Apple silicon Mac; `claude`, `codex`, `opencode`, `tmux` on `PATH`; `/usr/bin/python3` | not timed |

### Vox.app, on macOS (ADR-014 M-30, M-32)

`scripts/app-proofs.sh` is an ad hoc QE and troubleshooting tool that takes the app through its pieces (the decider, 2026-10-06): run by hand when someone reaches for it, in no CI workflow, and it blocks nothing — not a merge, a story or a release. App stories land on review and by-hand use of the built app. It builds `Vox.app` with the release `vox` inside it and runs these against a scratch data root and config directory. Before anything runs it refuses (APPARATUS) while a Vox login item is loaded or another `Vox.app` is registered with LaunchServices, and it fails a run that changed the real data root; it unregisters its own build at the end. The launch proof drives no UI. The XCUITest proofs need UI automation allowed on the Mac once (developer mode, then the approval macOS asks for), and without it they say so and run nothing. Every check on the window proves its own query first (Vox in front, its words readable), so each red names its side.

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `LaunchProof` (`scripts/app-launch-proof.py`) | With the login item declined, Vox.app starts no daemon, starts a second one, or lets the daemon it started stop while it is open; or, launched again, it does not use the daemon already running (ADR-014 M-9, #438). | `scripts/app-proofs.sh LaunchProof` | macOS, Xcode, `python3` | about 30 s after the build |
| `FirstRunProof` (`apps/macos/VoxAppProofs`, one journey) | Any step of the app's journey fails a person (ADR-014 M-30, M-31): first run and the login item question; attaching; the main window grouping rooms by need; read each way, `read by` shown, and nothing read while the app is hidden; the keyring view adding and removing with its effects said first; a file attached with To: and a note, pulled by the peer; ⌘J and ⌘⇧C, the copied address used by `vox forward`; a refused join at the top of the decision record; untrust cutting a live forward; quit detaching the node; the services view's copy box and one-step sharing (#444). The notification step is a case of its own, `testNotificationSaysWhoWroteNeverWhat`, the one part that needs a person at the Mac (Vox allowed to notify, no Focus on): a run that names nothing leaves it out and says so, and `scripts/app-proofs.sh FirstRunProof/testNotificationSaysWhoWroteNeverWhat` runs it alone in about a minute. `VOX_PROOF_SHA=<sha>` refuses a run whose tree is not that commit, before the build. `VOX_PROOF_FROM=6` starts the journey at step 6, what steps 1 to 5 leave staged by `vox` (and says steps 1–5 did not run), for troubleshooting a later step. A second case, `testALoginItemThatWillNotStartIsSaidWithAWayOut`, stages a login item that will not start and checks the app quotes its log line and offers Turn Keep Running Off. A third, `testKeepRunningCanBeTurnedOffAndOnWhileVoxRuns` (#571), starts at the first-run question: it must say what Keep Running does and where to turn it off, and Return must answer nothing (no default button). It then chooses Keep Running, turns it off and on again from the Vox menu, and checks the answer and the login item each time, and that Off also stops keeping the node, and that On with the node attached offers to keep it at once (declined in the proof: the Keychain is the person's). No login item is ever registered: app-proofs.sh builds the app under proof with a stand-in login item and LAN helper (`VOX_PROOF_STUB_SERVICES`) that register nothing, so no proof can register a login item or a root daemon; the case refuses an app without them, and `scripts/assemble-macos-app.sh` refuses a release that carries them. app-proofs.sh also refuses to start while a Vox login item is loaded, or registered and allowed. Approving a real login item stays `manual.login_item`. Not yet in it: `pulled by` (#498). | `scripts/app-proofs.sh FirstRunProof` | macOS, Xcode, UI automation allowed; Vox allowed to notify and no Focus on | not timed here |

The app runner defaults to a headless macOS guest on this Mac. See [guest setup and results](app-proof-vm.md). Use `--host` only for an explicit physical-desktop run; its notice precedes clipboard access. `VOX_PROOF_APP` naming an installed app is refused; prove the isolated app it builds instead.

### A move to another network, on macOS (needs the operator's `sudo`)

The Linux form runs unprivileged in a network namespace and is an ordinary proof. The macOS form changes the machine's `lo0` aliases and a host route to TEST-NET-1 (`192.0.2.1`) with `sudo`, and undoes them at the end; it never touches the default route or a real interface. Only the decider runs it.

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `a_network_change_is_noticed_and_acted_on_proof::a_move_to_another_network_is_noticed_and_acted_on` | A daemon that does not notice its machine moved to another network: peers wait out `SILENCE_IS_DEATH` (30 s) for a connection it accepted, and its advertised addresses stay stale (ADR-012 N-49–N-52, #413, #414). Four claims: `redial` (a new connection to the peer within 3 s, nothing sent), `said` (one change in the log within 1 s), `status` (the change and the new address in `vox status --json` within 2 s), `reads` (the peer reads a post within 5 s). | `sudo -v && VOX_PROOF_NETCHANGE_MACOS=1 cargo test --release -p vox-tui --test a_network_change_is_noticed_and_acted_on_proof -- --ignored --exact a_move_to_another_network_is_noticed_and_acted_on --nocapture` | macOS, `sudo`, `python3` | about 1 min |

### A published release (needs the network and `gh`)

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `update_proof::an_older_release_updates_itself_and_refuses_a_bad_download` | A person on the previous release runs `vox update` and is not moved to the newest, or a download whose digest does not match its record is installed anyway (claims `journey.update_replaces_an_older_install` and `verify.digest_mismatch_is_refused`). It runs a binary GitHub already serves, so it measures that artifact as much as this tree. | `cargo test --release -p vox-tui --features optional-proofs --test update_proof -- --ignored --exact an_older_release_updates_itself_and_refuses_a_bad_download` | the network, `curl` and `gh` (it lists the releases); it accepts no gap, so an unreachable GitHub or no earlier release reads `CANNOT MEASURE` | not timed here |

`update_proof`'s blocking test, `vox_update_replaces_an_install_it_owns_and_refuses_the_rest`, measures this build's refusals, record lookup, `--check` and `--rollback` with nothing to roll back to, and is not optional. Its half that needs another compiled version is optional; see the next section but one.

### Rollback to a published older CLI (macOS, RG-9)

`a_rollback_survives_a_power_loss_proof::a_rollback_to_an_older_release_restarts_its_running_daemon`
proves that a scratch standalone `vox update --rollback` replaces both hand-started and
client-started daemons when the older release lacks `--replace-pid`. It needs a genuine
published binary older than this build, so it is optional and blocks neither CI nor release.
`VOX_PROOF_OLDER_BINARY` is separate from the newer `VOX_PROOF_NEXT_BINARY` fixture.
Without `optional-proofs`, its stand-in prints `OPTIONAL PROOF NOT RUN`.

For example, download and check the published Apple Silicon v0.4.29 CLI, then run only this act:

```sh
set -e
older=$(mktemp -d)
curl --fail --location --max-time 120 \
  -o "$older/vox-aarch64-apple-darwin" \
  https://github.com/robertelee78/vox/releases/download/v0.4.29/vox-aarch64-apple-darwin
curl --fail --location --max-time 120 \
  -o "$older/vox-aarch64-apple-darwin.sha256" \
  https://github.com/robertelee78/vox/releases/download/v0.4.29/vox-aarch64-apple-darwin.sha256
(cd "$older" && shasum -a 256 -c vox-aarch64-apple-darwin.sha256)
chmod +x "$older/vox-aarch64-apple-darwin"
VOX_PROOF_OLDER_BINARY="$older/vox-aarch64-apple-darwin" \
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test a_rollback_survives_a_power_loss_proof \
  a_rollback_to_an_older_release_restarts_its_running_daemon \
  -- --ignored --exact --nocapture
```

Every product process uses the proof's scratch HOME and data/config roots; no installed app
or login item is involved. A fixture that is not older is an `APPARATUS` refusal.

### Two genuinely compiled versions (`VOX_PROOF_NEXT_BINARY`)

These journeys move an install, a daemon or a claim between this build and another genuinely
compiled `vox`. The release gate supplies no second version, so they are optional and block
neither CI nor release. Each needs `VOX_PROOF_NEXT_BINARY` naming a `vox` built from a copy of
the same tree with the workspace version's first character changed to `9` (0.4.31 becomes
9.4.31), with `cargo build --release --bin vox --features vox-tui/test-knobs`; a fixture saying
any other version is an `APPARATUS` refusal. A patched version string is not a fixture. Every
product process uses the proof's scratch HOME and data/config roots. None reads
`VOX_PROOF_ALLOW_UNPROVEN`.

| Proof | Helps troubleshoot |
|---|---|
| `a_rollback_survives_a_power_loss_proof::an_interrupted_rollback_is_finished_by_the_next_one` | A rollback cut short between its renames is refused afterwards ("no previous vox was retained") instead of finished, or a leftover copy is installed (#242). |
| `update_proof::vox_update_moves_an_install_it_owns_to_another_compiled_version_and_back` | `vox update --rollback` to another version ignores `VOX_NO_SHELL_SETUP`; on macOS, a controlled Vox.app bundle is not updated, rolled back and rolled back again as a whole, or a forged record changes it (ADR-014 M-29). macOS also needs `codesign`, `ditto` and `PlistBuddy`. |
| `update_proof::an_update_restarts_its_daemon_and_uses_a_different_local_version` | After `vox update` the daemon is not restarted onto the new version, or a node is left detached without being named (ADR-034 UP-1, UP-2). |
| `update_proof::a_client_uses_another_package_version_with_the_same_control_protocol` | A client of another package version with the same control protocol is refused by the daemon (ADR-041 RS-12). |
| `update_proof::a_claim_is_still_held_after_the_package_version_changes` | A claim made before an update is no longer held by its session afterwards (ADR-041 RS-10). |

Run each separately, in release, for example:

```sh
VOX_PROOF_NEXT_BINARY=/absolute/path/to/9.x/vox \
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test update_proof a_claim_is_still_held_after_the_package_version_changes \
  -- --ignored --exact --nocapture
```

On macOS, `a_client_uses_another_package_version_with_the_same_control_protocol` and
`a_claim_is_still_held_after_the_package_version_changes` also need the `test-knobs` scratch
keychain the build provides (`VOX_TEST_KEYCHAIN`).

### Root is told at once (Linux, ADR-026 C-1)

`the_daemon_and_its_nodes_proof::root_is_told_at_once_that_it_cannot_use_the_daemon` runs
`vox serve` and `vox daemon` as uid 0 in an unprivileged Linux user namespace
(`unshare --user --map-root-user`, no sudo) and requires each to end within 10 s saying it runs
as root and to run it as an ordinary user. macOS, where the release gate runs, cannot make root
without sudo, so it is optional. It needs Linux with unprivileged user namespaces and
`unshare` (util-linux) on `PATH`; a machine that refuses them reads `CANNOT MEASURE`.

```sh
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test the_daemon_and_its_nodes_proof root_is_told_at_once_that_it_cannot_use_the_daemon \
  -- --ignored --exact --nocapture
```

### A v0.4.30 store opened by this build (the update from v0.4.30)

These proofs open a store a v0.4.30 `vox` left behind: store schema 1, with no MP-6 or MP-11. They
check that nothing is lost or misread, and that a removed member's later posts leave. Updating from
v0.4.30 is in scope for this release. The release gate keeps no such store and no such binary, so
the proofs are optional. Each one names its fixture and refuses with `APPARATUS` when the fixture
is missing or the wrong shape. None reads `VOX_PROOF_ALLOW_UNPROVEN`.

| Proof | Helps troubleshoot | Needs |
|---|---|---|
| `retention_proof::old_small_rows_move_atomically_when_their_room_opens` | A v0.4.30 room's small rows are lost, duplicated or changed by the move into the shared table (store schema 2) when a SIGKILL interrupts it, or Sessions, roster or admins differ after two restarts. | `VOX_PROOF_OLD_STORE`, `test-knobs` |
| `retention_proof::a_failed_small_row_move_keeps_the_room_readable_and_retries` | A move that fails on a full disk keeps the room closed or hides a post, or the move is not resumed at the next open. | `VOX_PROOF_OLD_STORE`, `test-knobs` |
| `retention_proof::old_128_item_locator_pages_read_and_split_when_rewritten` | v0.4.30's 128-item locator pages are not read, or a rewritten page still needs an oversized allocation. | `VOX_PROOF_OLD_LOCATORS` |
| `a_room_can_be_left_and_ended_proof::a_store_an_older_vox_left_showing_refused_posts_loses_them_at_the_first_open` | A post that the member's own completed removal decision refuses is still shown after the update, or the posts the remover had read disappear (ADR-053 MP-6, MP-11). | `VOX_PROOF_BASE_BINARY`, `test-knobs` |

Fixtures:

- `VOX_PROOF_OLD_STORE` is a directory holding a stopped profile written by a store-schema-1 `vox`.
  - It contains the data root itself, with `cfg/` inside it; `.daemon/` and `proof.keychain-db` are not copied.
  - The identity passphrase is the proof's `IDENTITY`.
  - It holds one room with the 160 `PACKED-ROW-nnnn-` posts and their `Packed nnnn` Sessions, and at least 80 B-tree leaves that each hold a single small row.
  - A file `proof-room` names the room.
  - `tiny_rows_share_leaves_beside_large_values` writes exactly this when `VOX_PROOF_OLD_STORE` names a directory. It writes it after its staging and before its own schema-2 assertion. So the fixture comes from running that test with a harness whose `vox` writes schema 1, for example this proof file built at `afa78a1ae^` with `test-knobs`. Where the schema-2 assertion then fails, that is expected. This was not tried for v0.4.31.
- `VOX_PROOF_OLD_LOCATORS` is the same kind of directory. It is written by `locator_pages_fit_one_physical_page` (128 `LEGACY-LOCATOR-nnnn` rows, `proof-room`) under a schema-1 `vox` whose locator pages hold 128 items.
- `VOX_PROOF_BASE_BINARY` is a `vox` built before MP-6 and MP-11, for example tag `v0.4.30` (`8d71ab337`) built with `cargo build --release --bin vox --features vox-tui/test-knobs`. Every process the act starts uses its scratch roots.

What this machine already has does not fit as it stands (checked by reading, not run):

- `/opt/vox-evidence/v0431/simple-sync/upgrade/v0430/vox-aarch64-apple-darwin` is the published v0.4.30 asset. It is genuinely schema 1 and genuinely before MP-6 and MP-11. It is built without `test-knobs`: it contains no `VOX_TEST_KEYCHAIN`, so the proofs' scratch-keychain knob does not reach it on macOS. It is the right version for `VOX_PROOF_BASE_BINARY`, but use a `test-knobs` build of `v0.4.30` instead. It cannot write either store fixture by itself, because those come from this proof's own staging.
- `/opt/vox-evidence/v0431/simple-sync/upgrade/run1-before/` is a pristine v0.4.30 data set of three nodes and an anchor (`a/`, `b/`, `c/`, `anchor/`, each with `data/` and `cfg/` side by side, its own `*.pass`, and `room.id`). It is real v0.4.30 data for the update journey. It is not the shape these acts read:
  - It has no `proof-room`.
  - `cfg/` is not inside the data root.
  - Its passphrases are not the proof's.
  - It has no `PACKED-ROW` or `LEGACY-LOCATOR` rows.
  - It does not promise the single-row leaves or a 128-item page.

Run each separately, in release, for example:

```sh
VOX_PROOF_OLD_STORE=/absolute/stopped-schema-1-profile \
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test retention_proof old_small_rows_move_atomically_when_their_room_opens \
  -- --ignored --exact --nocapture
VOX_PROOF_BASE_BINARY=/absolute/v0.4.30-test-knobs/vox \
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test a_room_can_be_left_and_ended_proof \
  a_store_an_older_vox_left_showing_refused_posts_loses_them_at_the_first_open \
  -- --ignored --exact --nocapture
```

### Computer convergence journeys

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `nodes_of_one_daemon_proof::computer_pairing_uses_an_anchor_without_room_membership_and_reconnects` | Paired computers do not converge after path loss, lose historical misses across restart, or fail to apply the current managed grants after a newer policy. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test nodes_of_one_daemon_proof -- --ignored --exact computer_pairing_uses_an_anchor_without_room_membership_and_reconnects --nocapture` | a real machine with IPv4 and IPv6 loopback; run alone | several minutes; not timed in CI |
| `nodes_of_one_daemon_proof::computer_preview_and_approval_survive_a_crash` | An authenticated Add Computer preview or the local operator's approval disappears when the daemon crashes before the other operator approves. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test nodes_of_one_daemon_proof -- --ignored --exact computer_preview_and_approval_survive_a_crash --nocapture` | a real machine; run alone | not timed in CI |
| `nodes_of_one_daemon_proof::two_paired_computers_that_are_idle_exchange_nothing` | Idle paired computers keep exchanging unchanged histories, re-derive bindings, fail to reconcile siblings while one actor is held, replace policy during a held admitted join, or leave a refused pre-lease join on a real board after restart. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test nodes_of_one_daemon_proof -- --ignored --exact two_paired_computers_that_are_idle_exchange_nothing --nocapture` | a real machine; run alone | several minutes; not timed in CI |
| `nodes_of_one_daemon_proof::enrolled_computers_follow_node_changes_and_retire_removed_authority` | Three paired computers do not follow a node's creation, rename, personal selection or binding transfer and recovery; a removed computer keeps its grants. The other computers keep trusting a node whose folder was deleted after it was locked, or a node deleted and made again under the same name while its computer was off. `VOX_MUTANT_FX28=deleted-node-folder-check` and `VOX_MUTANT_FX28=same-name-node-replacement` each make their own step red. It does not enrol a removed computer again: pairing refuses that on purpose (see "My computers" in `docs/manual/keyring.md`). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test nodes_of_one_daemon_proof -- --ignored --exact enrolled_computers_follow_node_changes_and_retire_removed_authority --nocapture` | a real machine; run quiet | a few minutes; not timed in CI |
| `a_post_answers_promptly_while_a_peer_posts_proof::status_and_posts_answer_while_ten_sessions_step` | Status or posts lag behind agent Session saves. Holds one exact Session's durable transaction while ten real hooks step; status must answer within 1 s and every post within 5 s. Also holds an attention commit while Session, admin and hook pause-status reads wait; status must still answer within 1 s before release. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_post_answers_promptly_while_a_peer_posts_proof -- --ignored --exact status_and_posts_answer_while_ten_sessions_step --nocapture` | a real machine; run alone | latency measured, not timed in CI |
| `a_daemon_reopens_its_rooms_proof::a_restarted_room_drives_its_session_refresh_to_ready` | A retained room reopens slowly while it replays its own and other authors' Session lifecycle records. Stages all 257 heads from each author, then requires automatic public room readiness within 5 s without polling to wake the replay. The test-only receipt counts opened records, not index-only visits; zero-open batches can still walk the index. Only an apparatus positive-share check reads the count; readiness is measured from the public room-open event. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_daemon_reopens_its_rooms_proof -- --ignored --exact a_restarted_room_drives_its_session_refresh_to_ready --nocapture` | two real daemons and a real wire client; run alone | restart within 5 s |
| `retention_proof::a_session_change_rewrites_only_that_session` | One Session's metadata change rewrites unrelated Sessions. Bounds complete-publication OS writes at 100 and 1,500 unrelated Sessions, encrypted index bytes per Session, and unchanged ordered listings/steps across restart. Allocator values are printed diagnostics only. | `RG13_SESSION_LOCAL_EVIDENCE=/absolute/scratch/receipts cargo test --release -p vox-tui --features optional-proofs,test-knobs --test retention_proof -- --ignored --exact a_session_change_rewrites_only_that_session --nocapture` | macOS daemon OS write counter; real scratch daemon and product store copies |
| `retention_proof::an_existing_session_index_keeps_its_listing_when_upgraded` | A base-written Session index preserves its exact oldest-first listing on the first fixed read and after lazy backfill; a later rename has bounded OS writes. | `RG13_SESSION_BASE_VOX=/absolute/path/to/c5b12cef4/vox RG13_SESSION_FRESH_RECEIPTS=/absolute/path/to/fresh/receipts RG13_SESSION_LOCAL_EVIDENCE=/absolute/scratch/upgrade cargo test --release -p vox-tui --features optional-proofs,test-knobs --test retention_proof -- --ignored --exact an_existing_session_index_keeps_its_listing_when_upgraded --nocapture` | macOS; pinned base binary; test-knobs backfill staging; run quiet |
| `retention_proof::a_partly_expired_room_counts_pages_and_threads_only_what_remains` | A room in which only its oldest rows are due (40 old rows, 145 newer, a thread on both sides) gives a wrong Count, `older`, page or thread summary while the native prune is held; or a node stopped before that removal, reopened keeping longer, shows the 40 again. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test retention_proof -- --ignored --exact a_partly_expired_room_counts_pages_and_threads_only_what_remains --nocapture`; `VOX_MUTANT_EXPIRY=summary` or `VOX_MUTANT_RETENTION_FLOOR=1` for its mutants | test-knobs native prune hold; the node's 90-second lifetime; run quiet |

The Session index takes about 0.9 KB more per Session; a Session change no longer rewrites
the index of every Session in the room. Opened rooms lazily backfill the version-2 derived
index while retaining their previous readable projection. After that header is written,
v0.4.30 refuses the room's Session index (`Session index header version`); downgrade is
not supported.

For the constructor boundary independently of the full journey, set
`VOX_PROOF_STEP=constructor-re-admission` on that command. This selector is not a substitute
for the complete FX-28 journey; it stages the paired Computers and exercises the original create,
room ID, join and bidirectional posts.

For FX-64's direct-publication boundary, set `VOX_PROOF_STEP=direct-publication` on the same
command. This focused step stages the paired Computers and asserts that the directly reached
member's board serves the joiner's member and bundle records; it does not replace the full FX-28
journey.

For the FX-61b governance handoff independently, set `VOX_PROOF_STEP=superseded-governance`
on the same command. It stages an expiring admin grant, holds the selected ordinary governance
turn across a real Computer policy change, and asks the member's `vox room admin list` after
policy acceptance. Test-only apparatus holds periodic settlement only for the selected room,
so an incidental tick cannot mask the lost governance-owner wake.

`VOX_PROOF_STEP=join-ordering` stages the paired Computers and exercises the held publication
and pre-lease join boundaries; it is not a substitute for the complete journey.

FX-28's executable mutants are run one at a time with
`scripts/run-fx28-mutant.sh <mode>`, where `<mode>` is
`preview-approval-not-durable`, `stopped-reader-fresh-write`, `lock-through-computer-write`,
`deadline-as-storage-failure`, `join-writer-fence`, `join-outcome-refusal`, `join-policy-not-applied`,
`stale-tick-authority`, `stale-join-authority`,
`fresh-preview-inherits-old-deadline`, `late-application-abandons-work`, `detach-keeps-reconciliation`,
`redeem-rejects-pending-registration`, `owner-refusal-decoded-as-payload`,
`due-backoff-drops-causal-cause`,
`stale-post-authority`, `constructor-terminal-refusal`, `constructor-stale-commit` or
`stale-trust-projection`. Each mode selects the journey which stages that fault and accepts
only its exact named `PRODUCT [FX28 ...]:` verdict; another product red is an apparatus failure,
not evidence for the mutant. `stopped-reader-fresh-write` uses one real shipped daemon as an
authenticated peer which fills the other daemon's bounded management slots and leaves every
response unread. `lock-through-computer-write` restores the former state lock across an exact held
durable Computer write; shipped status must still answer with the last committed revision inside
its existing actor-liveness contract. `deadline-as-storage-failure` turns an exact pre-rename
causal refusal into permanent storage quarantine again. `join-writer-fence` skips the policy
replacement's physical writer; `join-outcome-refusal` refuses the already-published held join;
`join-policy-not-applied` discards the policy replacement after the publication reader drains.
`stale-join-authority` admits a superseded join before its publication lease (a join the room
accepted before the policy moved is kept as pending, says so and names the retry, and the retry
completes under the current policy, ADR-049 N2).
`stale-post-authority` bypasses the durable-policy fence around an
ordinary text append (a post racing a trust revision is kept, not refused: the shipped journey
requires it not to publish while delta's moved policy is held, then to publish under that policy
once applied and read once on beta; the kept post is `PRODUCT [FX28 stale-post-re-admission]:`);
`stale-trust-projection` makes the shipped trust list copy unreconciled
trusted rows; `constructor-terminal-refusal` makes the pre-admission supersession terminal instead
of retaining the exact sealed Create: the shipped journey requires its original room ID to
complete under the accepted current policy and appear in the room list. Its intended verdict is
`PRODUCT [FX28 constructor-re-admission]:`; stale authority must never commit that room.
`constructor-stale-commit` bypasses the refused constructor lease and its lease-less continuation
checks: while delta's moved Computer policy remains held, the original create must not succeed or
appear in the room list. Its intended verdict is `PRODUCT [FX28 constructor-stale-publication]:`.
Full transcripts are written under `target/fx28-mutants/`. The old-peer modes
(`rekey-writer-fence`, `stale-rekey-authority`, `legacy-ended-unanswered-not-selected`) went with the
legacy long-lived session that design-4 R10 refuses; a computer on an older Vox is now
`nodes_of_one_daemon_proof::a_computer_on_an_older_vox_exchanges_nothing_until_it_updates`
(mutant `VOX_MUTANT_FWD=preamble-any`). These are
on-demand diagnostics, not CI or release gates, and are serialized like the journeys.

The former expiry-before-keyring-commit phase and the `expired-plan-drops-prepared` and
`keyring-commit-not-recoverable` mutants are removed. The node-store commit now serializes the
exact policy revision and expiry state across one atomic batch of keyring and dependent metadata;
a superseding plan commits nothing. A sender's missed exchange is historical timing evidence and
does not revoke an authenticated receiver policy. The dedicated pre-receipt crash phase and its
knobs are removed too: an actual later removal derives its denied peers from authenticated
binding history regardless of a prepared receipt, so the old omitted-preparation mutation no
longer affects it. The same journey retains unchanged restart and final Ready supersession;
the independent preview/approval crash journey retains the operator's durable intent claim.

`redeem-rejects-pending-registration` restores the immediate policy refusal when the exact
inviter registration is still being published. The anchor journey holds that real registration,
observes the matching redemption, then releases publication and requires the same shipped pairing
command to authenticate the valid code. Known refusal and direct reach remain independent.

`owner-refusal-decoded-as-payload` skips recognition of the existing tagged peer refusal.
The anchor journey retries a cancelled invitation over an established computer connection and
requires the shipped command to preserve the owner's cancellation reason rather than report
malformed response data. It does not accept a transport failure as evidence of cancellation.

`due-backoff-drops-causal-cause` restores the due-backoff selector's early return before causal
classification. After an early failed exchange and its retry are staged, the anchor journey
requires the same unfinished cause to become expired in shipped status. A pending-state read
started after the original conservative return boundary is a product failure. A positive expired
read proves the structural outcome without inferring the instant it was published.

`fresh-preview-inherits-old-deadline` makes a new pairing request inherit an older ordinary
exchange's clock. The existing anchor journey holds that fresh reservation while the ordinary
miss stays visible, then verifies the exact invitation after reachability returns. Preview does
not acknowledge ordinary delivery. `late-application-abandons-work` drops only the accepted actor
causally held past its observation boundary. The journey requires that same revision to become
current and usable after release without a role toggle, detach, unlock or restart, while its
historical miss remains visible. Its return boundary stays fixed throughout the observation.
`detach-keeps-reconciliation` retains the departing actor's owned flight and live pending row.
The existing replacement journey first observes that exact public pending result and miss, then
requires same-policy reattachment to clear live pending status and confirm its actual grant while
retaining history. Its existing delayed-reply interval stages the race; failure to stage it is
APPARATUS and cannot count as a product or mutant verdict.

Startup derives the actual current binding and settles its exact application before the
state-locked Ready publication. Genuine policy movement continues the same accepted operation;
observation lateness does not destroy it. Every authority-bearing use also checks current durable
policy. The pause mutant is judged by the saved state shown by shipped `vox room session`, with
a registered Session and known pause status, even when the original command reports delivery
unknown. Ordinary text append and sender-key admission have their own use-boundary mutants above.

### Timing a person feels (needs a real machine; a CI VM's stalls make these unreliable)

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `perf_r40_chat_latency_proof::r40_a_message_between_two_online_nodes_arrives_in_under_a_second_direct` | Chat messages are slow to arrive between two online people on a direct path (PRD-001 R40, under 1 s). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test perf_r40_chat_latency_proof -- --ignored --exact r40_a_message_between_two_online_nodes_arrives_in_under_a_second_direct` | a real machine | 8 s / 9 s |
| `perf_r40_relayed_chat_proof::r40_a_message_between_two_online_nodes_arrives_in_under_a_second_relayed` | The same, when the only path is a relay (R40, under 1 s). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test perf_r40_relayed_chat_proof -- --ignored --exact r40_a_message_between_two_online_nodes_arrives_in_under_a_second_relayed` | a real machine with IPv4 and IPv6 loopback (the split is checked first) | 22 s / 23 s, with the deleted control running alongside |
| `perf_r41_tunnel_throughput_proof::r41_a_tunnel_does_not_throttle_the_link_it_runs_over` | A tunnel (`vox forward`, SOCKS) is much slower than the link it runs over (R41). Or, under ADR-024's tapered congestion control: slow on a lossy link (under 2× a Cubic flow on the same loss), slower than a Cubic flow sharing a congested link (under 0.5×), stalled when the link turns lossy, under its lossy-link speed after a pause, or not back at full speed after the loss ends. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test perf_r41_tunnel_throughput_proof -- --ignored --exact r41_a_tunnel_does_not_throttle_the_link_it_runs_over` | a real machine; ~2 GB through a userspace link emulator. A link or arm whose emulator cannot hold its rate (a calibration window under 95%, or packets released late) is `CANNOT MEASURE` for that link or arm only, naming the window or the lateness, and the rest still measure; it is not a product verdict. `VOX_PERF_ONLY=<text>[|<text>…]` runs only the links and arms whose names contain one of them. It sets `VOX_TEST_ADVERTISE`, so it needs `test-knobs` too, as every command here has it. | 725 s (one run at load 35–44, M24.2 c3.1 `0b7d4d0d`) |
| `perf_r41_tunnel_throughput_proof::r41a_a_stalled_receiver_behind_a_short_buffer_keeps_its_speed` | A tunnel slows far below raw TCP when the receiving host has a short socket buffer and its daemon stalls (R41a): the receiver's overflow reports never reach the sender, or the sender keeps the cuts they cover. On R41's WAN link the host receives through a 416 KiB buffer and its daemon is stopped 20 ms in every 100 ms. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test perf_r41_tunnel_throughput_proof -- --ignored --exact r41a_a_stalled_receiver_behind_a_short_buffer_keeps_its_speed` | Linux (on macOS it is CANNOT MEASURE: the kernel counts no socket drops); ~800 MB through the userspace link emulator | not timed here |
| `a_newcomer_reads_the_whole_history_proof::a_daemon_answers_the_hook_while_syncing` | The agent hook says the daemon did not answer promptly while a newcomer fetches older history (ADR-038 FX-17), `vox status` counts a room's rows differently from what a paged read shows (FX-16), or the serving lane runs rounds `vox status` names no reason for (FX-15). Each of 200 hook runs must finish within 2 s. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_daemon_answers_the_hook_while_syncing` | two scratch daemons, a 257-post backlog | not timed here |
| `a_first_direct_connection_is_prompt_proof::a_first_direct_connection_completes_in_under_two_seconds` | The first connection to a host on the same network takes more than 2 s (R42). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_first_direct_connection_is_prompt_proof -- --ignored --exact a_first_direct_connection_completes_in_under_two_seconds` | a real machine | 22 s / 25 s |
| `a_first_punched_connection_is_prompt_proof::a_first_hole_punched_connection_completes_in_under_two_seconds` | The first connection through two NATs takes more than 2 s (R42). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_first_punched_connection_is_prompt_proof -- --ignored --exact a_first_hole_punched_connection_completes_in_under_two_seconds` | a real machine | 45 s / 52 s |
| `a_first_relayed_connection_is_under_two_seconds_proof::a_first_relayed_connection_completes_in_under_two_seconds` | The first relayed connection takes more than 2 s (R42). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_first_relayed_connection_is_under_two_seconds_proof -- --ignored --exact a_first_relayed_connection_completes_in_under_two_seconds` | a real machine | 21 s / 21 s |
| `an_ipv6_joiner_reaches_its_board_promptly_proof::an_ipv6_only_joiner_reaches_its_board_within_two_seconds` | On an IPv6-only network, reaching the anchor takes more than 2 s (R42). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test an_ipv6_joiner_reaches_its_board_promptly_proof -- --ignored --exact an_ipv6_only_joiner_reaches_its_board_within_two_seconds` | a real machine with IPv6 loopback | 16 s for both tests (ubuntu) |
| `an_ipv6_joiner_reaches_its_board_promptly_proof::a_joiner_whose_address_names_only_gone_boards_reaches_its_own_within_two_seconds` | Dead anchors in a room's address delay joining past 2 s (R42). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test an_ipv6_joiner_reaches_its_board_promptly_proof -- --ignored --exact a_joiner_whose_address_names_only_gone_boards_reaches_its_own_within_two_seconds` | a real machine | (in the 16 s above) |
| `a_spoofed_peer_cannot_hide_its_silence_proof::a_spoofed_peer_cannot_hide_a_dead_connection` | A direct path died but the node kept using it for a minute instead of moving to the anchor, while something on the path sent it garbage under the peer's connection ID (V210-140, 20 s bound). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_spoofed_peer_cannot_hide_its_silence_proof -- --ignored --exact a_spoofed_peer_cannot_hide_a_dead_connection` | a real machine with IPv4 and IPv6 loopback | not timed in CI |
| `a_reach_waits_for_the_anchor_being_dialled_proof::a_forward_whose_anchor_is_still_being_dialled_reaches_on_its_first_attempt` | A restarted `vox forward` whose anchor connection is still being made fails its first reach and pays the 500 ms retry (V210-132). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_reach_waits_for_the_anchor_being_dialled_proof -- --ignored --exact a_forward_whose_anchor_is_still_being_dialled_reaches_on_its_first_attempt` | a real machine with IPv4 and IPv6 loopback | not timed in CI |
| `a_post_answers_promptly_while_a_peer_posts_proof::a_post_answers_promptly_while_a_peer_posts` | `vox room post` is sluggish while someone else in the room is posting (100 ms). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_post_answers_promptly_while_a_peer_posts_proof -- --ignored --exact a_post_answers_promptly_while_a_peer_posts` | a real machine | 11 s / 12 s |
| `a_newcomer_reads_the_whole_history_proof::retained_rows_render_once_their_key_and_consent_arrive` | A held key bypasses consent, or exact retained rows fail to reproject for either row→key→consent or row→consent→key (ADR-038 FX-22; #1007). Marker holds stage each ordering; one author contributes more than a production projection page while a competing author contributes another row. Both exact authors' recipient package bodies must be committed in every local room before either source stops. After both sender keys are held, a causal marker parks the first bounded turn that commits the competing author's row; shipped `vox status` plus exact paged `vox room read --json` must show that row readable while the long author's backlog remains unfinished. The shipped room rows, `vox agent doctor`, `vox room admin list`, and exact rename hashes prove retained-object readability, continued completion, canonical reset/grant order, restart behavior and stale-consent invalidation; no particular network arrival order is claimed. An authenticated same-name rename must remain in room order without displaying another `vox.room.notice/1` in the settled `--notices` page; the preceding exact message anchors that page's coverage. Its distinct negative control treats an equal room name as a new effect and must fail on that extra user-visible notice, not revision arithmetic. When status says a continuation is exhausted, the proof re-reads exact rows before deciding whether content is missing. After removing a reader, the original accepted new-generation message must acquire a readable body at the remaining reader before the semantic checks start. Its first readable observation must contain exactly one matching hash, the correct body and `owed: false`; this canary stages receiver key arrival, rather than treating unrelated render completion as its verdict. A separate marker parks a bounded sweep past an effective administrator; a same-name row positions the sweep, and the quiet room's real authority deadline must remove that administrator without an unrelated wake. The continuation mutant clears the next sparse continuation after its first exact row: status says finished while exact hashes/bodies remain missing, producing a PRODUCT red. Elapsed time and CPU are not verdicts; an operator may stop a structurally stalled run as NO RESULT. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact retained_rows_render_once_their_key_and_consent_arrive` | a real machine; `test-knobs` | not timed in CI |
| `a_newcomer_reads_the_whole_history_proof::a_newcomer_talks_both_ways_at_one_wait_fresh_or_behind_a_backlog` | A member who joins a room that already has history waits longer than one who joins an empty room before the room is usable: its first post is refused or slow to be read, or it is slow to read the others (ADR-037 R1, #958). Two rooms in one run, an empty one and one of 160 posts (past the 128-row live window a sparse join holds); from each join's return, the creator reads the joiner's first post and the joiner reads the creator's within the same 10 s. A red names which room passed the bound and by how much. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_newcomer_talks_both_ways_at_one_wait_fresh_or_behind_a_backlog` | a real machine | not timed in CI (about 2 min on a Mac) |
| `a_newcomer_reads_the_whole_history_proof::hosted_nodes_read_each_other` | More than eight nodes hosted by one daemon cannot read one another's posts. Fifteen named nodes share one shipped `vox daemon --no-node` and a peer runs on another daemon; every hosted node must show every other member's post in both rooms. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact hosted_nodes_read_each_other --nocapture` | a real machine | not timed |

### The governance fold held by a knob (ADR-037 R3, #953; needs `test-knobs`)

`VOX_TEST_FOLD_HOLD_FILE=<path>`: while that file exists, no room's governance fold advances in that daemon. A proof stages "received but not folded" with it, drives an egress, and removes the file to see the recovery. Only a `vox` built with `test-knobs` reads it; without it the proof stops at `CANNOT MEASURE` naming the knob.

`VOX_TEST_HOLD_INCOMING_CONSENT_FILE=<path>`: the marker contains the full room, author and recipient fingerprints, separated by spaces. The exact signed consent stays out of its room's ready set, so it is not admitted while every other entry (the rows before it, a key package) is, and independent sender-key delivery proceeds; it does not hold the room's one admission, so the rows arrive whether the consent reached the node before them or after. An atomically published sibling, `path.with_extension("entered")`, records those fingerprints and the actual entry hash; the proof checks that hash against the author's shipped hash view. Removing the marker makes that same consent ready again (within 20 ms). The retained-row journey uses one render page plus one row, within the automatic live suffix, and compares `envelope.body` rather than the encoded envelope in `text`. Same `test-knobs` rule.

`VOX_TEST_OMP_RECEIPT_HOLD_FILE=<path>` with `VOX_TEST_OMP_RECEIPT_NODE=<node>` and
`VOX_TEST_OMP_RECEIPT_SESSION=<session>` parks consumption of the exact enqueued Session admission's
physical receipt while the marker exists. `<path>.engaged` records node, Session, attachment
generation and room. The actor remains free to commit and serve unrelated commands; this stages
receipt-consumer delay, **not** physical-store latency. Removing the marker releases the original
receipt; physical actor termination also releases the hold. The marker is staging evidence only:
the original and subsequent private Session bodies at actual consumers supply the verdict. Same
`test-knobs` rule.

The v0.4.16 receipt-ownership spike used three unmodified OMP 18.16.0 native-extension
clients in one scratch room, each bound through `vox agent room` under its own node and
actual Session ID. Every Vox command set scratch `VOX_DATA_DIR` and `VOX_CONFIG_DIR`;
the CLI was a release-profile build with `test-knobs`. While one exact receipt was held,
the original tool result and a later reply had to remain readable through the authorized
`vox room session --json --details` consumer, and another Session had to answer independently.
After release, both original and later bodies were retained. Restoring only the historical
two-second receipt timeout in a detached inverse lost the later consumer body and failed
the same assertion. This was an uncommitted real-client spike, not a new CI proof or evidence
of store latency, lifecycle recovery, or signed-release acceptance. See #1140 for its
source-bound receipts and separate lifecycle acceptance.

`VOX_TEST_HOLD_PACKAGES_FILE=<path>`: while the marker exists, every sender-key acceptance entrance is held: the retained-package worker, room preparation, and live pairwise delivery. The first interception creates `<path>.engaged`; this alone does not prove a saved body. Committed recipient package bodies append 64-byte raw room/author records to that same receipt. The FX-22 proof requires both exact authors in every room, with zero received generations, before stopping either source. Retained packages stay queued; a live sender receives not-accepted and retains/retries delivery. Removing the marker and driving the shipped trust command replays local packages. Same `test-knobs` rule.

`VOX_TEST_HOLD_RENDER_FILE=<path>`: an empty marker parks existing render work. A 96-byte marker containing a raw room id and two raw author ids parks that room and is renamed with `.ready` appended when both exact sender keys are held. A 64-byte marker containing a raw room id and one raw author id lets a bounded native turn run, then is renamed with `.engaged` appended only after that author's visible rows commit and the completed save successfully publishes its saved-read view. Later turns then park. The FX-22 proof reads only shipped status and exact room rows for its verdict; these marker states only establish and freeze the causal boundary. Same `test-knobs` rule.

`VOX_TEST_HOLD_GOVERNANCE_SWEEP_AFTER_FILE=<path>`: the marker contains one raw room id. Accepted remote governance input renames it with `.ready` appended; unrelated room work and deadline wakes cannot arm it. One bounded sweep consumes only that ready marker, renames it with `.engaged` appended after selecting the room, and parks with its cursor beyond it. The FX-22 proof uses a remote administrator's same-name append for that input wake, then requires the room's real authority deadline to schedule the later sweep and remove the administrator. Same `test-knobs` rule.

`VOX_TEST_PRIVATE_POLICY_HOLD_FILE=<path>`: while that file exists, no room's private-Session policy is ready in that daemon, as while its Session-floor index is behind its authors' heads at a restart. A proof stages a peer's drive key arriving in that window (its pass is saved as pending and not run), stops the daemon, removes the file and starts it again to see the room open (ADR-038 FX-26). Same `test-knobs` rule.

`VOX_TEST_HOLD_PACKAGES_FILE=<path>`: while that file exists, the daemon leaves received key-packages queued instead of opening them. The quiet-room proof uses the hold only on the addressed recipient, while another member settles the authenticated public header for its role. Same `test-knobs` rule.

`VOX_TEST_FX29_CONTENT_OUTCOME_FILE=<path>`: the first sparse Content effect on that daemon
creates the marker once with `accepted:<entry-hash>` after its transaction and visible projection
complete, or `refused:<entry-hash>` after the room records the effect failure. The quiet-room proof
matches Alice's hash, then performs exactly one shipped Bob read for the Content publication
verdict. The marker is causal apparatus only and the exact read is the PRODUCT verdict. Same
`test-knobs` rule.

The isolated FX-29 mutants are
`VOX_TEST_WATCHDOG_SECS=<operator-deadman> scripts/run-fx29-mutant.sh drop-resume-owed` and the
same command with `finish-control-after-effect` or `track-content-through-settled-index`. The
delayed-refill mutant (`refill-content-with-current-time`) was removed with its claim: since
`7257301f9` (#1411) a node never owes or fetches a body whose lifetime is over
(`held_history.rs`, `completed`), so no shipped path brings the late bytes it needed. The first
removes only the `ResumeOwed` installation after the causally staged stale archive return; the
second restores the merge bug that tries to apply a sparse Presence before its position is
semantically published; the third makes sparse Content retention rediscover the entry only through
the still-unsettled public index instead of using the transaction's exact authenticated entry. The
Content verdict is attached only to one Bob read after the outcome marker binds Alice's exact
accepted entry hash; later reads retain their own claims. The runner accepts only each exact named
PRODUCT verdict after its exact staging line. Its
transcript is written under `target/fx29-mutants/`. The required positive deadman is chosen by the
operator for that machine and only turns a whole-proof wedge into APPARATUS; elapsed time never
decides the PRODUCT verdict. This is an on-demand diagnostic, not CI or a release gate.

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `a_newcomer_reads_the_whole_history_proof::a_returning_member_crosses_a_private_package_and_keeps_its_cursors` | A returning member does not settle its feed cursors across another member's private package or does not keep them exactly across a restart, members do not exchange posts afterwards, `vox status` does not name the last room sync, or a late member is shown a body every holder pruned. Bob returns behind two authors, crosses Carol's header-only private package, pages back once for Carol's posts below his first window, and after a restart his status shows the exact feed heads he held; Carol comes back and all three exchange posts; a member trusted before the posts shows a body every holder pruned as not received yet and does not show it. Its former privacy claim (Carol cannot read Alice's tail while Alice is offline) was removed: since #1075 (ADR-036 as amended by ADR-046; PRD-001 R11) every member keeps the sealed package so an always-on member carries it to an offline recipient, proven by `key_package_proof.rs::keys_reach_an_offline_member_through_an_always_on_member`. Its former interrupted-request resume (`--history resume`) was removed: since #1411 (ADR-054) a request was outstanding at the interruption only by chance; that command has no proof in this release. Its former delayed-body refill (the late member never shows the body even after its bytes come back) was removed: since `7257301f9` (#1411) a node never owes or fetches a body whose lifetime is over, so those bytes never come. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_returning_member_crosses_a_private_package_and_keeps_its_cursors --nocapture` | one real machine | not timed in CI |
| `a_newcomer_reads_the_whole_history_proof::a_room_that_cannot_finish_preparing_says_why_and_costs_nothing` | A room sits at "preparing history" with no reason shown, or a preparing room keeps the daemon busy (ADR-038 FX-15, FX-16, FX-24; #991). Alice's fold is held while bob's rows arrive; after her restart `vox room list` and `vox status --json` must name the wait within 5 s, the room must cost under 3 s of CPU and run no sync round over a minute, and open within 10 s of the hold's end. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_room_that_cannot_finish_preparing_says_why_and_costs_nothing` | a real machine | not timed in CI (about 2 min on a Mac) |
| `a_newcomer_reads_the_whole_history_proof::a_room_with_its_own_session_records_opens_after_a_restart` | A room with Session records never leaves "preparing history" after a restart, or a peer's drive key received at a restart is never rendered (ADR-038 FX-26; #991). Bob's drive key reaches alice while her private-Session policy is held not ready; after her restart the room must open within 20 s, read its rows, and within 30 s list bob's Session as one she can drive. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_room_with_its_own_session_records_opens_after_a_restart` | a real machine | not timed in CI (about 2 min on a Mac) |

### A full scratch filesystem (macOS; no sudo)

| Proof | Symptom | Command | Needs | Measured |
|---|---|---|---|---|
| `a_claude_session_is_mirrored_and_answered_from_either_side_proof::a_full_room_recovers_and_keeps_its_session_entries` | A room stays unable to save after disk space returns, hides the OS error, or drops Session activity. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_claude_session_is_mirrored_and_answered_from_either_side_proof a_full_room_recovers_and_keeps_its_session_entries -- --ignored --nocapture` | A 64 MiB userspace HFS+ disk image via `hdiutil`; prints `OPTIONAL PROOF NOT RUN` if unavailable. | 32 s on a Mac |

### Heavy (minutes of work, thousands of posts, or long waits)

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `failure_reasons_proof::a_full_keyring_names_its_cause` | `vox trust add` past the 1,024 identities a keyring holds is not refused with the keyring-full cause and how to make room (case (9) at the real cap). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test failure_reasons_proof -- --ignored --exact a_full_keyring_names_its_cause` | 1,100 production-Argon2id `trust add`s, eight at a time against one daemon | minutes in release; most of an hour in debug (#295) |
| `notify_proof::a_room_that_cannot_sync_notifies_once_and_once_when_it_syncs_again` | A disconnected room with no new sync entries for ten minutes is never said, is said more than once, or is never said to have recovered (PRD-001 R37). Alice's only other member and anchor stop; one desktop notice names the stale room, then one recovery follows Bob reconnecting, posting, and Alice reading the new post. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test notify_proof -- --ignored --exact a_room_that_cannot_sync_notifies_once_and_once_when_it_syncs_again` | nothing beyond `vox` | over ten minutes (`STALE_SYNC_MS`) |
| `a_join_outlives_its_displaced_path_proof::a_join_outlives_its_displaced_path` | A slow join fails when the network path changes under it. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_join_outlives_its_displaced_path_proof -- --ignored --exact a_join_outlives_its_displaced_path` | time (a 300 s join grind) | 314 s / 315 s |
| `a_slow_joiner_gets_in_or_is_told_why_proof::a_joiner_slower_than_the_old_patience_gets_in` | A slow machine can't get into a room. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_slow_joiner_gets_in_or_is_told_why_proof -- --ignored --exact a_joiner_slower_than_the_old_patience_gets_in` | time (a 150 s grind) | 488 s / 490 s for both, run together |
| `a_slow_joiner_gets_in_or_is_told_why_proof::a_joiner_slower_than_the_patience_is_told_why` | A machine too slow to join gets no explanation. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_slow_joiner_gets_in_or_is_told_why_proof -- --ignored --exact a_joiner_slower_than_the_patience_is_told_why` | time (a 485 s grind; run it alone so other work does not distort it) | (in the figure above) |
| `two_backlogs_meet_proof::two_backlogs_that_meet_both_cross` | Two members who were offline with big backlogs don't both catch up. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test two_backlogs_meet_proof -- --ignored --exact two_backlogs_that_meet_both_cross` | 48 MB of history | 42 s / 48 s |
| `a_member_reads_only_what_follows_trust_proof::posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read` | Someone trusted later reads what came before the trust, or misses what came after. Arm B's privacy half is tested only if the reader's node received the rows below post 1,101; this act does not show that it did. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_member_reads_only_what_follows_trust_proof -- --ignored --exact posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read` | 3,160 posts through the CLI, then about 20 `--history older` demands | about 290 s |
| `a_newcomer_reads_the_whole_history_proof::a_newcomer_trusted_before_every_post_reads_all_of_them` | A newcomer trusted from the start misses part of a long room's history, or the page below what it holds does not come when asked for (`vox room read --history older --before <oldest row>`, ADR-037 R1). A red names the page that never arrived and quotes `--history status`. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_newcomer_trusted_before_every_post_reads_all_of_them` | 1,500 posts, read back a page at a time in the room's order | 27 s / 30 s (before the pages were asked for on demand) |
| `a_newcomer_reads_the_whole_history_proof::a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back` | A member back after missing 8,000 acknowledged posts does not show the newest first, or does not come to show every post it missed without asking (ADR-052 RG-6, ADR-054 PL-3: a returning member owes itself everything above its floor). Sampled by full paged `vox room read`s a second apart; red when the newest is not among the first 256 shown, or when the shown count stops moving short of 8,000 for ten answered reads. Mutant: `VOX_MUTANT_NO_PROMOTION=1` (ADR-054 M3; build with `test-knobs`; given to the returned reader's daemon only, which must say it engaged). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_newcomer_reads_the_whole_history_proof -- --ignored --exact a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back --nocapture` | Fresh staging: 8,000 CLI posts and two scratch daemons; no test knob in the plain run | About fifteen minutes (staging, then about 190 s to show all 8,000, run r42). No latency verdict. |
| `a_long_room_reopens_proof::a_room_of_five_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all` | A long room loses posts across a restart, or a newcomer never catches up with it. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_long_room_reopens_proof -- --ignored --exact a_room_of_five_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all` | 5,000 posts | not timed here |
| `a_long_room_reopens_proof::a_room_of_a_hundred_thousand_posts_reopens_and_a_newcomer_holds_them_all` | The same, in a room past 65,536 posts. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_long_room_reopens_proof -- --ignored --exact a_room_of_a_hundred_thousand_posts_reopens_and_a_newcomer_holds_them_all` | 100,000 posts | not timed here (about 21 min on a Mac) |
| `an_idle_node_stays_on_its_board_proof::an_idle_node_stays_findable_on_its_board` | An idle `vox` stops being findable after a while. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test an_idle_node_stays_on_its_board_proof -- --ignored --exact an_idle_node_stays_findable_on_its_board` | time (several record lifetimes) | 113 s / 107 s for both, run together |
| `an_idle_node_stays_on_its_board_proof::a_round_to_one_anchor_does_not_put_off_the_others` | One flapping anchor makes you unfindable on the others. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test an_idle_node_stays_on_its_board_proof -- --ignored --exact a_round_to_one_anchor_does_not_put_off_the_others` | time | (in the figure above) |
| `a_relayed_pair_finds_a_direct_path_proof::a_relayed_pair_finds_a_direct_path_once_one_becomes_possible` | A relayed connection never upgrades to a direct one. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_relayed_pair_finds_a_direct_path_proof -- --ignored --exact a_relayed_pair_finds_a_direct_path_once_one_becomes_possible` | time (two 60 s retries) | 138 s / 137 s |
| `a_displaced_relay_is_let_go_proof::a_relayed_path_a_direct_one_displaced_is_let_go_after_its_grace` | An anchor keeps carrying relays for pairs that went direct. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_displaced_relay_is_let_go_proof -- --ignored --exact a_relayed_path_a_direct_one_displaced_is_let_go_after_its_grace` | time (a 60 s grace) | 82 s / 83 s |
| `every_member_is_back_after_an_anchor_restart_proof::every_member_is_back_after_an_anchor_restart` | After an anchor restarts, some members stay disconnected, or its management listener refuses node identity requests before startup attaches the anchor. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test every_member_is_back_after_an_anchor_restart_proof -- --ignored --exact every_member_is_back_after_an_anchor_restart` | 32 real `vox daemon`s and one `vox node`, 16 members per source IP; run alone after building. Startup acceptance waits for initial attachments, including management-only startup; mutant starts acceptance during management registration again. | about a minute in release; not timed on CI |
| `a_room_takes_every_joiner_proof::every_joiner_of_a_three_hundred_member_room_gets_in` | Joining a large room fails with "the anchor could not be reached" while the anchor is up: a busy anchor closed the connection the join was fetching the room over (V210-104, #299). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_room_takes_every_joiner_proof -- --ignored --exact every_joiner_of_a_three_hundred_member_room_gets_in` | an anchor, a host and 301 one-shot `vox connect` joins, four at a time; run it alone. A rate claim: the defect failed 1–2% of joins, so when hunting it, run it up to three times | about 8 min in release; not timed on CI |
| `a_room_of_about_500_members_works_proof::a_room_of_about_500_members_works` | A room of about 500 members does not work: a join is refused, a post does not reach every member, or a stopped member does not catch up (PRD-001 R2). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_room_of_about_500_members_works_proof -- --ignored --exact a_room_of_about_500_members_works` | an anchor, a host and about 500 real `vox daemon`s on one machine; run it alone, in a terminal that stays open | 1.5 to 2.5 hours in release; not timed on CI |
| `an_anchor_that_restarts_is_redialled_promptly_proof::a_connection_held_only_through_the_stopped_anchor_says_so` | When the anchor a host's only path ran through stops, the message about the host blames a liveness probe instead of saying the path ran through the stopped anchor (V210-93). | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test an_anchor_that_restarts_is_redialled_promptly_proof -- --ignored --exact a_connection_held_only_through_the_stopped_anchor_says_so` | a real machine with IPv4 and IPv6 loopback; it says CANNOT MEASURE when the forward did not hold the relayed connection as its host's | not timed here |
| `opening_a_room_does_not_hold_up_a_post_proof::a_post_answers_while_the_node_opens_another_room` (macOS only) | Posting stalls while the same node opens another room with its passphrase. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test opening_a_room_does_not_hold_up_a_post_proof -- --ignored --exact a_post_answers_while_the_node_opens_another_room` | drives the TUI (`pyte`, or `VOX_PYTE_PATH`); hundreds of posts | not timed here |
| `a_room_of_many_members_syncs_without_holding_its_lock_proof::a_room_of_many_members_syncs_without_holding_its_lock` | A room with many members stops answering its own member while it syncs. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_room_of_many_members_syncs_without_holding_its_lock_proof -- --ignored --exact a_room_of_many_members_syncs_without_holding_its_lock` | time (joins many identities) | not timed here |

**Accepted (the decider, 2026-10-07, #342):** under load, `every_joiner_of_a_three_hundred_member_room_gets_in` refuses a few joins when one online member is slow to agree within 5 s (the strict room-wide cap). The refusal names the silent member, and the next join gets in. Rooms that big are not expected yet, so there is no product change.

**Accepted (the decider, 2026-10-07, #342):** under load, `a_room_of_about_500_members_works` refuses a few joins the same way, for the same reason.

The `a_room_takes_every_joiner_proof` row came with #299 (V210-104), which made the proof optional with a stand-in from the start. The last four rows came from #262 (V210-71) and #287 (V210-93). Both first made these proofs opt-in, #262 through `[[test]]` entries with `required-features` and #287 through `#[cfg(feature = "heavy-proofs")]`. Neither was compiled without the feature, so nothing showed the proof existed. Each now has a stand-in, like the rest.

**Part of a blocking proof:** `failure_reasons_proof`'s case (9), the keyring-full refusal, is blocking at a small keyring cap set by the test-only `VOX_TEST_KEYRING_CAP`. Its arm at the real 1,024-identity cap is the optional `a_full_keyring_names_its_cause` above.

### Spike (samples a race under deliberate CPU load)

| Proof | Helps troubleshoot | Run | Needs | Time |
|---|---|---|---|---|
| `a_member_that_just_joined_is_not_refused_proof::a_member_that_just_joined_is_not_refused_by_its_anchor` | A member who just joined is told of an integrity failure that isn't real. | `cargo test --release -p vox-tui --features optional-proofs,test-knobs --test a_member_that_just_joined_is_not_refused_proof -- --ignored --exact a_member_that_just_joined_is_not_refused_by_its_anchor` | it makes its own CPU load; run it alone | 88 s / 102 s |

### Large collection paging (ADR-034 #791)

`cargo test --release -p vox-tui --features test-knobs,optional-proofs --test a_large_room_reads_whole_proof every_large_collection_reaches_the_cli_and_app -- --exact --ignored --nocapture`

Two shipped nodes exchange 1000 unread 64 KiB messages and 1000 real service shares. Stopping
the shares produces 1000 real decision events. The CLI and app client must read every row
whole, in order where ordered, and remain usable afterwards. This expensive proof is optional
and blocks neither CI nor a release. Without the feature it says OPTIONAL PROOF NOT RUN.

`cargo test --release -p vox-tui --features test-knobs,optional-proofs --test a_large_room_reads_whole_proof a_six_thousand_entry_room_opens_in_the_tui_in_order -- --exact --ignored --nocapture`

A real room receives 6000 posts. Its shipped TUI must open at the newest rows, show every
row in order as PageUp walks the timeline, and return to the newest row with End (#793).
This expensive proof is optional and blocks neither CI nor release.

`cargo test --release -p vox-tui --features test-knobs,optional-proofs --test a_large_room_reads_whole_proof a_seventy_member_room_opens_with_every_read_mark_and_trust -- --exact --ignored --nocapture`

Seventy shipped nodes share one scratch daemon, join a room, trust each other and mark70
messages read. The app client must expose all69 readers on every message and every trust
relationship. The terminal must open the room and show every reader and peer's trust (#792).
This expensive proof is optional and blocks neither CI nor release.

### Private Session record storage (ADR-052 RG-13)

`cargo test --release -p vox-tui --features test-knobs,optional-proofs --test retention_proof private_session_steps_store_one_body_and_reopen_after_rotation -- --exact --ignored --nocapture`

Two scratch daemons append different-sized Session steps, read identical complete pages,
restart, and rotate the drive generation. The author must still read the old steps;
the member downgraded to read must not read the Session. Stopped-store measurements
require one row per step, one stored byte per body byte, and one signature's fixed cost.
A wire peer holding the author's identity then offers forged steps: one changed bit in the
signature, header, room, author or ciphertext, and one step's genuine signature on the
message of the step before it. The recipient must show and store none of them, and still
read every genuine step.
This proof is optional; without the feature it prints OPTIONAL PROOF NOT RUN.

### RG-8 computer anchors and late pairing closure

The existing `nodes_of_one_daemon_proof` hosts two on-demand real-binary acts:
`computer_management_uses_anchors_added_after_start` stages a real relay and restart;
`either_computer_closes_a_half_signed_pairing_at_once` waits for each late completion's
causal exchange outcome, once for each holder, so may take two minutes. Both are compiled
only with `optional-proofs`, with loud `not_run!` stand-ins otherwise.
Build once with `cargo test --release -p vox-tui --features test-knobs,optional-proofs --test nodes_of_one_daemon_proof --no-run`,
then select one function with `-- --ignored --exact --nocapture`. Run these acts quiet.
Each uses isolated account data/config roots. Closing a half-signed attempt is local:
the other computer can still complete until expiry; the closer refuses it. Close it on
both computers to stop the attempt on both.

The seconds-long no-route diagnosis, status guidance and pause/resume guidance acts are
release-gate proofs, not optional proofs.

### Linux release installation (ADR-051, RG-11)

Build the Linux dist with `scripts/build-linux-release.sh /absolute/path/to/linux-dist`.
The release workflow and this wrapper run `scripts/linux-release-steps.sh` in the same
digest-pinned manylinux glibc 2.28 x86_64 image. Add the release's own `install.sh` to that
dist before running the asset proof. All container starts, builds and proof runs on the
shared proof host go through its build slot.

The release workflow's `workflow_dispatch` candidate-only mode runs that same Linux job
after checking the requested commit, alongside the signed Mac candidates. Its
`vox-candidate-normal-x86_64-unknown-linux-gnu` artifact includes the six Linux release
files and that commit's `install.sh`; candidate-only mode publishes no release.

```sh
for proof in the_linux_release_asset_installs_only_where_it_runs \
  the_linux_release_installer_refuses_below_its_floor \
  the_linux_release_installer_names_a_missing_loader; do
  VOX_PROOF_DIST=/absolute/path/to/release-assets cargo test --release -p vox-tui \
    --features optional-proofs,test-knobs --test install_sh_proof \
    "$proof" -- --ignored --exact --nocapture
done
```

These optional proofs drive the supplied installer and asset as an ordinary user in five
disposable `linux/amd64` container acts, each limited to four CPUs and 8 GiB. Digests are
pinned inline: AlmaLinux 8 is the glibc 2.28 floor; Ubuntu 22.04 (2.35) is one supported
system above it and matches the reported install failure; Ubuntu 18.04 (2.27) is below
the floor, once with working `getconf` and once with it unavailable; Alpine 3.20 has no
GNU loader. It records image, architecture, kernel, libc, command output and wall time,
and removes its containers and images it pulled. A remote Podman connection must be the
already-running `podman-machine-default`; the proof forwards only its loopback release
server port into that VM. No profile or home directory is mounted. Without
`optional-proofs`, the usual loud `OPTIONAL PROOF NOT RUN` stand-in is compiled instead.
Under amd64 emulation, `/proc/<pid>/exe` can name QEMU rather than Vox. The asset
proof records that symlink without treating it as the guest program's identity, and
checks the launched Vox path in the daemon's kernel argv.

Arm (f), a shipped asset updating from a stand-in release server, is not run: shipped
Vox takes releases from GitHub only and contains no release-source test knob.
Arm (e) proves the same updater code on a `test-knobs` build and blocks; the real release
source is exercised only when a later release exists.

The blocking source journeys run as x86_64 Linux in an emulated container on an arm64
host, not natively as arm64 (which has no Linux release target). The emulated harness is
release-built: a debug harness run under QEMU was interrupted after 46 minutes without
a verdict, and release mode avoids unoptimized fixture hashing. This apparatus choice does
not change the real x86_64 product, installer or release floor.
Emulated executions use shared slots only; time-bound arms are not judged under emulation.
Measure the smallest arm first and keep holds near 20 minutes. A longer single arm needs
its measured apparatus cost reported before another run, not a false product-time verdict.

```sh
cargo test --release -p vox-tui --features test-knobs --test install_sh_proof \
  install_sh_installs_what_it_verified_and_refuses_what_it_could_not -- --exact --nocapture
VOX_PROOF_NEXT_BINARY=/absolute/path/to/9.x/vox cargo test --release -p vox-tui \
  --features test-knobs,optional-proofs --test update_proof \
  an_update_restarts_its_daemon_and_uses_a_different_local_version -- --ignored --exact --nocapture
```

Build the fixture from a copy of the same tree with the workspace version's first
character changed to `9` (0.4.31 becomes 9.4.31), using
`cargo build --release --bin vox --features vox-tui/test-knobs`. Record the image digest,
`uname -m`, VM kernel and build wall times with both journeys' claim lists.

The Linux kernel-keyring proof crosses login-session boundaries and also checks a lost
boot credential and a chosen persistent passphrase file:

```sh
cargo test --release -p vox-tui --features test-knobs --test the_daemon_and_its_nodes_proof \
  a_linux_typed_unlock_survives_another_sessions_daemon -- --ignored --exact --nocapture
```

For a typed unlock across the actual Linux update, use the same compiled `9.x` fixture:

```sh
VOX_PROOF_NEXT_BINARY=/absolute/path/to/9.x/vox cargo test --release -p vox-tui \
  --features test-knobs --test update_proof a_linux_typed_unlock_stays_ready_after_update \
  -- --ignored --exact --nocapture
```

It needs `python3` (the existing typed-terminal driver) and `keyctl`. In a container,
`--security-opt seccomp=unconfined` permits `add_key` and `keyctl`, which the default
container profile refuses; this changes syscall access, not keyring lifetime, uid
permissions, cross-session visibility or the user-visible Ready/Locked assertions.
It clears only a newly created session keyring and removes only its scratch node's
boot credential, never another user's or another node's key.

Rootless Linux user namespaces can refuse the per-user keyring with `ENOKEY`, even with
seccomp disabled. The Ready-after-restart proof needs an ordinary uid in the initial user
namespace and a successful `keyctl add user <scratch-name> <scratch-value> @u` precondition.
An existing rootful Podman connection to the authorized machine can supply that container;
do not change the machine's rootful setting or default connection.

The Linux store creates its key in a temporary thread keyring while setting uid-only
permissions, then links it into the user keyring and drops the thread reference. Creating
it directly in an unpossessed user keyring does not grant the caller permission to change
the key's default permissions.

Run this preservation proof where `@u` is unavailable: a rootless namespace, an ordinary
container's default seccomp profile, or QEMU returning `ENOSYS`:

```sh
cargo test --release -p vox-tui --features test-knobs --test the_daemon_and_its_nodes_proof \
  a_linux_unavailable_keyring_keeps_unlock_ready_without_a_disk_secret -- --ignored --exact --nocapture
```

It checks successful typed unlock with the actual not-remembered reason, Ready for that
daemon's lifetime, no plaintext fallback, Locked with the unlock command after restart,
and successful lock and forget-passphrase. An unavailable keyring (`ENOKEY`, `ENOSYS`,
`EPERM`, `EACCES` or `EOPNOTSUPP` while finding a key) has nothing this process can
remember or forget. A failure to revoke or unlink a key found in a working keyring
remains an error. Retention itself cannot be judged under QEMU's missing keyring syscalls;
run its typed-update triplet natively with both genuinely compiled native versions.

### Fetch-serving cache, receipt witnesses and old-room cleanup (ADR-052 RG-13, RG-6)

Fetch proof descriptors share one daemon-wide FIFO cache capped below 8 MiB, including keys,
values and container/rehash allocation. A proof fetched, rebuilt or served for one request is
not written to the store. Canonical prefix ranges, source headers, contexts, witnesses and
receipts remain durable, and each durable inclusion or prefix receipt keeps, in the same
transaction, exactly the pieces that serve it again under its head (the inclusion siblings or
the consistency nodes) as ProofRange rows: a member that verified another author's evidence
serves it after a restart while that author is away. A repeated fetch under the same head,
author and position writes nothing new. Opening a room created by an older build removes that
room's old ProofRange objects and index references once, in bounded atomic batches;
interruption leaves completed batches applied and the next open resumes by an idempotent scan.
Completion is recorded once as one sealed bit (CBOR uint 1) in the existing per-room
KeyMaterial segment namespace, slot 30; subsequent opens read that bit and do not scan
the object tree, and a room created or joined by this build carries the bit from its first
transaction. No directory or store-format version changes. Locked/unopened rooms
are not converted by a whole-store startup pass.

These optional journeys extend `retention_proof.rs` and
`a_newcomer_reads_the_whole_history_proof.rs` and use private scratch profiles/Keychains:

```sh
cargo test --release -p vox-tui --features test-knobs,optional-proofs --test retention_proof \
  fetching_keeps_serving_proofs_out_of_the_store -- --exact --ignored --nocapture
cargo test --release -p vox-tui --features test-knobs,optional-proofs --test retention_proof \
  opening_a_room_reclaims_old_serving_proofs_across_interruption -- --exact --ignored --nocapture
cargo test --release -p vox-tui --features test-knobs,optional-proofs \
  --test a_newcomer_reads_the_whole_history_proof \
  a_newcomer_reads_a_member_while_the_author_it_cites_is_stopped -- --exact --ignored --nocapture
```

The first exchanges messages across changing signed heads, abandons verified fetches, restarts
both members and pages back through every acknowledged message; every decoded stopped-store
ProofRange row must be a piece of a receipt held in the same store, and two more restarts with
a repeated history request leave both members' row counts unchanged. Its mutant
`VOX_MUTANT_WITNESS=every-trace` (every range a completed proof touched is saved) turns it red.
The second seeds the old serving-row shape in a real stopped room, opens it, interrupts
after a committed cleanup batch and reopens it, preserving other object kinds and readable
history. A second open preserves planted stopped-store canaries, proving the completed room
does not scan again; each row-count observation also records the store's file length.
The third: an author with 200 posts and a member that read them and posts; the author is
stopped for good and the member restarted; a newcomer that reaches only that member reads its
next post and trusts it. Red on 403218281 and under `VOX_MUTANT_WITNESS=unkept` (a receipt is
saved without its pieces) or `VOX_MUTANT_NEW_ROOM_UNMARKED=1` (the restart's sweep deletes
them): the newcomer then wants nothing from the member and needs only the stopped author.

### Reading while messages expire (#1373)

Two optional acts in `retention_proof.rs`, each in private scratch profiles:

```sh
cargo test --release -p vox-tui --features optional-proofs,test-knobs --test retention_proof \
  a_room_stays_readable_while_messages_keep_expiring -- --ignored --exact --nocapture
cargo test --release -p vox-tui --features optional-proofs,test-knobs --test retention_proof \
  a_hook_continuation_read_skips_expired_messages -- --ignored --exact --nocapture
```

The first sets a one-second message lifetime and keeps posting: reads must answer, without
already-expired messages and with exact pages, counts and thread summaries, while messages
expire; a backlog larger than one cleanup sweep must still answer `the room is refreshing saved
history; retry` until it is readable. The second holds the native prune with a test knob and
requires the hook's continuation read to skip the expired rows instead of refusing. Then, with
removal held (`VOX_TEST_HOLD_RETENTION_REMOVAL_FILE`) and the lengthening's projection turn held
(`VOX_TEST_HOLD_LENGTHENING_FILE`), the admin keeps everything: the hook's read must still leave
out what the one second had made due. Its mutant is `VOX_MUTANT_RETENTION_EDGE=read`.

The same knob names the other retention-fence mutants: `stopped`, `seen` and `merged` for
`a_node_keeps_less_than_its_room_and_never_shows_what_arrives_expired` (a node stopped cleanly
keeps what passed its old lifetime while it was stopped; after a kill, what its shorter lifetime
hid stays hidden and a message that first reaches it after a lengthening is kept; a later
shortening and lengthening does not remove that message, which `merged`, one pair per kind,
does), and `private`
for `session_steps_expire_after_two_days_unless_the_admin_chose_otherwise` (a step the admin's
three-second step lifetime had expired, still stored, removal held, when the running room switches
to two days, stays expired, and is removed once the hold goes).

## RG-15 release assets in disposable guests

`scripts/release/guest-state.sh` runs one state in the existing `vox-app-proofs` Tart guest,
using the shared guest lock and one build-slot hold per build or proof, then stops the guest.
`scripts/release/linux.py` runs one journey in its own `vox-rg15-*` container and removes it.
Neither runs the product on the host or changes its real profile. The dist's own `install.sh`,
records and signed bytes are the inputs; every product command uses a private home/data/config.

For a guest prerequisite check without building or running a journey, use
`guest-state.sh <new-evidence-state> readiness readiness <dist>`. It takes the free guest lock
without waiting, records the SSH and journey Node paths/versions and `Promise.withResolvers`,
records free disk, then stops the guest and releases the lock. A missing Node22 runtime or less
than10GiB free is APPARATUS, not a product verdict. Node runtime preparation belongs only in
the apparatus's own directory, never a system-wide guest installation.

The existing proof files have three optional entry points:

- `install_sh_proof::a_shipped_release_installs_and_serves_a_fresh_node`: install the given
  `VOX_PROOF_DIST`, check its version, create a Ready node and post/read a room.
- `update_proof::a_published_install_updates_through_github_with_its_agent_turn`: install a
  published previous dist, run its real GitHub updater, and require
  `VOX_PROOF_EXPECTED_VERSION`, Ready node and surviving room. The old loaded extension's
  messages are quoted as EXPECTED OLD BEHAVIOUR. Continued later-news delivery passes; otherwise
  the advice must contain at least one of the accepted phrases `Vox update mismatch` or
  `start a new native OMP conversation` (other `NOTIFY:` lines alone do not pass).
  A new conversation after update must show later news exactly once, with no
  `Vox update mismatch` or uncertainty. This is the published-previous path.
- `update_proof::a_candidate_source_pair_updates_with_its_agent_turn`: before-tag observation
  with `VOX_PROOF_DIST` and `VOX_PROOF_CANDIDATE_DIST` naming genuine **nonshipping**
  test-knobs builds. The same held conversation must show later news exactly once, report one
  reconnecting line and no mismatch. This proves the candidate's updater/restart/agent turn,
  not the published previous updater or real endpoint. macOS retains Apple verification.

The two update observations are deliberately distinct. Before publication, normal assets have
no release-base override. After publication the previous normal asset must update through
`releases/latest`; never substitute a local copy or add a knob to make that observation green.
`VOX_PROOF_JOURNEY_WORK` names a new scratch directory. The launcher uses
`VOX_PROOF_JOURNEY_SCRIPT` only to locate the apparatus after copying it into a guest.
For explicitly authorized refusal diagnosis only, `VOX_PROOF_INSPECT_REFUSED_UPDATE=1`
records the installed version, status and saved post after a refused update, closes the native
conversation, and records one further update and explicit daemon restart. The original refusal
remains RED even if recovery succeeds; ordinary release journeys never enable this option.

The busy-room journey already accepts `VOX_PROOF_SHIPPED_BINARY`; the guest runner points it at
the binary the actual installer put in the scratch home. Build its release harness in a shared
hold, then execute it alone. QEMU cannot judge its real-time posting/pause cadence, kernel-keyring
retention, or other time-bound claims; such rows are APPARATUS/not judged under emulation, never
a shipping GREEN. A non-timing install or updater verdict can still be measured there.

macOS cleanup queries LaunchServices before unregistering an owned app path; a path that is
already absent needs no removal. The exact PlugInKit `no plugin at <owned path>` response
likewise means already absent. Other registration/cleanup failures are APPARATUS and prevent
a successful journey state; the guest wrapper still stops its owned VM before releasing the lock.

Every normal journey reads the installed, resolved binary and refuses a
`VOX_TEST_RELEASE_BASE` marker as APPARATUS (wrong asset supplied). Controlled-update instead
requires that marker in both nonshipping binaries. GREEN names the installed SHA-256 (both
before/after digests for updates) and is printed only after owned cleanup succeeds. A cleanup
failure after passing assertions says the assertions had held, exits nonzero and prints no GREEN.
A wait that makes no progress names the unmet claim and is APPARATUS/not judged; an unexplained
red is not cleared by a later green rerun.
