# User manual evidence map

Updated: 2026-10-04. Scope: ADR-027 M27.1 / work item #421. This is maintainer evidence,
not a chapter in the public navigation manifest. Source inspection is not an execution test.

## Baselines

| Label | Exact source revision | Use |
|---|---|---|
| Released v0.2.10 | `8d95a381f14d6bbb45f714d75f64e57d2f5dbf96` | Default task chapters and stable troubleshooting |
| Development rearch/v030 | `2d8385d4f90891c96843f32d6d002bc1b69aac1e` | Explicitly labelled development chapter and model distinctions |
| Older integrate/v0.3.0 | `06271b79280969caf270001aebffd714cba32244` | Comparison only; never used as a synonym for rearch/v030 |
| Manual branch base | `412303a3` plus accepted ADR-027 | Canonical prose; website resolves moving main once per build |

The website's resolved manual commit is separate from these implementation-evidence refs.
The manual follows `main`; immutable source citations explain which behavior was reviewed.
They are not a maintained website snapshot or a promise that the development branch has
remained unchanged since this review.

## Source map

Paths below are repository-relative and line numbers refer to the source revision in the
first column. Recheck them before changing a claim; a later parser or implementation may
invalidate both an example and its troubleshooting advice.

| Ref | Chapter / claim | Evidence |
|---|---|---|
| v0.2.10 | install: target, exact record, digest, signature, install destination | `install.sh`; `crates/vox-tui/src/update.rs`; `.github/workflows/release.yml` |
| v0.2.10 | first-room: profile selection and identity | `crates/vox-tui/src/cli.rs:27`, `:1200`; `tunnel_cli.rs` identity prompting |
| v0.2.10 | first-room / rooms: create, join, explicit secret input | `crates/vox-tui/src/cli.rs:687–715`; `room_cli.rs:3021` onward |
| v0.2.10 | daemon vs anchor; missing socket | `crates/vox-tui/src/cli.rs:756`; `room_cli.rs:35–74` |
| v0.2.10 | keyring: scope, aliases, rotation, command surface | `crates/vox-tui/src/cli.rs:1329–1396`; `room_cli.rs` trust operations; `ui.rs:24–35` |
| v0.2.10 | rooms: list/read/tail/cursors and lifecycle | `crates/vox-tui/src/cli.rs:583–683`, `:1091`; `room_cli.rs:164–201`, `:782`, `:958`, `:3232` |
| v0.2.10 | services: numeric port, proxy and forward syntax | `crates/vox-tui/src/cli.rs:1148–1197`, `:1400–1493`; `tunnel_cli.rs:735–765` |
| v0.2.10 | exclusive profile and safe holder advice | `crates/vox-tui/src/tunnel_cli.rs:195–221`; `cli.rs` socket-routing branches for service/trust |
| v0.2.10 | join errors distinguish failed steps | `crates/vox-tui/src/tunnel_cli.rs:1090–1273` |
| v0.2.10 | files: live offer, overwrite refusal, verified staging | `crates/vox-tui/src/room_cli.rs:2251–2283`, `:2513–2525`, `:2727`, `:2737–2787`, `:2960–3015` |
| v0.2.10 | agents: generated hooks/plugins/skill and trust | `crates/vox-tui/src/cli.rs:885–1029`, plugin emission near `:2120`; `assets/opencode-plugin.js` |
| v0.2.10 | agents: client-specific wake, no new model run | `crates/vox-tui/src/wake.rs:21–40`, `:136–155`, `:395–396` |
| v0.2.10 | agents: attribution and hook success is not delivery | `crates/vox-tui/src/agent_hook.rs:537`, `:657`, `:833–856`; `cli.rs:885–900` |
| v0.2.10 | claim agreement, status codes, issue vs room | `crates/vox-tui/src/cli.rs:604–628`; `room_cli.rs:1496`, `:1691–1804`; `assets/agent-skill.md` |
| v0.2.10 | reference: paths and secret-input precedence | `crates/vox-core/src/node/paths.rs:1–11`; `crates/vox-tui/src/cli.rs`; `tunnel_cli.rs:89–105`, `:1437–1459` |
| v0.2.10 | reference: daemon room passphrase lines, whole-line then named-room resolution | `crates/vox-tui/src/app.rs:1329–1431`, `run_daemon` |
| rearch/v030 | development: identity vs daemon, naming and TUI limits | `docs/adr/ADR-026-daemon-and-nodes.md:5–10`, `:14–23`, `:56–79`; `crates/vox-tui/src/client.rs:1–18` |
| rearch/v030 | development: selection/migration and detached-node fix | `crates/vox-tui/src/client.rs:37–84`, `:209–227`; `crates/vox-core/src/node/daemonipc.rs:324` |
| rearch/v030 | development: explicit agent node and doctor | `crates/vox-tui/src/cli.rs:839–869`, `:929–956`; `doctor.rs:1–17` |
| rearch/v030 | development: ping is daemon-only, timeout ambiguity | `crates/vox-tui/src/cli.rs:363–374`; `ping.rs:1–13`, `:203–205` |
| rearch/v030 | development: missing body is not trust marker | `crates/vox-core/src/node/api.rs:71–79`; `channel.rs:3858–3905`; `crates/vox-tui/src/room_cli.rs:957–961` |
| rearch/v030 | development: changed service syntax, room lifecycle | `crates/vox-tui/src/cli.rs:341–512`, `:1508–1558` |

## Independent practical verification

The independent verifier `manual_practice_research` used the published v0.2.10 executable,
checked its digest/signing identity, and ran the first-room sequence in two disposable data
and config roots. Its reported observations on 2026-10-04:

- `id` before daemon prompted for new identity passphrase and confirmation.
- A running daemon's empty room list printed `no rooms`.
- Room create, invite, join, and trust-after-join worked in the documented order.
- Both original nodes received the other's distinctive message. `robertGPT` alias case was
  preserved. A local successful post alone was not counted as receipt.
- A wrong room passphrase produced the specific responder-refused explanation and exit 1;
  the same identity then joined with the correct passphrase.
- A room closed in the actual TUI produced the documented closed-room error through the CLI;
  selecting and opening it in the TUI restored reading the previous messages.

The exact commands, executable identity and acceptance evidence belong to work item #421
and the verification work item, not to this prose as an unqualified test-suite claim.
The independent verifier reported corrections: “archive” became “executable” for installation;
the agent join example gained its required invitation; development examples now explicitly
select both disposable roots; and closed-room recovery/daemon passphrase input became concrete
rather than pointing to help that does not show the full file format.

Limits: this exercised same-host loopback nodes, not two physical machines, NAT traversal,
relaying, all service/file paths or a live agent harness. Agent integration statements were
reviewed against release source, not claimed as live-model acceptance. Development commands
were source-reviewed at the stated commit; they were not executed on a real or migrated
profile. No existing personal/family/agent state was opened for these checks.

## Drift that the manual deliberately avoids

- `integrate/v0.3.0` lacks some released prompt/input improvements and rearch diagnostics.
  It is not a valid source for a mixed “v0.3” quickstart.
- Development doctor fallback wording still mentions “profile”; the manual uses the
  specific detached-node remedy, not a blindly copied fallback.
- Generated/shipped prose can overgeneralize urgent wakes; the actual implementation
  explicitly never interrupts Codex. The manual uses client-specific delivery.
- Older design discussions describe auto-held attachments, inline thumbnails, new service
  helpers and UI flows. The manual does not present those proposals as released behavior.
- The first command on a development data root can migrate layout. “Doctor is read-only”
  does not imply that common first-use path resolution never changes files.

Maintain this map together with [manual authoring instructions](manual-authoring.md).
