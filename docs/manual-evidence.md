# User manual evidence map

Updated: 2026-10-04. Scope: ADR-027 M27.1 / work item #421. This is maintainer evidence,
not a chapter in the public navigation manifest. Source inspection is not an execution test.

## Baselines

| Label | Exact source revision | Use |
|---|---|---|
| v0.3.0 | `82523cebc870a29e0947b0cb7c20b4563d233966` (built); manual merged at `c24a260dee708a340df5544f80a4518823e261a8` | Task chapters, troubleshooting, the v0.3.0 command check |
| Released v0.2.10 | `8d95a381f14d6bbb45f714d75f64e57d2f5dbf96` | "Coming from v0.2.10"; the profile-to-node move check |
| `rearch/v030` | `2d8385d4f90891c96843f32d6d002bc1b69aac1e` | Superseded label: an ancestor of the v0.3.0 baseline, which ships it |
| Manual branch base | `412303a3` plus accepted ADR-027 | Canonical prose; website resolves moving main once per build |

`integrate/v0.3.0` is the v0.3.0 release candidate and contains `rearch/v030`
(`git merge-base --is-ancestor 2d8385d4 82523ceb` succeeds). The earlier entry that called it an
older, divergent prototype described `06271b79`, before `rearch/v030` was merged in, and is
withdrawn. Between `82523ceb` and `c24a260d` the only change outside `docs/` is the top-level
`README.md`, so the binary built at `82523ceb` is the one `c24a260d` ships.

The website's resolved manual commit is separate from these implementation-evidence refs.
The manual follows `main`; immutable source citations explain which behavior was reviewed.

## Source map

Paths are repository-relative at the v0.3.0 baseline. Recheck them before changing a claim; a
later parser or implementation may invalidate both an example and its troubleshooting advice.

| Chapter / claim | Evidence |
|---|---|
| install: target, record, digest, signature, destination, `update --check`/`--rollback` | `install.sh`; `crates/vox-tui/src/update.rs`; `vox update --help` |
| install: profiles move to `nodes/<name>/`; pre-v0.3.0 rooms refused | `crates/vox-core/src/node/layout.rs`; `crates/vox-tui/src/client.rs:81`; `crates/vox-core/src/node/api.rs:1196` |
| nodes, daemon, selection order, attach/detach | `docs/adr/ADR-026-daemon-and-nodes.md` (C-3, L-2, L-3, S-2); `crates/vox-tui/src/client.rs:319`; `crates/vox-core/src/node/daemonipc.rs:324`; `crates/vox-tui/src/daemon.rs:596` |
| first-room / rooms: create, invite, join, roster, post, read | `crates/vox-tui/src/cli.rs` (`RoomCmd`); `crates/vox-tui/src/room_cli.rs` |
| rooms: read row format, `  \| ` continuation, hidden characters | `crates/vox-tui/src/room_cli.rs:983-1022` (`plain_row`), `:889` (`row_json`) |
| rooms: retention, admin, end, idle end, leave | `crates/vox-tui/src/cli.rs` (`Retention`, `Admin`, `End`, `--idle-end`); `docs/adr/ADR-023-room-lifecycle.md` RL-2, RL-8; `crates/vox-core/src/node/api.rs:1131`, `:1178`, `:1184` |
| keyring: scope, rename, history, 30-minute window | `crates/vox-tui/src/cli.rs` (`TrustCmd`); `crates/vox-core/src/node/actor.rs:1967` (`KEYRING_WINDOW_SECS = 30 * 60`); `crates/vox-tui/src/ui.rs` (`trust_label`) |
| TUI commands | `crates/vox-tui/src/state.rs:716-780` (`parse_command`), `:323` (`t`), `crates/vox-tui/src/ui.rs` (hint bar) |
| services: named shares, addresses, `up`, `forward`, `tunnel close`, `lan up` | `crates/vox-tui/src/cli.rs`; `crates/vox-tui/src/tunnel_cli.rs`; `crates/vox-tui/src/lan_cli.rs:220`; `docs/adr/ADR-017-room-bound-services.md` §12 |
| services: anchor commands | `vox node --help`, `vox node create --help` (`--headless`): help only, not run |
| services / troubleshooting: no network-change detection in v0.3.0 | `docs/adr/ADR-012-nat-traversal-and-reachability.md` status and N-49–N-58 (v0.3.1) |
| files: send, share, get, verified staging, no resume | `crates/vox-tui/src/room_cli.rs`; `crates/vox-tui/src/share_cli.rs` |
| agents: `--node` required, plugin output, hook registration and implicit attach | `crates/vox-tui/src/cli.rs` (`AgentHookArgs`, `AgentPluginArgs`); `crates/vox-tui/src/agent_hook.rs:1137-1180` |
| agents: wakes per client, doctor, ping | `crates/vox-tui/src/wake.rs`; `crates/vox-tui/src/doctor.rs`; `crates/vox-tui/src/ping.rs` |
| agents: claim exit codes | `vox room claim --help`; `vox room post --help` (`--op`, exit 4) |
| reference: paths, data root layout, passphrase input, daemon passphrase-file lines | `crates/vox-core/src/node/paths.rs`; ADR-026 F-1; `crates/vox-tui/src/app.rs:870-1020` |

## v0.3.0 command check

Run on 2026-10-04 with the `vox 0.3.0` binary built at the v0.3.0 baseline (`cargo build
--release --bin vox`, no features). Every process had its own scratch `VOX_DATA_DIR` and
`VOX_CONFIG_DIR`. Two data roots, A and B, stood for two people on one macOS host, each with
its own background daemon. No personal, family or agent state was opened. Fingerprints, entry
hashes and room IDs below are from those scratch nodes; local paths, LAN and public addresses
are replaced by placeholders.

| Manual claim | Command | Observed |
|---|---|---|
| `--profile` is gone | `vox id --profile family` | `error: unexpected argument '--profile' found` (exit 2) |
| A node is made, then attached | `vox node create robertgpt --passphrase-file EMPTY` | `vox: no identity passphrase; going on without one. A passphrase is encouraged.` / `vox: created node robertgpt` / the 52-character fingerprint |
| | `vox node list` | `robertgpt detached` |
| | `vox room list` (before attach) | `vox: no vox daemon is running for this data root, so node robertgpt is not attached.` / `Start one:  vox daemon      (or vox node attach robertgpt)` (exit 1) |
| | `vox room list` (empty data root) | `vox: there is no node in DATA_ROOT yet; make one: vox node create <name>` (exit 1) |
| | `vox node attach robertgpt --passphrase-file EMPTY` | `vox: node robertgpt attached`; then `vox node list` → `robertgpt attached   FINGERPRINT`, `vox room list` → `no rooms` |
| `vox id` prints the fingerprint | `vox id` | the fingerprint alone on one line |
| Create | `vox room create --name family --passphrase-file ROOM_PASS` | `vox: created family` / `` `vox room list` shows its id; that id is what agents pass as --room `` ; list → `bmbkjywlgzar  family` |
| The room link goes to stdout | `vox room invite bmbkjywlgzar` | stdout: `vox://bmbkjywlgzar…?a=…&b=…&r=…`; stderr: how the link names this host, `send the passphrase by a different channel than this address`, `joining grants nothing — use vox trust add to decide who reads you` |
| Join | `vox room join 'ROOM_LINK' --name family --passphrase-file ROOM_PASS` (B) | `vox: joined family` / `you read a member once you trust it and it trusts you: vox trust add`; roster lists both fingerprints |
| Trust scope is stated | `vox trust add FINGERPRINT --name ann` | `trusting eldco374… as "ann"` / `it may now read what you write in every room you share — now and later` / `and you read what it writes, once it trusts you too` / `and reach every service you bind to a room you are both in` |
| Receipt both ways | A posts `hello from robertGPT`; B `room read`; B posts; A `room read` | B: `wezorchin… robertGPT hello from robertGPT`; A: `wezorchin… you hello from robertGPT` and `ea6ldny… ann hello back from ann` |
| `--to` reports reach | `vox room post ROOM --to ann "…"` | `vox: to ann: none of its sessions has announced itself in this room; you trust it; it trusts you` |
| Structured posts read as JSON | B `room read` after `--to` and `--re` posts | the whole envelope as text, e.g. `{"v":1,…,"type":"say",…,"body":"can you check the file?",…}` then `  (to you)` |
| Hidden characters | post `bidi U+202E evil U+202C and zero U+200B width` | `bidi \u{202e}evil\u{202c} and zero⟨U+200B⟩width`, then a `  \| ` line for the trailing newline |
| `--since` takes a full hash | `vox room read ROOM --since wezorchin` | `vox: --since takes a full 52-character entry hash, as vox room read prints it in the first column` (exit 1) |
| Ping | `vox room ping ROOM robertGPT --wait 5` (B) | `robertGPT's node answered: it holds no agent session` |
| Share into an existing room | `vox service add ROOM web 127.0.0.1:18080` | `vox: offering "web" at 127.0.0.1:18080 in room bmbkjywlgzar` / `it is dark until you vox trust add someone — and they join this room` |
| Addresses are the viewer's | `vox service list ROOM` on A, then on B | A: `web.FINGERPRINT.family.vox  by you` and `web  →  127.0.0.1:18080`; B: `web.robertgpt.family.vox  by robertgpt` (B's alias `robertGPT`, lower-cased) |
| Forward by address | `vox forward web.robertgpt.family.vox 127.0.0.1:18081` (B) | `vox: forwarding 127.0.0.1:18081 to web on web.robertgpt.family.vox (3nx7faqhb5hd)`; `curl http://127.0.0.1:18081/` returned the test page |
| `vox up` carries every room | `vox up --bind 127.0.0.1:18082` (B) | `vox up on 127.0.0.1:18082 — carrying every room this node holds`, the `Host *.vox` block with `ProxyCommand nc -X 5 -x 127.0.0.1:18082 %h %p` and the socat alternative, `ALL_PROXY=socks5h://127.0.0.1:18082`; `curl --socks5-hostname` to `web.robertgpt.family.vox` and to `web.robertGPT.family.vox` both returned the page |
| Status lists tunnels and paths | `vox status` (B) | member `trusted  connected`, peer `direct  rtt 0 ms`, `tunnels` → `forward 127.0.0.1:18081 to 3nx7faqhb5hd's web (room bmbkjywlgzar)` |
| Rename | `vox trust rename eldco374 annie` | `vox: eldco374g7wc is now "annie" — its services are reachable as <service>.annie.<room>.vox` |
| Remove cuts reach | `vox trust remove FINGERPRINT` (A), then curl through B's forward | `no longer trusting …` / `your sender key is rotated and everyone still trusted is re-keyed`; curl failed; the forward printed `tunnel refused or cut — the host refused "web" — it has not trusted this identity (vox trust add), or offers nothing there, or its service did not answer` |
| Retention always asks for the identity passphrase | `vox room retention ROOM 1w` with no terminal | `this needs the identity passphrase, and there is no terminal to ask at.` (exit 1) |
| Creator sets retention | `vox room retention ROOM 1w --identity-passphrase-file EMPTY` (A) | `bmbkjywlgzar keeps messages for 1 week` / `older messages are removed now, on every member as this reaches them` / `a modified node can keep everything: this is not a security property` |
| Admins | `vox room admin list/add/remove` | `… (creator)`; `eldco374g7wc is now an admin of bmbkjywlgzar`; B (admin) `retention … forever` → `keeps messages forever`; `… is no longer an admin` |
| A non-admin keeps less | `vox room retention ROOM 1h …` (B, not admin) | `set your own retention for bmbkjywlgzar: this node keeps its messages for 1 hour` / `the room's is forever, and only its creator or an admin changes that; nothing changed for anyone else` |
| End is refused to a non-admin | `vox room end ROOM` (B) | `cannot end: only the room's creator, or an admin it delegated, may do that — and this identity is neither` (exit 1) |
| End deletes everywhere | `vox room end ROOM` (A) | `ended bmbkjywlgzar for everyone`; B's `room list` → `no rooms` |
| Leave | `vox room leave 743wt` (B) | `left room "svc" (…)` / `its other members see that you left; this node no longer holds it` |
| Send and get | `vox room send ROOM ./report.txt` (A); `vox room get ROOM report.txt --dir ./incoming` twice; `--out` onto an existing file (B) | `offering report.txt (18 bytes) as file-4c694ad7…`, `collect it with: vox room get bmbkjywlgzar report.txt`; `./incoming/report.txt (18 bytes) verified`; `./incoming/report (1).txt (18 bytes) verified`; `./incoming/report.txt already exists; vox room get never overwrites a file …` (exit 1) |
| Share a folder | `vox share ROOM ./shared --count 1` (A); `vox room get ROOM shared.tar --dir ./incoming` (B) | `sharing shared.tar (4096 bytes)` with a curl line through `vox up`; `./incoming/shared.tar (4096 bytes) verified`; the share then printed `no longer sharing shared.tar (fetched 1 time(s))` and exited |
| A stopped offer | the same get again | `vox: reading the reply: Connection reset by peer (os error 54)` (exit 1) |
| Named shares only | `vox serve 18080` | `"18080" has no name: every shared service is named, and reached as <name>.<node>.<room>.vox` / `name it as <name>=<port>, e.g. vox serve ssh=22` (exit 1) |
| `serve` and `connect` | `vox serve web2=18080 --name svc` (A); `vox connect 'ROOM_LINK' --passphrase-file PASS --name svc` (B) | room, address, `passphrase …-…-…` with `^ send this by a different channel than the address`, `sharing 127.0.0.1:18080 as web2.FINGERPRINT.ROOM_ID.vox`, `who can reach it: the identities you have trusted, once they join`; B: `joined. vox service list 743wt6obkyej shows what is shared here`; `curl --socks5-hostname` to `web2.robertgpt.svc.vox` returned the page |
| `lan up` needs the helper | `vox lan up ROOM` | `no LAN helper is answering on /var/run/vox-lan.sock. … start it in another terminal with sudo vox lan helper` (exit 1); the helper was not run (no sudo) |
| `tunnel close` | `vox tunnel close --id 999` | `no live tunnel matches that — vox status lists them, with their numbers` (exit 1) |
| Agents need `--node` | `vox agent plugin claude`; `vox agent hook` | both `error: the following required arguments were not provided: --node <NODE>` (exit 2) |
| Plugin output | `vox agent plugin claude --node claude-mbp`; `codex`; `opencode` | Claude: hooks `vox agent hook --node claude-mbp` for SessionEnd, Stop, UserPromptSubmit and `"env": {"VOX_NODE": "claude-mbp"}`; Codex: `"async": false` and `pass --node claude-mbp to every vox the agent runs`; OpenCode: `const VOX_NODE = "claude-mbp"` |
| Doctor | `vox agent doctor`; `vox agent doctor --node claude-mbp --room ROOM` | `ok/warn` lines for node, room, each harness, drain, sessions, trust and versions; unattached node → `fail  node: node claude-mbp is not attached; attach it first: vox node attach claude-mbp`, `vox: 1 check failed` (exit 1) |
| Profiles become nodes | v0.2.10: `vox id --profile family --identity-passphrase-file PASS`; v0.3.0: `vox node list`, `vox id` | `vox: moved DATA_ROOT/family to DATA_ROOT/nodes/family (from v0.3.0 each node lives under nodes/)` / `family detached`; `vox id` printed the same fingerprint v0.2.10 printed |

The forward, the proxy, the shares and the test web server were stopped by their recorded
PIDs; both nodes were then detached with `vox node detach`, and each background daemon exited
by itself; no `vox` process remained.

Limits: two data roots on one host, so no NAT traversal, relaying, anchor or second machine;
no live agent harness (hooks were generated and the doctor run, but no session received a
message); `vox lan up` stopped at the missing helper; the closed-room recovery in the TUI, the
daemon passphrase-file room lines, the restart remedy after a network change and the 30-minute
keyring window were reviewed in source, not exercised; `NODE.ROOM.vox` reaching nothing rests on
ADR-017 §12 and its proof, not on this check.

## Product findings recorded during the check

These are behaviors of the binary, not manual errors. The manual describes them as they are:

- `vox room read` prints structured posts (addressed posts, replies, file offers, ping and pong)
  as the raw JSON envelope; agents' hooks show only the body.
- Hidden characters are escaped in two styles: `⟨U+XXXX⟩`, or `\u{…}` for line and direction
  controls.
- Fetching from a stopped offer reports a connection reset, not that the offer is gone
  (ADR-020 11.8).
- Help and messages still say "profile" in places: `vox id`, `vox node`, `vox service list` and
  `vox up` help, the doctor's `start this profile's node: vox daemon (or vox tui)` fix, and
  `this profile has no identity yet`. `vox up` help still shows the withdrawn two-part
  `ssh nas.family.vox`.
- The TUI join prompt labels its first field `invite link (vox://…)`; `vox status` prints
  `always-on member: unknown: not recorded until ADR-023`.
- `vox serve` states who can reach a service as a rule, not as a list of members (ADR-017 4.2).

## Retired heading fragments

The v0.3.0 rewrite keeps every fragment whose heading is still true. These v0.2.10 fragments
were retired because their headings would now be false; a published website needs a redirect or
compatible anchor for each (ADR-027 D1): `agents.md#give-the-agent-its-own-profile-and-room`,
`first-room.md#2-each-person-keeps-a-daemon-running`, `keyring.md#names-and-versions`,
`reference.md#select-the-same-profile`. The troubleshooting headings `No node is running for
this profile` and `Another Vox process is using this profile` are kept, with their v0.3.0
meaning, so existing links still land.

## Earlier verification (v0.2.10)

The independent verifier `manual_practice_research` checked the v0.2.10 edition with the
published v0.2.10 executable in two disposable roots on 2026-10-04: identity before the daemon,
an empty room list, create/invite/join/trust, receipt both ways, a wrong room passphrase's
refusal, and closed-room recovery in the TUI. That record applies to v0.2.10 only; the
[reader proof](research/manual-reader-proof-2026-10-04.md) holds it.

## Drift that the manual deliberately avoids

- Generated/shipped prose can overgeneralize urgent wakes; the actual implementation
  explicitly never interrupts Codex. The manual uses client-specific delivery.
- Older design discussions describe auto-held attachments, inline thumbnails, new service
  helpers and UI flows. The manual does not present those proposals as released behavior.
- The first command on a v0.2.10 data root moves its profiles. "Doctor is read-only" does not
  imply that common first-use path resolution never changes files.
- Network-change detection (ADR-012 N-49–N-58) is v0.3.1 work; the manual marks it as not in
  this release.

Maintain this map together with [manual authoring instructions](manual-authoring.md).
