# User manual evidence map

Updated: 2026-10-04. Scope: ADR-027 M27.1 / work item #421. This is maintainer evidence,
not a chapter in the public navigation manifest. Source inspection is not an execution test.

## Baselines

| Label | Exact source revision | Use |
|---|---|---|
| v0.3.1 | `bf6dfcdbee65e82a4683400baa94dd62fc8532d6` (built on macOS and on Linux) | Task chapters from v0.3.1 (#425), the v0.3.1 command check |
| v0.3.0 | `82523cebc870a29e0947b0cb7c20b4563d233966` (built); manual merged at `c24a260dee708a340df5544f80a4518823e261a8`; review fixes at `c142ddd3293bfd1273cfd5737a673bcceb93dfc9` and `vox room link` at `d01c2c767c9ae295d1ed9aabdf66b73838c8f266` (each built, rechecked) | Task chapters, troubleshooting, the v0.3.0 command check |
| Released v0.2.10 | `8d95a381f14d6bbb45f714d75f64e57d2f5dbf96` | History only: the earlier edition and the profile-to-node move check; the manual no longer describes it |
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
| first-room / rooms: create, room link, join, roster, post, read | `crates/vox-tui/src/cli.rs` (`RoomCmd`); `crates/vox-tui/src/room_cli.rs` |
| rooms: read row format, `  \| ` continuation, hidden characters | `crates/vox-tui/src/room_cli.rs` (`plain_row`, `row_json`); `crates/vox-text/src/lib.rs` |
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
| troubleshooting / services: network change noticed and said (v0.3.1) | `crates/vox-core/src/nat/netwatch.rs` (`summary`); `crates/vox-core/src/node/status.rs` (`network_changed`); `crates/vox-core/src/node/net.rs` (probe after a change); ADR-012 N-49–N-58 |
| reference: `gateway` in status, mapping renewal and deletion at stop (v0.3.1) | `crates/vox-tui/src/status_cli.rs` (gateway); `crates/vox-core/src/nat/portmap.rs` (method names); `crates/vox-core/src/node/presence.rs` (deletion at stop) |
| install: containers, root refusal, receive buffer (v0.3.1) | `crates/vox-core/src/error.rs` (`Root`); `crates/vox-core/src/transport/quic.rs` (`UDP_SOCKET_BUFFER`, `mtu_ceiling_for`, the buffer line) |
| reference: paths, data root layout, passphrase input, daemon passphrase-file lines | `crates/vox-core/src/node/paths.rs`; ADR-026 F-1; `crates/vox-tui/src/app.rs:870-1020` |

## v0.4.0 command check (integrate, in progress)

For #516 the chapters are being written as v0.4.0 stories merge. They were checked on 2026-10-05
against `integrate/v0.4.0` as it stood, in three steps: `0e27808d` (the keyring window, service
kinds, the room cap), `6e79b45d` (files, the daemon's proxy, one-step serve, no backup) and
`00914d2a` (canonical addresses, the share an agent is given). Each vox binary was `cargo build
--release --bin vox` with no features, and still says `vox 0.3.1`. Lines that need a test-only
knob (a room cap lowered to 3, a member that never answers) or a terminal (the TUI) come from the
merged proofs. Those were run in release with `--features test-knobs`, at the commit each row
names. A row's quote is replaced where a later step changed the output.
Every process had scratch `VOX_DATA_DIR` and `VOX_CONFIG_DIR`, and every process was stopped by its
recorded PID or `vox node detach`. No `sudo` was used. All of it is to be checked again against
the v0.4.0 candidate, which is to replace this commit in the Baselines table.

| Manual claim | Where and how | Observed |
|---|---|---|
| `vox status` shows the keyring window (#478) | macOS, a node attached with an empty passphrase file, then `vox status` | second line `keyring open 30m` |
| The window, closing | the release binary: a node attached at 17:05:29, then `vox status` at 17:34:32 and 17:36:32 | `keyring open 1m`, then `keyring asks for the passphrase` |
| The window, closed (knob) | `a_keyring_change_needs_a_recent_passphrase_proof` (test-knobs: a 1-minute window) | `vox status, open: Some("keyring open 1m"); past the window: Some("keyring asks for the passphrase")` |
| The TUI status bar shows it | `the_tui_says_what_attaching_its_node_said_proof` (pty, pyte) | the status bar: `sync: idle — no peer connected · node default · attached: default · keyring open 30m` |
| `vox serve` prints each share's kind (#489) | `vox serve ssh=P1 web=P2 plain=P3 --name svc` (an SSH-banner stand-in, an HTTP stand-in, a TCP echo), at `0e27808d` | `sharing 127.0.0.1:P1 as ssh.FINGERPRINT.ROOM_ID.vox (ssh)`, `… web… (http)`, `… plain… (tcp)`; at `00914d2a` the line names the share and its canonical address (next rows) |
| `https` and `dns/udp` | `vox serve site=P4 names=P5/udp` (a TLS server with a throwaway self-signed certificate; a UDP responder answering any query with its id and the QR bit) | `… site… (https)`, `… names… (dns/udp)`; `service list`: `names.FINGERPRINT.svc.vox  by you  dns/udp`, `site.FINGERPRINT.svc.vox  by you  https` |
| A plain UDP service | `vox serve media=P7/udp` (a UDP echo) | `… media… (udp)`; `service list`: `media.FINGERPRINT.svc.vox  by you  udp` |
| The kind never comes from the name | `vox serve ssh=P6` (a TCP echo) | `… ssh.FINGERPRINT.ROOM_ID.vox (tcp)` |
| `service list` shows the kind, on host and guest | A: `vox service list ROOM_ID`; B after `vox connect` and trust both ways | A: `ssh.FINGERPRINT.svc.vox  by you  ssh` with `services offered` `ssh  →  127.0.0.1:P1`; B: `ssh.robertgpt.svc.vox  by robertgpt  ssh`, `web.robertgpt.svc.vox  by robertgpt  http`, `plain.robertgpt.svc.vox  by robertgpt  tcp` |
| `service add` is detected too | `vox service add ROOM_ID pages 127.0.0.1:P2` | `vox: offering "pages" at 127.0.0.1:P2 in room ROOM_ID` / `it is dark until you vox trust add someone — and they join this room`; then `pages.FINGERPRINT.svc.vox  by you  http` in `service list` |
| Refusals at the cap (#366) | `a_join_to_a_full_room_is_refused_proof`, cap 3 | `vox: cannot join: the room is full, so you were not admitted` / `your passphrase was accepted; the room takes no more members`; `vox: cannot join: another newcomer took the room's last place at the same moment, so you were not admitted` / `your passphrase was accepted; try again`; `vox: cannot join: a member of the room did not agree to take you in, so you were not admitted` with `said: …: exchange: member bob did not answer within 5s, and every member online must agree before the room takes a newcomer` |
| `vox serve` names the share and its canonical address (#487) | `vox serve web=P --name family`, at `00914d2a` | `sharing 127.0.0.1:P as web — SERVICE_ID.FINGERPRINT.ROOM_ID.vox (http)` |
| `service list` shows both addresses | A, then B after `vox connect` and trust both ways | A: `web.FINGERPRINT.family.vox  by you  http` with the canonical address on the next line; B: `web.robertgpt.family.vox  by robertgpt  http`, and the same canonical address |
| Both forms reach the service | B: `curl --socks5-hostname PROXY` to the readable and to the canonical address | both returned the HTTP stand-in's `hello` |
| An unknown readable part is refused | B: `vox forward web.nobody.family.vox 127.0.0.1:0` | `vox: web.nobody.family.vox: no node you trust is called nobody — only trusted nodes have names here (vox trust add <fingerprint> --name nobody)` (exit 1) |
| The proxy runs in the daemon (#492) | B: `vox up`, with the daemon given `VOX_PROXY=127.0.0.1:0` (every agent on this box shares port 1080) | `vox up on 127.0.0.1:PORT — the vox daemon's proxy, carrying every room its attached nodes hold`, the `Host *.vox` block, `ALL_PROXY=socks5h://127.0.0.1:PORT`, `it runs while a node is attached; vox up --watch shows what it refuses or cuts`; exit 0 |
| A taken proxy port is said | a proof's guest `vox up` while another daemon held 1080 | `the .vox proxy is not running: the .vox proxy could not listen on 127.0.0.1:1080: Address already in use (os error 48). Free the port, or set --proxy or VOX_PROXY to another` |
| No backup (#477) | `vox node create robertgpt --passphrase-file EMPTY`, at `6e79b45d` | stderr: `vox: there is no backup of a node: if this machine is lost, so is this node; make a new one, and ask everyone who trusts this one to untrust it and trust the new one` |
| A share is one message, served by the daemon (#493, #494) | A: `vox share ROOM_ID ./report.txt -m "the report"`, three nodes A, B, C, each trusting A and A trusting both | the five `vox: sharing report.txt (22 bytes) as file-…` lines as quoted; exit 0 at once; B `room read`: `… robertGPT file offered: report.txt (22 bytes): the report` |
| Pulled by itself, into files/ROOM_ID (#495) | B and C after A's share | 1.0 s later `B/nodes/ann/files/FULL_ROOM_ID/report.txt` and the same on C |
| Addressed to another member | A: `vox share ROOM_ID ./notes.txt --to carol` | `for carol` in the share's lines; C pulled it, B did not; B `room read`: `file offered: notes.txt (15 bytes)` then `(to d5ruqwtsknsv4wlybmjzn5dq2o)` (B has not named carol) |
| Pull by hand, default place and a taken name | B: `vox room get ROOM_ID notes.txt`, twice; then with `--dir` | `vox: DATA_ROOT/nodes/ann/files/FULL_ROOM_ID/notes.txt (15 bytes) matches its announced SHA-256`; the second `notes (1).txt`; `--dir`: `…/incoming/notes.txt (15 bytes) matches its announced SHA-256` |
| A folder | A: `vox share ROOM_ID ./photos` | `vox: sharing photos.tar (2560 bytes) as file-…` |
| List and stop | A: `vox share list`, `vox share stop ROOM_ID report.txt`; C: `vox room get … report.txt` | `file-…  photos.tar (2560 bytes)  fetched 0 time(s)` …; `vox: no longer sharing report.txt (file-ff174003a0a82197-58af8b08440c4061; fetched 2 time(s))`; C: `vox: the offer of report.txt is gone: robertGPT no longer serves it. …` (exit 1) |
| One-step serve (#491) | `vox serve --name svc`, typed: the stand-in's port, Enter, `n`; then the port, `web`, `y` | the list header, the stand-in's row `python3.13           127.0.0.1:P  tcp` (the machine's other listeners are not recorded), the note about other users' services, `name it [http]`, `members will reach it as web.FINGERPRINT.<the new room>.vox`, `who can reach it: nobody yet: you trust no node (vox trust add)`, `who cannot: anyone else who joins with the room link and passphrase`, `share it? [y/N]`; `n` → `vox: not shared` (exit 1); `y` → the room and `sharing … (http)`. With trusted nodes (check of `6e79b45d`): `who can reach it: each node you trust, once it joins the room: carol, ann` |
| Warnings before sharing | `vox serve pages=P` (a stand-in on 0.0.0.0); `vox serve db=5432` | `vox: warning: pages (python3.13           0.0.0.0:P  tcp  (every interface)) listens on every interface of this machine, so its networks reach it without Vox; sharing it does not change that`; `vox: warning: db is on port 5432, PostgreSQL's: every node you trust in the room can reach it` |
| An agent is given the note and the path (#497) | A: `vox share ROOM_ID ./notes.txt --to ann -m "read this before the call"`; B: `vox agent hook --node ann --room ROOM_ID --format text --session ann-agent`, at `00914d2a` | `[hfnbgudh from robertGPT to you] file offered: notes.txt (9 bytes): read this before the call` / `  ↳ pulled to DATA_ROOT/nodes/ann/files/FULL_ROOM_ID/notes.txt` |
| The decision record (#506) | at `2de3cfae`: B joins A's room with a wrong passphrase, then the right one; A `trust add` then `trust remove` B; A shares a file and `share stop`s it; then A's `nodes/robertgpt/decisions/` | directory `0700`, one file `2026-10-06.jsonl` (the UTC day; local time was 2026-10-05) `0600`, four lines: `refused` `to join a room` `answering kdbctelrwq73: join proof-of-possession failed`; `trusted` (alias `ann`); `untrusted` with `this node's person removed them from the keyring: they read nothing new from it and reach none of its services`; `stopped` `to stop sharing a service` naming the share's tag, not its file name. The 14-day pruning and the hourly folding are from source (`KEEP_DAYS`, `record_folded` in `crates/vox-core/src/node/decisions.rs`) |
| Trust glyphs, the card and the keyring view (#509, #472) | `the_tui_shows_the_room_truthfully_proof` and `tui_member_names_proof` on #509's branch rebased on `7a1761b5` (the TUI code merged at `bc43024f`) | `look`: `⇄ alice` and `→ dave` bold in text.primary, `· <carol's fingerprint>` plain in text.secondary; `consent`: `in keyring · reads you`, `not in keyring · you don't read each other`; `depths`: `<> alice`, `-> dave`, `. ` under `NO_COLOR` and `LC_ALL=C`; the card under the selected Alice (five art rows beside `m4ol surt bsra fsq2 djll`…); `k` → `Keyring (Esc: back)` listing alice and erin with their cards |
| The sidebar (#511, #484) | the truth proof's `regions` and `unreach` claims, same run | `node default · attached`, `needs you (1)`, `▶ m (to you 1 · 3 new)  [● online]`, `nodes on this machine`, `default  attached`, `spare  detached`; later `[○ offline]` |
| Each change of access says its effect before and after (#471) | at `a14f4d14`, two data roots: `trust add`, `service add`, `service remove`, `share`, `share stop`, `room retention`, `room leave` (B), `trust remove`, `room end` | the `vox: about to …` line and its follow-on lines before each result, as quoted in keyring.md, rooms.md, services.md and files.md; e.g. `vox: about to leave room "family" (ROOM_ID): its other members are to see that you left, and this node is to delete it with everything it holds of it`; `vox: about to end "family" for everyone: every member's node is to take no new message in it and delete it`. The untrust lines with a live session and an offered service are from RP-10 (`tunnel_honesty_proof`) at the #471 merge: `and to reach none of your services from now on: it loses 59905 in "service"`, `cut: tunnel 1: the guest reaching your 59905`, `your sessions into its services are untouched: tunnel 0: you reaching the guest's notes`. The TUI's `:leave` and `:end` confirmations are from `a_room_can_be_left_and_ended_proof` |
| Pulled by (#498) | A shares; B pulls by itself; A `vox room read` | `… you file offered: report.txt (8 bytes)` then `  pulled by ann` |
| `vox connect`'s last line, `vox up --watch`'s refusal (help-words) | at `fc4cfc42` (merged as `5bb3208d`) | `reach a service as <service>.<node>.<room>.vox through the daemon's proxy, running while a node is attached (vox up says where)`; `a CONNECT to a bare address: the .vox proxy carries .vox names only` |
| @alias and lookalike aliases (#474) | `an_addressee_is_shown_by_the_readers_own_name_proof` at the #474 branch rebased on `056d2102` | members pane `→ Alice#lhk6xo` / `⇄ alice#6tvrsb`; timeline `alice#6tvrsb to Alice#lhk6xo: …`; bob's `@alice …` carried alice's whole fingerprint in `to` |
| Replies, the join line (#485, #476) | the truth proof at #475's branch on `a14f4d14` | `quote`: the row above Bob's reply `┆ alice: q-mid the lexer first`; `jump`: Enter moved the selection from `▶ you: q-answer on it` to `▶ alice: q-mid the lexer first`; `newcomer`: `<frank> (not in keyring) joined. No one you trust trusts it yet.`, then `… joined. alice trusts it.` |
| Who reads whom after a join (#481); recent refusals (#507) | at `ea2f1e6f`, three roots: B joins, C joins with a wrong passphrase, A `vox status` | B: `who reads whom:` / `· y2vem5l7ay2tsmkw7xcnkk3aw2 — not in keyring: to read each other, you run vox trust add … --name NAME; if they have not trusted you, they run vox trust add …`; A: `recent refusals` / `4s ago  refused 34rtzgeq333h to join a room: answering 34rtzgeq333h: join proof-of-possession failed`, and the node's card at the top |
| Per-kind commands (#490) | B: `vox service list` for A's `ssh` | the `ssh`, `forward`, `then` and four `needs … : yes` lines and the `~/.ssh/config` block as quoted (the proxy's port was `VOX_PROXY`'s free one; the manual shows 1080) |
| Folders (#499) | A shares `docs/` (5 files), changes one, shares again; B | `sharing docs/ (5 files, 3500 bytes)`, `… (of its file list)`; B's files dir held `docs/f0.txt`…`f4.txt`; after the second share only `docs/f2.txt` changed on B; `vox room get ROOM docs --dir …` → `…/docs/ (5 files: 5 fetched, 0 already here) matches its announced SHA-256s`. Resuming a cut-off pull is from #499's own proof and source, not run here |
| Image preview (#500) | A shares a 64×48 PNG; B `vox room read --json` | `data.image` with `blurhash`, `width`, `height`, `thumb` (base64 JPEG) |
| Link cards (#501) | A posts a loopback URL, then `https://example.com/`; B reads | loopback: no card, the local server counted 0 requests; example.com: `data.card` `{"title":"Example Domain","url":"https://example.com/"}`, and `vox room read` showed `↳ link: Example Domain` |
| One node per TUI (#470), trust words (#473), retention in the TUI (#483), the Shared pane (#490), `:serve` (#491), inline images (#502), the trust prompt (#475) | `the_tui_shows_the_room_truthfully_proof` at `ea2f1e6f`, 32 of 32 | `onenode`: `this window acts only as node default; to act as spare, open vox tui --node spare`; `consent`: `trusted both ways`, `waiting for the other side`, `not in keyring: trust to read each other`; `retention`: header `Timeline · ⏱ 1 week`, `alice set the room's retention to 1 week: messages older than 1 week are removed from now on`; `copies`: OSC 52 carried `ssh $USER@<canonical>`; `serve`: the preview as quoted; `inline`: drawn only once pulled and verified; `trust`: as quoted in keyring.md |
| Every node has a passphrase (#522), at `21b851ad` | `vox node create alice` at a terminal (a pty), Enter alone twice; then twice a passphrase; `vox node create bob --passphrase-file PATH` | `vox node: every node has an identity passphrase, and an empty one is refused; nothing was created` (exit 1); then `vox: created node alice`, the fingerprint and `there is no backup of a node: …` |
| Attaching opens no keyring window (#523), at `21b851ad` | `vox node attach alice` (pty, the passphrase typed), then `vox status --node alice` | `vox: node alice attached`; status second line `keyring asks for the passphrase` |
| A keyring change is typed only (#524), at `21b851ad` | `vox trust add FP --name bob --node alice` with no terminal; the same with `VOX_IDENTITY_PASSPHRASE` set; with `--identity-passphrase-file PATH` | first two: `vox: changing who you trust needs your identity passphrase: it was not entered for a keyring change in the last 30 minutes` / `it is typed at a terminal, and taken from nothing else (not VOX_IDENTITY_PASSPHRASE, not a file). Run it in a terminal: vox trust add FP --name bob --node alice`, exit 1; third: `vox: --identity-passphrase-file is refused: a keyring change's passphrase is typed at a terminal, never read from a file (ADR-028 K-13)` |
| The typed change opens the window, at `21b851ad` | the same `vox trust add` at a pty, the passphrase typed at `identity passphrase:`; then `vox status` | `vox: trusting FP as "bob": read` and its four lines; status `keyring open 30m` |
| In a shared room, at `21b851ad` | robertgpt creates `family`, ann joins (one daemon, two nodes); robertgpt `vox trust add ANN --name ann` at a pty; `vox trust remove ANN` | `about to trust … as "ann"` / `it is to read what you write in "family", and in any room you share with it later` / …, then `trusting … as "ann": read` / `it may now read what you write in "family" — now and later` / … / `` `vox trust remove` undoes it and changes the lock everywhere ``; remove: `it is to read nothing you write from now on in "family"; what it already read stays read`, `cut: none was open`, `your sessions into its services are untouched` |
| Read or read + drive (#525), at `21b851ad` | `vox trust list`; `vox trust drive FP`; `vox trust list`; `vox trust read FP`; `vox trust add --help` | `FP  bob  read`; `vox: FP26 now has read + drive`; `FP  bob  read + drive`; `vox: FP26 now has read`; `--drive  Grant read + drive: it may also drive this node's Sessions` |
| Rename and remove, at `21b851ad` | `vox trust rename FP builder`; `vox trust remove FP`; `vox trust list` | `vox: FP12 is now "builder" — its services are reachable as <service>.builder.<room>.vox`; `no longer trusting …`, `your sender key is rotated and everyone still trusted is re-keyed`; `no trusted identities` |
| A hook never attaches its node (#524), at `21b851ad` | `vox agent hook --node bob --format text` with bob detached | `Vox could not read your rooms this turn: node bob is not attached, and a hook never attaches it. Ask the operator to run, in a terminal outside this session: vox node attach bob`; `vox node list`: `bob detached` |
| The member pane's capability line (#525) | a TUI screen (`tui_close_room.py`) from `a_member_removed_while_its_room_was_closed_proof` in release, test-knobs, on integrate `1186a577` plus `b7187621` (#560's key-history fix, which does not touch the TUI) | the Members pane: `⇄ alice`, then `trusted both ways`, then `read` |
| `vox setup` (#552 and its follow-ups) | `an_agents_wiring_acts_only_as_its_node_proof::setup_makes_a_node_for_each_installed_harness` and `setup_keeps_codex_app_server_running`, release, at `21b851ad` | the listing, the per-harness `… is to get a node of its own …` block, `Create claude-mac and wire Claude Code to it? [Y/n]`, `created node`, `installed the hook/skill`, `no node for you`, the card and `alias claude-mac · harness Claude Code · host mac · macOS 27.2 · vox 0.3.1`, and `next, run vox agent trust codex: Codex runs a hook only once it is trusted`. Paths in the manual are written as `~/…`; the proof's were under its scratch HOME |
| The room map and `vox agent room` (#550, #551) | `agent_hook_proof::a_session_works_in_the_room_its_start_directory_is_mapped_to`, at `21b851ad` | `Vox: this session works in no room: no entry in the room map is the directory it started in. vox agent room <room> sets one.`; `vox: about to set the room session 22222222 of node default works in: room qilvehgxilrf, where its Session is to open` / `vox: session 22222222 now works in room qilvehgxilrf`; the save offer and its warning; the move: `… now works in room eluecghv5j6o; its Session in room qilvehgxilrf ended`. The map's exact match and the 0600 refusal are from `room_map.rs` |
| `vox room sessions`, a Session sealed to drive, `vox agent send`, `--file` (#543, #546, #538) | `a_session_is_sealed_to_drive_proof`, at `21b851ad` | `--json` rows with `label` `alice · 3f0c25bf` and `can_drive` true for bob, false for carol; carol: `Only members alice trusts with drive see inside this Session.`; `vox agent send`'s two lines as quoted; bob's `--file`: `alice · 3f0c25bf: accepted, pulling 90000 bytes`; carol's: `vox: not delivered to alice · 3f0c25bf: default does not trust you with drive; it trusts you to read only, or not at all`. The plain `open   LABEL` / `ended:` listing is from `room_cli.rs` |
| Reading a Session; answering from either side (#540, #545) | `a_claude_session_is_mirrored_and_answered_from_either_side_proof` (a stand-in speaking Claude Code's hook JSON), at `21b851ad` | the Session's seven lines as quoted; Details of a 220000-byte output whole; `--approve`: `handed to the session; it decides`; a second answer after the terminal's: `already answered at the terminal`; the tmux deliveries and the refusals quoted (pane no longer running, no Session named) |
| Driving Codex and OpenCode (#541, #542, #544) | `a_codex_and_an_opencode_session_are_mirrored_and_driven_proof` (an app-server stand-in, and the shipped OpenCode plugin under node), at `21b851ad` | `--say`: `typed; it starts the session's next turn`; `/clear` refused (the refusal then still named an ADR, removed on `v040/no-adr-in-help`); a read-only member refused; OpenCode `--interrupt`: `the running turn was stopped` |
| A live Claude Code session followed, approved and interrupted | the optional live proof's recorded run, `scratchpad/harness-runs/live-claude-2.log` (harness's lane, sandboxed) | `--approve …: handed to the session; it decides` with Claude Code's own prompt on its screen too; `--interrupt: delivered to its terminal` |
| Sessions in the TUI (#553) | `the_tui_shows_the_room_truthfully_proof` at `21b851ad`, 43 of 43 | `sessions`: `▸ General`, `All`, `● alice · 3f0c25bf`, `Ended (1)`; `approve`: `! alice · 3f0c25bf · waiting on you`, `family (waiting 1)`, `a` → `handed to the session; it decides`; `steer`: say, slash, `:interrupt`, `:stop` each `delivered to its terminal`; `share`: `accepted, pulling 44 bytes`; without drive: no composer |
| Addressing one session (#547, #548) | source (`room_cli.rs` `addressees`) and `an_urgent_message_wakes_each_harness_within_seconds_proof` as merged; not run for this check | `--to MEMBER/SESSION` carried as `<fingerprint>/<session id>`; an ended session refused, nothing posted |
| Readable addresses part by part (#488) | at `21b851ad`, three roots: A shares `web`, B trusts A as robertGPT, C has no name for A; each `vox service list`; A posts its canonical address, B reads | A: `web.g5xawb52urpd.family.vox  by you  tcp`; B: `web.robertgpt.family.vox  by robertgpt  tcp`; C: `web.g5xawb52urpd.family.vox  by g5xawb52urpd…(whole)  tcp`; B's `vox room read`: `robertGPT open web.robertgpt.family.vox please`. The whole fingerprint for an ambiguous part is from `a_service_is_reached_only_by_its_address_proof` (15) and `resolver.rs`, not run here |
| Smaller fixes at `21b851ad`: the post limit, a daemon taking over, `vox tui` ending with its terminal, `connect`'s stdin | the post limit's words from `room_cli`/`node` source and the large-room proof's arm as merged (`d1e1d6ab`); the takeover from `the_daemon_and_its_nodes_proof` as merged (`007b0100`); the TUI from the truth proof at `21b851ad`, `gone`: `its pty closed: exited within 5 s, status 0`, `signals`: `SIGHUP: exit 0`, `SIGTERM: exit 0`; `connect --help` read from the release binary | as quoted; the post-limit sentence and the takeover were not run for this check |
| Read by, where, notifications (#482, #486, #504, #505) | `the_tui_shows_the_room_truthfully_proof`, run on #509's branch rebased on `7a1761b5` | `readby`: under Bob's post, `on 3 of 3 members' nodes`, then `read by alice` after her agent drained it; `where`: `only on this machine`, then `on 1 of 3 members' nodes`; `notify`: one notification `Vox: m` / `new messages from alice` for three messages; `shown`: `vox room read --json` gives the drawn message `read_by` `['bob']` |
| A split room passes its cap and says so | the same proof's split case, cap 3 | `the split healed: both list all 4, one past the cap of 3, and it is said`. A daemon's log carried `past its cap of 3, now 4 members: another member admitted it`; the manual gives the 1,024 cap's numbers (`MAX_AUTHORS` in `crates/vox-core/src/node/channel.rs`) |

From source, not run: expiry deleting pulled copies and ending the serving (`crates/vox-core/src/node/pulls.rs`, #496); an automatic pull's retries (`RETRY_MIN`, `RETRY_MAX`); the agent's "not pulled yet" line (`crates/vox-tui/src/agent_hook.rs`); `notify-command` in a node's `config/config` and the OSC 9 or bell route (`crates/vox-tui/src/notify.rs`); the cap of 1,024 (`MAX_AUTHORS`); the program-name fallback (`lsof` on
macOS, `ss` on Linux, `kind_of_command` in `crates/vox-core/src/node/probe.rs`); up to three probe
connections to a TCP service (`probe_tcp`). The split case was red once in this check: bob refused
y as full because x, whose daemon was still running, had reached bob directly. That run's red was
reported to the lead as staging rather than product, and a second run was green.
| A Session keeps what its session did while its room was joining | `agent_hook_proof::a_session_works_in_the_room_its_start_directory_is_mapped_to`, release, `--ignored`, at `48b1c743` (2026-10-07) | passed in 70.9 s: the first prompt, typed before the node was a member, is read in the Session once the room opens; the dropped-entries sentence is quoted from `host.rs` (b2f4bd42), not run (it needs over 4 MiB held) |
| `--to member/session` on `vox share` | `vox share --help` at `48b1c743` (f60207c0) | `Or address one session of a member as <member>/<session>, the session named as vox room sessions names it` … `For example: --to bob/gso-cap` |
| Pass at integrate `a51335ff` (2026-10-07) | release `vox` at `a51335ff`, scratch root; source of the merges since `f5e687b7` | `vox room retention`: `vox: "family" keeps messages for 1 week` (the room by its name); `--notices` help names no design document; the decision record is sealed (`74152319`): `nodes/NAME/decisions/YYYY-MM-DD.sealed`, read through the node, so reference.md no longer shows a JSON line or a `grep`; the TUI's Session header `LABEL — name and id as ALIAS says` (`4fd4efbc`); `:answer` splits on `;` (`9dc92a5e`) |

### The app chapter (`v040/app-stack` 6e909d10, then integrate fa559fd8 and f5e687b7)

[The Vox app on a Mac](manual/app.md) was written on 2026-10-07 against app2's candidate
`v040/app-stack` at `6e909d10`, before it merged. No Vox.app was launched and no login item was
registered: its words come from the app's Swift source at that commit and from
`scripts/app-screenshots.sh`, which renders the app's own views offscreen from a demo data root it
makes (scratch `VOX_DATA_DIR` and `VOX_CONFIG_DIR`, its daemon stopped by PID). The renders show
the look; they are not product proof. The two checkers on #437 ran the daemon side of attach and
quit with the release `vox`. Sessions in the app (#554) and the Finder Share menu and Services item
(#449, `v040/share-extension`) are not in this candidate, and the chapter says so.

| Manual claim | Where and how | Observed |
|---|---|---|
| The timeline title | screenshot render, room `family` with `vox room retention … 1w` | `Timeline · ⏱ 1 week` |
| What was done to the room, among the messages | same render | `you named the room family`; `you set the room's retention to 1 week: messages older than 1 week are removed from now on` |
| Sidebar groups, nodes on this Mac, status bar | same render | `node ann, attached`; `NEEDS YOU (0)`, `ACTIVE (0)`, `QUIET (1)`; `ann attached` …; `node ann  3 peers  keyring open 30m` |
| File cards, link card, members | same render | `shopping-list.txt  41 bytes · sha256 435e42cc…` with `Quick Look` and `Show in Finder`; the image's preview; `Leek and potato soup` / `Forty minutes, one pot, serves six.`; `⇄ builder`, `⇄ ben` |
| The keyring view | render `keyring.png` | `ADD A NODE`, `Fingerprint (paste or type)`, `Alias`, `Trust`; rows `⇄ builder` with art, grouped fingerprint, `Rename…`, `Compare…`, `Remove…` |
| The decision record | render `decision-record.png` | `refused  to join a room · qvpip3tkrhoo (not in keyring)` / `answering qvpip3tkrhoo: join proof-of-possession failed`; `trusted  to trust a member · ben`; filters `every node`, `every room`; `kept 14 days and never sent anywhere` |
| A wrong passphrase is the daemon's sentence | the demo build's `vox`, scratch root: `vox node attach mac --passphrase-file BAD` | `vox node: that passphrase does not open node mac's identity` (exit 1); the app shows the sentence without `vox node: ` (`AppModel.sentence`) |
| Quit lets go; a holder keeps it | checkers appG and appK on #437, release `vox`: a holding client, then SIGTERM | `default attached … (held)`, then `default detached` |
| First run, Keep Running, Keychain, menu bar, notifications, keys, services view, accessibility | source at 6e909d10: `RootView.swift`, `AppModel.swift`, `Daemon.swift`, `MenuBar.swift`, `Notify.swift`, `Commands.swift`, `Services.swift`, `Keyring.swift`, `Theme.swift`; `crates/vox-tui/src/keychain.rs` | quoted strings as in the source; not run |
| Install, update and the daemon restart | source at `fa559fd8`: `install.sh`, `crates/vox-tui/src/update/bundle.rs`, `update/restart.rs` (#451–#453); not run, since an install or update replaces the real `/Applications/Vox.app` and restarts the account's daemon | quoted strings as in the source |
| Share menu and Services item | source at `fa559fd8`: `apps/macos/ShareExtension/ShareViewController.swift`, `Bundle/Vox-Info.plist` (#449) | `Share to a Vox room`, `To (none: the whole room)`, `Open Vox to attach node NAME first.`, `Shared NAME (SHA-256 …)`; Services item `Share to Vox Room` |
| `vox room read --json --notices` | release `vox` at `fa559fd8`, one scratch node: a post, then `vox room retention … 1w`; `--json`, `--json --notices`, `--notices` alone | `--json`: one `vox.room.row/1`; with `--notices`: `named the room family`, the row, then `set the room's retention to 1 week: …`, each `vox.room.notice/1` with `"by":"you"` and `created_millis`; alone: `error: the following required arguments were not provided: --json` (exit 2) |
| The link card and To: are drawn as written (fixed after the renders) | source at `fa559fd8` (`f05125f3`): `.caption()` replaces `.eyebrow()`, `To:` `.fixedSize()` | not rendered again |
| Sessions in the app | source at `f5e687b7` (`dac8a703`): `Sessions.swift`, `SessionDrive.swift`, `Timeline.swift`; not run (no Vox.app is launched for the manual) | `SESSIONS`, `General`, `All`, `! LABEL · waiting on you`, `Ended (N)`; `Timeline — LABEL · open · ⏱ …`; `Only members NODE trusts with drive see inside this Session.`; `Composer — to LABEL`, `Interrupt`, `Stop`, `Approve`, `Reject`, `Send answers`; `no answer from LABEL: it may or may not have been delivered` |

### Trust offers (`v040/trust-offers` c429f9be, `v040/agent-offers` dfbbf9ae, not merged)

The branches now stand at `acc4032e` and `024e2705`. Their user words differ from `dfbbf9ae` only in
the agent's turn, which now reads `Vox offers your node these nodes to trust`; the manual quotes that
(from the source at `024e2705`, not run).

Written on 2026-10-07 against `dfbbf9ae`, which holds both, before either merged; to be checked
again when they do. `cargo build --release --bin vox` with no features; one daemon in a scratch
data root with nodes `ann` and `ben` (both with an identity passphrase), room `family`, every
process stopped by PID.

| Manual claim | Where and how | Observed |
|---|---|---|
| A newcomer is offered | `ben` joins `ann`'s room; `vox trust offers --node ann` | the card, then `xgfmgktt6c64dkgehy7nvxg3if (not in keyring) joined. No one you trust trusts it yet.`, `in "family"`, `accept: vox trust add … --name <name> [--drive]   dismiss: vox trust dismiss xgfmgktt6c64` |
| The one who was there first is not | `vox trust offers --node ben` | `no offers: every node you share a room with is in your keyring, or was dismissed` |
| Dismiss | `vox trust dismiss --node ann xgfmgk`; a prefix matching no offer | `vox: about to dismiss the offer of xgfmgktt6c64dkgehy7nvxg3if: on this node alone; …`, `vox: dismissed the offer of …; if it leaves and joins again, it is offered again`; `vox: no offer matches "zzzzzz"; vox trust offers lists them` (exit 1) |
| Leave and join again: offered again | `vox room leave` and `vox room join` as `ben` | `ann`'s offers list `ben` again, `joined` |
| Accept, and the offer back | `vox trust add --node ann FP --name ben`, the passphrase typed at a terminal; then `vox trust offers --node ben` | `vox: trusting xgfmgktt6c64dkgehy7nvxg3if as "ben": read`; `ann`'s offers empty; `ben`'s: `2o5a45ggy2i5ndadhow4xl776d (not in keyring) trusts you. No one you trust trusts it yet.` |
| An agent's node is offered in its turn | `agent_hook_proof::an_offer_for_the_agents_node_is_shown_in_its_turn_and_only_the_operator_accepts_it`, release, `--ignored`, at `dfbbf9ae` | passed in 10.5 s; turn 1 carried `Vox offers your node these nodes to trust (…)` and the `accept: … --node default` line quoted |
| The TUI's offer rows, card and accept prompt | `the_tui_shows_the_room_truthfully_proof`, release, `--features vox-tui/test-knobs`, `--ignored`, at `dfbbf9ae` (a first run built without `test-knobs` stopped as APPARATUS, precondition unmet) | passed in 455.6 s; sidebar `needs you (2)`, `offer: kt3y l5vl… joined`, `offer: zvfn 6q7d… trusts you`; claims `offer`, `reoffer`, `offerback` and `accept` ok, the accept asking a name and read or read + drive and no fingerprint to compare |

## v0.3.1 command check

Run on 2026-10-05 for #425 with `vox 0.3.1` built at `bf6dfcdb` (`cargo build --release --bin
vox`, no features): on macOS, and on Linux (built on io.loveathome.us, x86_64, and run there and on
a second Linux host). Every process had scratch `VOX_DATA_DIR` and `VOX_CONFIG_DIR`; no personal
state was opened; no `sudo`. Addresses below are scratch or placeholders.

| Manual claim | Where and how | Observed |
|---|---|---|
| The first room, room link, trust, receipt both ways, a service by address, end (unchanged commands still hold) | macOS, two data roots | `vox: node robertgpt attached`; `no rooms`; `vox: created family`; `room link` → the `vox://…` link and `send the passphrase another way than this address (in person, a call, a different app)`; `vox: joined family`; the trust sentences as quoted; B read `… robertGPT hello from robertGPT`, A read `… ann hello back from ann`; `web.robertgpt.family.vox  by robertgpt`; `forwarding 127.0.0.1:18098 to web on web.robertgpt.family.vox`, curl returned the page; `ended … for everyone`, B `no rooms` |
| `vox status` gateway section | macOS, behind a home router | `gateway` / `ipv4  next hop 192.168.1.1 via en0` / `asked 192.168.1.1:5351, 192.0.0.9:5351: PCP answered at 192.168.1.1:5351` / `ipv6  no default route` / `no gateway asked`; `--json`: `"gateway":{"ipv4":{"next_hop":{…},"asked":[…],"answered":{"address":"192.168.1.1:5351","rung":"PCP","external":"PUBLIC_IP:53277","lifetime":7200},"renewal":false},"ipv6":{…}}` and `"network_changed":null` |
| Mappings deleted when the daemon stops | macOS: `vox node detach` of the only node, so the background daemon stopped | daemon log: `vox daemon: deleted the port mapping UDP 53277 at 192.168.1.1:5351 (PCP)` / `vox daemon: stopped` |
| A network change is noticed and said | Linux, inside `unshare --user --net --map-current-user --keep-caps` (no sudo): a dummy link with 10.9.0.1 and a default route, a node attached, then a second dummy link with 10.9.1.7 and the default route moved to it | within 6 s the daemon log said `vox: the network changed: addresses came: 10.9.1.7; went: 10.9.0.1; IPv4 default route 10.9.0.254 → 10.9.1.254; this node now advertises /ip4/10.9.1.7/udp/55525, /ip4/127.0.0.1/udp/55525, and republished 0 room(s) to its board and its anchors`; `vox status --json` → `"network_changed":{"at":1791211286,"change":"the network changed: addresses came: 10.9.1.7; went: 10.9.0.1; IPv4 default route 10.9.0.254 → 10.9.1.254"}`. The redial of connected peers and the probe line (`… did not answer a probe after the network changed; closed, and dialled again`) are from source (`node/net.rs`), not exercised: the namespace had no peer |
| A client run as root is told at once | Linux, `unshare --user --map-root-user` (uid 0 in the namespace) | `vox room list` → `vox: this is running as root (uid 0), and the vox daemon refuses every control connection from root, so nothing run as root can use it. Run vox as an ordinary user: in a container, set a non-root USER (for example `podman run --user 1000 …`). Socket: …` (exit 1) |
| `vox daemon` will not start as root | same | `vox: vox daemon will not run as root (uid 0): it admits no control connection from root, so a daemon run as root could serve nobody. Run vox as an ordinary user: …` (exit 1) |
| The short-buffer line | Linux host with `net.core.rmem_max = 212992` | daemon log: `vox: UDP receive buffer 416 KiB: path-MTU ceiling 1452 bytes, not 8192 — the OS granted a smaller receive buffer than 8192-byte datagrams need (on Linux, raise net.core.rmem_max to at least 4 MiB)` |
| No line with a 4 MiB limit | macOS (default); a Linux host with `net.core.rmem_max = 4194304` | no `UDP receive buffer` line in the daemon log on macOS |
| Podman on macOS | `podman machine ssh podman-machine-default 'sysctl net.core.rmem_max'`; a container's `/proc/sys/net/core/rmem_max` | `net.core.rmem_max = 4194304`; `4194304`. Whether this is that VM's default or was set on it was not determined |

Not exercised: a real switch of Wi-Fi networks (the change was staged in a network namespace);
the throughput cost of a small buffer, which is the decider's measurement for R41a (#218), not
this check; `sysctl -w` and `/etc/sysctl.d` themselves (they need root on the host, and the
manual's checks never use sudo). All processes were stopped (`vox node detach`, or by recorded
PID) and none remained on any host.

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
| The room link goes to stdout (rechecked at `d01c2c76`) | `vox room link y5mdh6dvqnle` | stdout: `vox://y5mdh6dvqnle…?a=…&b=…&r=…`; stderr: how the link names this host, `send the passphrase another way than this address (in person, a call, a different app)`, `joining grants nothing — use vox trust add to decide who reads you`; B joined with it: `vox: joined family` |
| `vox room invite` is gone (`d01c2c76`) | `vox room invite y5mdh6dvqnle` | `error: unrecognized subcommand 'invite'` (exit 2) |
| Join | `vox room join 'ROOM_LINK' --name family --passphrase-file ROOM_PASS` (B) | `vox: joined family` / `you read a member once you trust it and it trusts you: vox trust add`; roster lists both fingerprints |
| Trust scope is stated | `vox trust add FINGERPRINT --name ann` | `trusting eldco374… as "ann"` / `it may now read what you write in every room you share — now and later` / `and you read what it writes, once it trusts you too` / `and reach every service you bind to a room you are both in` |
| Receipt both ways | A posts `hello from robertGPT`; B `room read`; B posts; A `room read` | B: `wezorchin… robertGPT hello from robertGPT`; A: `wezorchin… you hello from robertGPT` and `ea6ldny… ann hello back from ann` |
| `--to` reports reach | `vox room post ROOM --to ann "…"` | `vox: to ann: none of its sessions has announced itself in this room; you trust it; it trusts you` |
| Structured posts read as words (rechecked at `c142ddd3`) | B `room read` after `--to`, `--re`, a file offer and a ping | `j3w3hlj6… robertGPT can you check the file?` then `  (to you)`; `yrunj6g7… you yes, it arrived`; `2ug6v2n4… robertGPT file offered: report.txt (18 bytes)`; `z6baqjlu… you ping: which agent sessions does this node hold, and can each be reached?` then `  (to robertGPT)`; `srioj3qf… robertGPT pong: 0 agent sessions on this node` |
| Hidden characters, one escape style (rechecked at `c142ddd3`) | post `bidi U+202E evil U+202C and zero U+200B width`, a newline, `second line` | `bidi ⟨U+202E⟩evil⟨U+202C⟩ and zero⟨U+200B⟩width`, then `  \| second line` and a `  \| ` line for the trailing newline |
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
| A stopped offer is said to be gone (rechecked at `c142ddd3`) | `vox share ROOM ./report.txt --count 1`, one get, then the same get again (B) | first: `./incoming/report.txt (18 bytes) verified`; again: `vox: the offer of report.txt is gone: robertGPT no longer serves it. The announcement stays in the room, but the file is served only while robertGPT shares it; ask them to share it again` (exit 1); the unreachable-sender wording `the offer of … cannot be collected now` is from source (`room_cli.rs`), not run |
| Named shares only | `vox serve 18080` | `"18080" has no name: every shared service is named, and reached as <name>.<node>.<room>.vox` / `name it as <name>=<port>, e.g. vox serve ssh=22` (exit 1) |
| `serve` and `connect` | `vox serve web2=18080 --name svc` (A); `vox connect 'ROOM_LINK' --passphrase-file PASS --name svc` (B) | room, address, `passphrase …-…-…` with `^ send this another way than the address (in person, a call, a different app)` (rechecked at `d01c2c76`), `sharing 127.0.0.1:18080 as web2.FINGERPRINT.ROOM_ID.vox`, `who can reach it: a member of this room you have trusted (vox trust add)`, `can reach it now: nobody yet`, `in the room and cannot (not trusted): nobody`, and after B joined `can reach it now: ann` (audience lines rechecked at `c142ddd3`); B: `joined. vox service list 743wt6obkyej shows what is shared here`; `curl --socks5-hostname` to `web2.robertgpt.svc.vox` returned the page |
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

The first check, at `82523ceb`, found seven product issues. All are fixed at `c142ddd3`
(`f68741b0`, `38cc358b`, #406), rechecked there with a release build in scratch roots, and the
manual now quotes the fixed output:

- `vox room read` printed structured posts as the raw JSON envelope; it now prints their words
  (`file offered: …`, `ping: …`, `pong: …`), with `(to …)` lines as before.
- Hidden characters were escaped in two styles; now every one is `⟨U+XXXX⟩`.
- A fetch from a stopped offer reported a connection reset; it now says
  `the offer of FILE is gone: NAME no longer serves it` (ADR-020 11.8).
- Help and messages said "profile"; at `c142ddd3` no `--help` page of the 64 contains "profile",
  `vox up` help no longer shows the two-part `ssh nas.family.vox`, and `vox id` with no node says
  `this node has no identity yet, and there is no terminal to ask at.`
- The TUI join prompt's first field is now `room link (vox://…)` (`state.rs`).
- `vox status` now says `always-on member: not recorded: Vox does not track which member stays
  online; each member's last_seen says when it was last heard from`.
- `vox serve` now names who can reach the service and who in the room cannot (ADR-017 4.2).

At `d01c2c76` `vox room invite` became `vox room link` (no alias; `:link` in the TUI, `state.rs`),
and the passphrase advice became `another way than this address (in person, a call, a different
app)`. None of the 64 `--help` pages at `d01c2c76` contains `invite`, `channel` or `consent`.
During the `c142ddd3` recheck, `vox serve`'s output also printed once,
after B joined, `sync of room … did not complete — sync failed: the peer refused: epoch mismatch`;
B's join and the audience line both succeeded, and it was not investigated further.

## Retired heading fragments

Decider ruling, 2026-10-04: the manual describes v0.3.0 as it is, with nothing that looks back at
earlier releases. The "Coming from v0.2.10" chapter (slug `development`, route
`/docs/manual/development/`), the install chapter's upgrade section and the troubleshooting entry
for rooms made before v0.3.0 were removed. ADR-027 D1 requires that a published slug or heading
fragment be preserved, or given a compatible route/anchor or an explicit redirect, never left as a
silently broken link. If the website has published any of the following, each needs an explicit
redirect there; plain Markdown cannot carry a compatibility anchor without raw HTML, which D4 forbids:

- the page `/docs/manual/development/` and its fragments: redirect to `/docs/manual/`;
- `install.md#upgrading-from-v0210`: redirect to `/docs/manual/install/`;
- `troubleshooting.md#no-node-is-running-for-this-profile`: now `#the-node-is-not-attached`;
- `troubleshooting.md#another-vox-process-is-using-this-profile`: now `#a-daemon-is-already-running`;
- `troubleshooting.md#the-room-was-made-before-v030`: removed; redirect to `/docs/manual/troubleshooting/`;
- from the earlier v0.3.0 rewrite: `agents.md#give-the-agent-its-own-profile-and-room`,
  `first-room.md#2-each-person-keeps-a-daemon-running`, `first-room.md#3-one-person-creates-and-invites`,
  `keyring.md#names-and-versions`, `reference.md#select-the-same-profile`.

## Earlier verification (v0.2.10)

The independent verifier `manual_practice_research` checked the v0.2.10 edition with the
published v0.2.10 executable in two disposable roots on 2026-10-04: identity before the daemon,
an empty room list, create, room link, join, trust, receipt both ways, a wrong room passphrase's
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
