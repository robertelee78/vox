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
| Read by, where, notifications (#482, #486, #504, #505) | `the_tui_shows_the_room_truthfully_proof`, run on #509's branch rebased on `7a1761b5` | `readby`: under Bob's post, `on 3 of 3 members' nodes`, then `read by alice` after her agent drained it; `where`: `only on this machine`, then `on 1 of 3 members' nodes`; `notify`: one notification `Vox: m` / `new messages from alice` for three messages; `shown`: `vox room read --json` gives the drawn message `read_by` `['bob']` |
| A split room passes its cap and says so | the same proof's split case, cap 3 | `the split healed: both list all 4, one past the cap of 3, and it is said`. A daemon's log carried `past its cap of 3, now 4 members: another member admitted it`; the manual gives the 1,024 cap's numbers (`MAX_AUTHORS` in `crates/vox-core/src/node/channel.rs`) |

From source, not run: expiry deleting pulled copies and ending the serving (`crates/vox-core/src/node/pulls.rs`, #496); an automatic pull's retries (`RETRY_MIN`, `RETRY_MAX`); the agent's "not pulled yet" line (`crates/vox-tui/src/agent_hook.rs`); `notify-command` in a node's `config/config` and the OSC 9 or bell route (`crates/vox-tui/src/notify.rs`); the cap of 1,024 (`MAX_AUTHORS`); the program-name fallback (`lsof` on
macOS, `ss` on Linux, `kind_of_command` in `crates/vox-core/src/node/probe.rs`); up to three probe
connections to a TCP service (`probe_tcp`). The split case was red once in this check: bob refused
y as full because x, whose daemon was still running, had reached bob directly. That run's red was
reported to the lead as staging rather than product, and a second run was green.

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
