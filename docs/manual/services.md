# Reach a shared service

Applies to: v0.3.1. This chapter describes named services reached as `service.node.room.vox`.
Examples act as the only attached node; with several, add `--node NAME`.

You need a running local service on the host, two nodes whose fingerprints have been compared,
and the host's trust in the guest. Vox does not start an SSH server or replace that server's own
authentication. Do not enable a new service merely to follow an example.

## How a service is named

Every shared service has a name the sharer chose, and a member reaches it only by its address.
Each service has two addresses, and both reach it.

The **readable address** is the one you type:

```text
SERVICE.NODE.ROOM.vox
```

`SERVICE` is the sharer's name for the service, `NODE` is **your** name for the sharing node (the
name you gave it with `vox trust add`) and `ROOM` is **your** name for the room. Two members can
therefore see different readable addresses for the same service: `web.robertgpt.family.vox` on
your machine may be `web.rob.home.vox` on someone else's. Names are matched without regard to
case, so your alias `robertGPT` appears as `robertgpt` in an address. A part that names nothing
you know is refused with the reason, for example ``no node you trust is called `nobody` — only
trusted nodes have names here``.

The **canonical address** is the one to copy and send. It is made of fingerprints and IDs only,
`SERVICE_ID.NODE_FINGERPRINT.ROOM_ID.vox`, so it reaches the same service on every member's
machine. `vox service list` prints it under the readable one:

```text
vox: shared in family (pym47virdp2b)
  web.robertgpt.family.vox  by robertgpt  http
    lnprznanqhhlxnmpzbtyfwrlomjfpzxzzovs5la2ru27smorscjq.xcxrnsegnn74dd5mxxmdrch7zfvooa4ekqxaswamlgzjwejmrwsq.pym47virdp2bauqugugmjbqa3tm6qeu762dxggg663vglzd44zua.vox
```

`NODE.ROOM.vox` and `ROOM.vox` reach nothing.

On a member's machine, `vox service list` also gives the commands for each service's kind, ready
to copy, with its canonical address in them, and what each needs, with whether it holds now:

```text
  ssh.robertgpt.family.vox  by robertgpt  ssh
    SERVICE_ID.NODE_FINGERPRINT.ROOM_ID.vox
      ssh     ssh $USER@SERVICE_ID.NODE_FINGERPRINT.ROOM_ID.vox
      forward vox forward SERVICE_ID.NODE_FINGERPRINT.ROOM_ID.vox 127.0.0.1:2222
      then    ssh -p 2222 $USER@127.0.0.1
      needs   robertgpt trusts this node (as the room's log says): yes
      needs   this node is attached: yes
      needs   the .vox proxy is running on 127.0.0.1:1080: yes
      needs   robertgpt is online: yes
  for ssh by address, add this to ~/.ssh/config once:
    Host *.vox
        ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

A `needs` line that says `no` names what to fix first. In the TUI, the same commands are in the
room's Shared pane, and `y` copies the selected one to your clipboard.

## A port shared into a new room

On the host, with SSH already listening on loopback port 22:

```sh
vox serve ssh=22
```

`serve` creates a room, shares `127.0.0.1:22` in it as `ssh`, and keeps running. It prints the
room ID, the room link, a generated room passphrase (`^ send this another way than the address (in
person, a call, a different app)`) and the service's [canonical address](#how-a-service-is-named),
followed by the [kind](#what-kind-of-service-it-is) Vox detected:
`sharing 127.0.0.1:22 as ssh — SERVICE_ID.FINGERPRINT.ROOM_ID.vox (ssh)`.
Send the link and the passphrase separately. Protect this output: it includes the room passphrase.
Several shares can be named at once, such as `vox serve ssh=22 dns=53/udp`; `--at` names a local
endpoint other than `127.0.0.1:PORT`, and `--name` sets the new room's name, which every member sees (default
`service`). A bare port is refused: `"22" has no name: every shared service is named`.

`serve` then says who can reach it: **a member of this room you have trusted**. Someone with
the link and the passphrase who is not in your keyring reaches nothing. It names them, by your
names for them, and says it again as members join:

```text
who can reach it: a member of this room you have trusted (`vox trust add`)
  a joiner with the address and the passphrase reaches NOTHING until then
  can reach it now: nobody yet
  in the room and cannot (not trusted): nobody
```

After a trusted member joins, it prints `can reach it now: ann`.

Before it creates the room, `serve` warns about a service that is already exposed or sensitive:

```text
vox: warning: `web` (nginx                0.0.0.0:8080  tcp  (every interface)) listens on every interface of this machine, so its networks reach it without Vox; sharing it does not change that
vox: warning: `db` is on port 5432, PostgreSQL's: every node you trust in the room can reach it
```

### Pick the service from a list

`vox serve` with no service named lists what is listening on this machine, with each program's
name, and asks which to share:

```text
vox: services listening on this machine
   3  sshd                 127.0.0.1:22  tcp
  another user's services, root's among them, may be missing here or listed without their program; name one with vox serve <name>=<port>
share which? (its number, or its port)
```

Answer with the number or the port. It then suggests a name, the service's
[kind](#what-kind-of-service-it-is) where Vox recognizes one (`name it [ssh]`); press Enter to
take it or type another. Before anything is created it shows the address members will use and
who can reach it, with any warning, and asks `share it? [y/N]`:

```text
members will reach it as ssh.FINGERPRINT.<the new room>.vox
who can reach it: each node you trust, once it joins the room: carol, ann
who cannot: anyone else who joins with the room link and passphrase
share it? [y/N]
```

Anything but `y` stops with `not shared`, and nothing is created. On `y` it goes on as
`vox serve ssh=22` does.

In the TUI, `:serve` in a room does the same into that room: it lists what listens here, and
Enter on one shows the preview, `share python3.13 0.0.0.0:51529 tcp (every interface) as
python3-13: members will reach it as python3-13.…family.vox`, who can reach it and who cannot, and
any warning, then `Enter: share it in this room · Esc: back to the list`. Run as yourself, the list may miss another user's services, root's
among them; name such a service as `NAME=PORT`.

On the guest:

```sh
vox connect 'ROOM_LINK'
vox service list ROOM_ID
```

`connect` asks for the room passphrase, joins once and exits, printing the command to list what is
shared and that a service is reached through the daemon's proxy, running while a node is attached
(`vox up` says where). Both sides then exchange trust as in [Identity and keyring](keyring.md); the host must
trust the guest's fingerprint before the guest can reach its service.

## Offer a service in an existing room

With the node attached and the room on it:

```sh
vox service add ROOM_ID ssh 127.0.0.1:22
vox service list ROOM_ID
```

Vox first says who is to reach it (`vox: about to offer "ssh" at 127.0.0.1:22 in "family"` / `the
members of it in your keyring are to reach it: ann`), then `offering "ssh" at 127.0.0.1:22 in room
ROOM_ID` and who can reach it now; with nobody in your keyring in the room yet it says `it is dark
until you vox trust add someone — and they join this room`. On the host, `service list` prints the readable address, `by you` and the kind
under `shared in`, the canonical address under it, and the endpoint under `services offered`. On a
guest it prints the readable address, who shares it and the kind, for example
`ssh.robertgpt.family.vox  by robertgpt  ssh`, and the canonical address under it. This offers
an existing endpoint; it does not start
`sshd`. The host's trust keyring controls reach, not the service name. Bind your underlying
service appropriately: a service already listening on every LAN interface is still exposed there
independently of Vox.

## What kind of service it is

When a service is shared, Vox finds out what it is and records that with the share. Every member's
`vox service list` shows it, and the sharer's `vox serve` prints it in brackets. The kinds are:

| Kind | How Vox recognizes it |
|---|---|
| `ssh` | the service greets a new connection with an SSH banner |
| `https` | it answers a TLS handshake |
| `http` | it answers an HTTP request |
| `dns/udp` | a UDP service that answers a DNS query |
| `tcp`, `udp` | anything else |

To find out, Vox **connects to the service**: up to three short connections to a TCP service (one
each for the banner, the handshake and the request), or one query to a UDP service. Your
service's log may show them. For a service on this machine that none of these identifies, Vox
also looks up the name of the program listening on the port (`lsof` on macOS, `ss` on Linux),
so a local `sshd` is still `ssh` if it said nothing in time. The kind never comes from the port
number or the name you gave the service: a plain echo shared as `ssh=7000` is `tcp`.

## Reach it through the local proxy

While a node is attached, the daemon runs a SOCKS5 proxy on `127.0.0.1:1080` that resolves
`.vox` addresses and carries every room its attached nodes hold. Nothing else has to be started.
On the guest, ask where it is:

```sh
vox up
```

It prints `vox up on 127.0.0.1:1080 — the vox daemon's proxy, carrying every room its attached
nodes hold`, a block to add to `~/.ssh/config` once, and a line for other tools, then exits:

```text
Host *.vox
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
    # or, without nc:
    #   ProxyCommand socat - SOCKS5:127.0.0.1:1080:%h:%p
```

Vox prints this block rather than editing your SSH configuration. Copy the one your `vox up`
printed: it names the port the proxy really listens on. To use another loopback port, start the
daemon with `vox daemon --proxy 127.0.0.1:PORT`, or set `VOX_PROXY`; the proxy listens on loopback
only. If the port is taken, `vox up` says `the .vox proxy could not listen on 127.0.0.1:1080:
Address already in use` and names both settings. `vox up --watch` stays in the foreground and
prints what the proxy refuses or cuts, until stopped; the proxy runs on without it.

Use the **real SSH account on the host** and your service address:

```sh
ssh SSH_USER@ssh.robertgpt.family.vox
```

A Vox alias is not an SSH login name. Other tools use the proxy through
`ALL_PROXY=socks5h://127.0.0.1:1080`, for example
`curl --socks5-hostname 127.0.0.1:1080 http://web.robertgpt.family.vox/`.

Success means the expected service answers and its ordinary authentication still works.
An SSH host-key warning belongs to SSH identity verification; do not disable it to make a
Vox test pass. A published offer or accepted room join alone is not service reach.

## Reach it through a local forward

For a tool without SOCKS support, the guest forwards a local port to the address:

```sh
vox forward ssh.robertgpt.family.vox 127.0.0.1:2222
```

It prints `forwarding 127.0.0.1:2222 to ssh on ssh.robertgpt.family.vox` and runs until Ctrl-C.
It is a client of the daemon, so nothing else needs stopping. Point the tool at loopback port
2222; for SSH, `ssh -p 2222 SSH_USER@127.0.0.1`. Do not bind a forward publicly unless you
explicitly intend other local-network users to access it.

`vox status` lists live tunnels under `tunnels`. `vox tunnel close MEMBER [SERVICE]`, or
`vox tunnel close --id NUMBER`, closes them.

## Stop sharing

For a service registered in a room:

```sh
vox service remove ROOM_ID ssh
vox service list ROOM_ID
```

Removal withdraws the offer and cuts its live sessions; warn affected users first. Vox says
which sessions it is to cut before it acts (`its live sessions are to be cut: none is open`) and
which it cut after (`no longer offering "ssh"; live sessions cut: none was open`). It does
not remove the guest from your keyring or stop the underlying local SSH/web server. Removing a
node from your keyring also cuts its reach at once. For the foreground `serve` example, Ctrl-C
stops that serving process and its live offer. Leaving or ending the room stops every service
shared in it.

## A family LAN

`vox lan up ROOM_ID` puts this machine on a network interface on which the room's trusted
members are one subnet, so local-network discovery works across Vox. Creating an interface needs
root, and only a separate helper has it: run `sudo vox lan helper` in another terminal, then run
`vox lan up` as yourself, not with sudo. Without the helper it stops with `no LAN helper is
answering on /var/run/vox-lan.sock`. The manual's command check went no further than that message.

## When an anchor is needed

If peers can reach each other directly, including an appropriate same-LAN path, no anchor
is needed. If both are behind NAT and cannot otherwise discover/reach each other, an
always-on host they can reach can run an anchor. On that host, per `vox node --help`:

```sh
vox node create anchor --headless
vox node --node anchor --listen 0.0.0.0:PORT
```

The anchor prints a `FINGERPRINT@ADDRESS` specification. Verify it through a way you already
trust and supply it with `--anchor` to the commands that attach or start nodes, such as
`vox node attach`, `serve` and `up`; a room link also carries the anchors its sharer uses. The
manual's command check did not run an anchor; these two commands come from the command help.

An anchor is infrastructure you operate, not an account with a central provider. It holds
no room key and stores nothing for rooms it is not in. Running it does not make an arbitrary
private address publicly reachable; its actual address must be reachable by the participants.
Do not blame an absent anchor when the failed step was a directly reached member refusing a
passphrase.

When your machine changes network, for example from home Wi-Fi to a phone hotspot, the daemon
notices within seconds, publishes its new addresses and dials its peers and anchors again; see
[after a network change](troubleshooting.md#peers-cannot-find-me-after-a-network-change).

If it fails, use [service troubleshooting](troubleshooting.md#the-service-is-unreachable)
or [join troubleshooting](troubleshooting.md#i-cannot-join-a-room).

Source: [service, proxy and forward arguments](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[tunnel behavior and diagnostics](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/tunnel_cli.rs),
[how a service's kind is detected](https://github.com/robertelee78/vox/blob/0e27808d2769e34fa678870ecb17ed141caff269/crates/vox-core/src/node/probe.rs),
[service addresses](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/docs/adr/ADR-017-room-bound-services.md)
and [network changes and port mappings](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/docs/adr/ADR-012-nat-traversal-and-reachability.md).
