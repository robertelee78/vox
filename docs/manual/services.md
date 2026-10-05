# Reach a shared service

Applies to: v0.3.0. This chapter describes named services reached as `service.node.room.vox`.
Examples act as the only attached node; with several, add `--node NAME`.

You need a running local service on the host, two nodes whose fingerprints have been compared,
and the host's trust in the guest. Vox does not start an SSH server or replace that server's own
authentication. Do not enable a new service merely to follow an example.

## How a service is named

Every shared service has a name the sharer chose, and a member reaches it only by its address:

```text
SERVICE.NODE.ROOM.vox
```

`SERVICE` is the sharer's name for the service, `NODE` is **your** name for the sharing node (the
name you gave it with `vox trust add`, or its fingerprint) and `ROOM` is **your** name for the
room. Two members can therefore see different addresses for the same service; copy yours from
`vox service list`, never from someone else's screen. `NODE.ROOM.vox` and `ROOM.vox` reach
nothing. Names are matched without regard to case, so your alias `robertGPT` appears as
`robertgpt` in an address.

## A port shared into a new room

On the host, with SSH already listening on loopback port 22:

```sh
vox serve ssh=22
```

`serve` creates a room, shares `127.0.0.1:22` in it as `ssh`, and keeps running. It prints the
room ID, the room link, a generated room passphrase (`^ send this by a different channel than the
address`) and the address the service answers on, with fingerprints in the node and room places.
Send the link and the passphrase separately. Protect this output: it includes the room passphrase.
Several shares can be named at once, such as `vox serve ssh=22 dns=53/udp`; `--at` names a local
endpoint other than `127.0.0.1:PORT`, and `--name` sets your local name for the new room (default
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

On the guest:

```sh
vox connect 'ROOM_LINK' --name svc
vox service list ROOM_ID
```

`connect` asks for the room passphrase, joins once and exits, printing the command to list what is
shared. Both sides then exchange trust as in [Identity and keyring](keyring.md); the host must
trust the guest's fingerprint before the guest can reach its service.

## Offer a service in an existing room

With the node attached and the room on it:

```sh
vox service add ROOM_ID ssh 127.0.0.1:22
vox service list ROOM_ID
```

Vox replies `offering "ssh" at 127.0.0.1:22 … it is dark until you vox trust add someone — and they
join this room`. On the host, `service list` prints the address under `shared in` and the endpoint
under `services offered`; on a guest it prints the address and who shares it, for example
`ssh.robertgpt.family.vox  by robertgpt`. This offers an existing endpoint; it does not start
`sshd`. The host's trust keyring controls reach, not the service name. Bind your underlying
service appropriately: a service already listening on every LAN interface is still exposed there
independently of Vox.

## Reach it through the local proxy

On the guest:

```sh
vox up
```

With no room named, `vox up` carries every room the node holds. It prints `vox up on
127.0.0.1:1080 — carrying every room this node holds`, a block to add to `~/.ssh/config` once,
and a line for other tools:

```text
Host *.vox
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
    # or, without nc:
    #   ProxyCommand socat - SOCKS5:127.0.0.1:1080:%h:%p
```

Vox prints this block rather than editing your SSH configuration. Copy the one your `vox up`
printed: it names the port it really bound (`--bind` chooses another loopback port above 1024).
Keep `vox up` running, then in another terminal use the **real SSH account on the host** and your
service address:

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
explicitly intend other local-network users to access it. The older three-part form, room then
member then service, is gone in this release.

`vox status` lists live tunnels under `tunnels`. `vox tunnel close MEMBER [SERVICE]`, or
`vox tunnel close --id NUMBER`, closes them.

## Stop sharing

For a service registered in a room:

```sh
vox service remove ROOM_ID ssh
vox service list ROOM_ID
```

Removal withdraws the offer and cuts its live sessions; warn affected users first. It does
not remove the guest from your keyring or stop the underlying local SSH/web server. Removing a
node from your keyring also cuts its reach at once. For the foreground `serve` example, Ctrl-C
stops that serving process and its live offer. Leaving or ending the room stops every service
shared in it.

## A family LAN

`vox lan up ROOM_ID` puts this machine on a network interface on which the room's trusted
members are one subnet, so local-network discovery works across Vox. Creating an interface needs
root, and only a separate helper has it: run `sudo vox lan helper` in another terminal, then run
`vox lan up` as yourself, not with sudo. Without the helper it stops with `no LAN helper is
answering on /var/run/vox-lan.sock`. This manual's v0.3.0 check went no further than that message.

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
manual's v0.3.0 check did not run an anchor; these two commands come from the command help.

An anchor is infrastructure you operate, not an account with a central provider. It holds
no room key and stores nothing for rooms it is not in. Running it does not make an arbitrary
private address publicly reachable; its actual address must be reachable by the participants.
Do not blame an absent anchor when the failed step was a directly reached member refusing a
passphrase.

**Not in this release:** v0.3.0 does not notice when your machine changes network, for example
from home Wi-Fi to a phone hotspot, and off Linux it does not read the default route. After such a
change, peers may keep trying the old address. This work is planned for v0.3.1.

If it fails, use [service troubleshooting](troubleshooting.md#the-service-is-unreachable)
or [join troubleshooting](troubleshooting.md#i-cannot-join-a-room).

Source: [v0.3.0 service, proxy and forward arguments](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/cli.rs),
[tunnel behavior and diagnostics](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/tunnel_cli.rs),
[service addresses](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-017-room-bound-services.md)
and [network-change work for v0.3.1](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-012-nat-traversal-and-reachability.md).
