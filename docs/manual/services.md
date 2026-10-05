# Reach a shared service

Applies to: v0.2.10. This chapter describes TCP and the released numeric-port service syntax.
It does not describe development `ssh=22` shares or `service.node.room.vox` addresses.

You need a running local service on the host, two identities whose fingerprints have been
compared, and the host's trust in the guest. Vox does not start an SSH server or replace that
server's own authentication. Do not enable a new service merely to follow an example.

## A port shared into a new room

On the host, first obtain its identity and arrange the [keyring decisions](keyring.md).
On the guest, do the same. Use a dedicated profile consistently, for example `service`.
The host must trust the guest fingerprint before the guest can reach its service.

On a host already running SSH on loopback port 22, with no daemon/TUI holding this profile:

```sh
vox serve --profile service 22
```

`serve` creates a room, offers `127.0.0.1:22`, and prints a room ID, invitation, generated
room passphrase and the room's `.vox` hostname. Keep it running. Send the invitation and
passphrase separately to the guest. Protect this output: it includes the room passphrase.

On the guest, with no other process holding its `service` profile:

```sh
vox connect --profile service 'vox://…'
vox up --profile service ROOM_ID
```

`connect` joins once and exits. `up` starts a loopback SOCKS5 proxy, normally
`127.0.0.1:1080`, and stays running. In another terminal on the guest, use the SSH command
or ProxyCommand printed by `up`, with the **real SSH account on the host** and its printed
Vox hostname. A Vox alias is not an SSH login name.

The usual shape is:

```sh
ssh -o 'ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p' SSH_USER@ROOM_HOSTNAME.vox
```

Replace both placeholders. This form also requires an `nc` implementation supporting those
proxy options. Use the actual command and hostname emitted by your installed Vox rather than
guessing an address from this development website's illustrations.

Success means the expected service answers and its ordinary authentication still works.
An SSH host-key warning belongs to SSH identity verification; do not disable it to make a
Vox test pass. A published offer or accepted room join alone is not service reach.

## Offer a service in an existing room

With a daemon/TUI already holding the profile and room:

```sh
vox service add --profile family ROOM_ID ssh 127.0.0.1:22
vox service list --profile family ROOM_ID
```

This offers an existing endpoint; it does not start `sshd`. Inspect the listing to confirm
the intended tag, host and room. The host's trust keyring controls reach, not the tag name.
Bind your underlying service appropriately: a service already listening on every LAN
interface is still exposed there independently of Vox.

For a tool without SOCKS support, the guest can use a local forward:

```sh
vox forward --profile family ROOM_ID HOST_FINGERPRINT ssh 127.0.0.1:2222
```

This released command starts its own profile holder, so stop that guest profile's daemon/TUI
deliberately before using it. Keep the forward running, then point the tool at loopback
port 2222. For SSH, use `ssh -p 2222 SSH_USER@127.0.0.1`. Do not bind a forward publicly unless
you explicitly intend other local-network users to access it.

## Stop sharing

For a service registered in a running room:

```sh
vox service remove --profile family ROOM_ID ssh
vox service list --profile family ROOM_ID
```

Removal withdraws the offer and cuts its live sessions; warn affected users first. It does
not remove the guest from your keyring or stop the underlying local SSH/web server.
For the foreground `serve` example, Ctrl-C stops that serving process and its live offer.

## When an anchor is needed

If peers can reach each other directly, including an appropriate same-LAN path, no anchor
is needed. If both are behind NAT and cannot otherwise discover/reach each other, an
always-on host they can reach can run an anchor:

```sh
vox node --profile anchor --listen 0.0.0.0:0
```

The anchor prints a fingerprint/address specification. Verify it through your established
channel and supply it using `--anchor` to the relevant networking commands. In the new-room
example, provide it when the host runs `serve` and the guest runs `up`; the invitation also
carries rendezvous information for the join.

An anchor is infrastructure you operate, not an account with a central provider. It holds
no room key. Running it does not make an arbitrary private address publicly reachable; its
actual address must be reachable by the participants. Do not blame an absent anchor when
the failed step was a directly reached member refusing a passphrase.

If it fails, use [service troubleshooting](troubleshooting.md#the-service-is-unreachable)
or [join troubleshooting](troubleshooting.md#i-cannot-join-a-room).

Source: [released service and proxy arguments](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/cli.rs)
and [tunnel behavior and diagnostics](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/tunnel_cli.rs).
