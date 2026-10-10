# Reach a shared service

This page shows how to share a service on your machine, such as SSH, with the members of a room
you trust, and how they reach it. robertgpt shares, and ann reaches it and names robertgpt
`robertgpt`. Vox does not start the service or replace its own login: SSH still asks for its
account and keys.

## How a service is named

A member reaches a shared service by its address. It has two:

- The **readable address**, `ssh.robertgpt.family.vox`: the service's name, the member's own name
  for the sharing node, the room's name, and `.vox`. Case does not count, so ann's name `robertGPT`
gives `robertgpt` in the address. Your keyring names other nodes, not your own,
  so in the address of your own service, and of a node you have not named, the node part is the
  first twelve characters of the fingerprint. Two members may therefore
  see different readable addresses for one service.
- The **canonical address**, made of the service ID, the node's fingerprint and the room ID. It is
  the same for every member, so it is the one to copy and send.

`vox service list` shows both, with the commands for each service's kind and what reaching it
needs:

```text
  ssh.robertgpt.family.vox  by robertgpt  ssh
    mffm4sohl2j7kaefpvwk3jwrwc3xoynh3q2w5xesjcoteicf26ua.ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a.gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja.vox
      ssh     ssh $USER@mffm4sohl2j7kaefpvwk3jwrwc3xoynh3q2w5xesjcoteicf26ua.ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a.gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja.vox
      forward vox forward mffm4sohl2j7kaefpvwk3jwrwc3xoynh3q2w5xesjcoteicf26ua.ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a.gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja.vox 127.0.0.1:2222
      then    ssh -p 2222 $USER@127.0.0.1
      ✓ proxy configured
      ✓ node attached
      ✓ robertgpt trusts you
      ✓ robertgpt online
```

The printed commands use `$USER`, your user name on this machine. If your account on the sharer's
machine has another name, use that. A line that does not hold says `missing:` and what to do, such as `missing: robertgpt online —
robertgpt is not reachable now; it is reached when it comes back`. A canonical address inside a
message is shown in its readable form.

## Share a service in a room you have

The service must already run. For SSH on a Mac, turn on Remote Login in System Settings, General,
Sharing. Share it at `127.0.0.1:22`, whichever interfaces SSH listens on. On robertgpt, run:

```sh
vox service add family ssh 127.0.0.1:22
vox service list family
```

Vox prints `offering "ssh" at 127.0.0.1:22 in room gkpeyuly4m4e`, then who can reach it now,
such as `ann can reach it now`. Only members your node trusts reach it. With nobody you trust in
the room yet, it says `it is dark until you vox trust add someone — and they join this room`:
nobody reaches it yet.

Vox adds no protection to what is already open: a service that listens on every network interface
stays reachable on your network without Vox.

To stop sharing, run:

```sh
vox service remove family ssh
```

It withdraws the offer and cuts the live connections to it. Leaving or ending the room, or
removing a member from your keyring, also cuts that member's reach.

## Share a service in a new room

```sh
vox serve ssh=22
```

`vox serve` creates a room, shares `127.0.0.1:22` in it as `ssh`, and keeps sharing until you
press Ctrl-C. It prints the room's ID, its link, a generated room passphrase, and the service's
canonical address. Send the link and the passphrase separately, and protect this output: it holds
the passphrase. As members join, it says who can reach the service: only members you trust.

Name several services at once, such as `vox serve ssh=22 dns=53/udp`. `--at` names an address
other than `127.0.0.1`, and `--name` names the room (`service` by default). Before it creates the
room, `vox serve` warns about a service that listens on every interface, or on a port such as
PostgreSQL's.

With no service named, `vox serve` lists what listens on this machine and asks which to share. It
suggests a name, shows the address members will use and who can reach it, and asks
`share it? [y/N]`. Anything but `y` shares nothing. Run as yourself, the list may miss another
user's services. Name such a service as `ssh=22`.

The other person joins with `vox connect`, with the link in single quotes, and lists what is
shared:

```sh
vox connect 'vox://gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja?a=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&b=/ip4/203.0.113.7/udp/53213&m=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&r=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a'
vox service list family
```

Then you trust each other as in [Identity and keyring](keyring.md). The sharer must trust the
other person's fingerprint before they reach anything.

## What kind of service it is

When a service is shared, Vox connects to it to find out what it is, and records the kind:

| Kind | How Vox recognizes it |
|---|---|
| `ssh` | it greets a connection with an SSH banner |
| `https` | it answers a TLS handshake |
| `http` | it answers an HTTP request |
| `dns/udp` | a UDP service that answers a DNS query |
| `tcp`, `udp` | anything else |

That is up to three short TCP connections, or one UDP query, which may show in the service's log.
For a local service that none of these identifies, Vox also asks the system which program listens
on the port. The kind never comes from the port number or the name you gave.

## Reach it through the local proxy

While a node is attached, the daemon runs a SOCKS5 proxy on `127.0.0.1:1080` that resolves `.vox`
addresses. Nothing else needs starting. On ann's machine, run this to see where the proxy listens;
it starts nothing:

```sh
vox up
```

It prints the proxy's address and a block to add to `~/.ssh/config` once:

```text
Host *.vox
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
    # or, without nc:
    #   ProxyCommand socat - SOCKS5:127.0.0.1:1080:%h:%p
```

Copy the block your `vox up` printed: it names the port the proxy really uses. `nc -X` is the
OpenBSD netcat that macOS and most Linux systems ship. With another netcat, use the `socat` line. Then
connect with your account on the sharer's machine, here `robert`:

```sh
ssh robert@ssh.robertgpt.family.vox
```

Other tools use `ALL_PROXY=socks5h://127.0.0.1:1080`, or
`curl --socks5-hostname 127.0.0.1:1080 http://web.robertgpt.family.vox/`. To move the proxy, start
the daemon with `vox daemon --proxy 127.0.0.1:1081`, or set `VOX_PROXY`. It listens on loopback
only. `vox up --watch` prints what the proxy refuses or cuts.

Keep SSH's host-key check on: it is SSH's own identity check.

## Reach it through a local port

For a tool that cannot use a proxy, forward a local port to the address:

```sh
vox forward ssh.robertgpt.family.vox 127.0.0.1:2222
```

It prints `vox: forwarding 127.0.0.1:2222 to ssh on ssh.robertgpt.family.vox (ek46r5zf3r7m)` and
runs until Ctrl-C. Point the tool at the local port: `ssh -p 2222 robert@127.0.0.1`. Keep the
forward on loopback unless you mean others on your network to use it.

`vox status` lists live tunnels with their numbers. `vox tunnel close` closes all of one member's
tunnels (`vox tunnel close f7l2q44g56mz`), those to one service (`vox tunnel close f7l2q44g56mz
ssh`), or one by its number (`vox tunnel close --id 1`).

## Put a room on one local network

`vox lan up family` puts this machine on a network interface on which the room's trusted members
form one subnet, so local discovery, such as media servers and game lobbies, works across Vox.
Creating an interface needs root, which only a separate helper has. On Linux, run
`sudo vox lan helper` in another terminal, then `vox lan up family` as yourself. On a Mac, turn on
the room's **FAMILY LAN** switch in the app and allow the helper in System Settings
([the app](app.md#members-and-trust)).

## When an anchor is needed

Nodes that can reach each other directly, including over the same LAN, need no anchor. When both
are behind NAT and cannot reach each other, run an anchor on an always-on host that both can
reach:

```sh
vox node create anchor --headless
vox node --node anchor --listen 0.0.0.0:4433
```

`--headless` makes a node with no passphrase and no rooms, which only an anchor uses. `vox node`
with no subcommand runs a node as an anchor, in the foreground.

Use a port the other hosts can reach, here 4433. The anchor prints its `FINGERPRINT@ADDRESS`
lines, one per address, and writes them to the anchors file on its own machine, so nodes there
use it. On each other host, add one of those lines to its anchors file, below, or pass it with
`--anchor`. A room link made on such a host carries the anchor to whoever joins with it. Check the
anchor's fingerprint through a way you trust before anyone uses it.

An anchor is a host you run, not an account somewhere. It holds no room key and stores nothing
for rooms it is not in. An anchor only helps nodes find each other: if a member refused your
passphrase, the member was already reached.

### How a node gets its anchors

A node uses every anchor it learns from these three sources together:

- **Its anchors file.** One `FINGERPRINT@ADDRESS` per line. The address is a multiaddr such as
  `/ip4/203.0.113.7/udp/4433`, or `host:port`. Blank lines and lines starting with `#` are skipped.
  A node reads `nodes/NAME/config/anchors` in the data root if it exists, and otherwise the
  account's `anchors` in the config directory: `~/Library/Application Support/vox/anchors` on a
  Mac, `~/.config/vox/anchors` on Linux. `VOX_CONFIG_DIR`, or `XDG_CONFIG_HOME`, moves it. The
  daemon reads the file when the node attaches and every 30 seconds after. A line it cannot use is
  skipped, and named with its line number by the command that attached the node and in the
  daemon's log.
- **`--anchor FINGERPRINT@ADDRESS`**, repeatable, on any command that attaches a node or starts the
  daemon, such as `vox node attach`, `vox serve`, `vox connect`, `vox up`, `vox forward` and
  `vox daemon`. `VOX_ANCHORS` takes a comma-separated list.
- **The room link.** A link names the anchors its sharer uses. Joining with it keeps them for that
  room.

An anchors file that names one anchor:

```text
# the family's anchor on the NAS
ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a@/ip4/203.0.113.7/udp/4433
```

When your machine changes network, such as from home Wi-Fi to a phone hotspot, the daemon notices
within seconds, publishes its new addresses and dials its peers and anchors again. See
[after a network change](troubleshooting.md#peers-cannot-find-me-after-a-network-change).
