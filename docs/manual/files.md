# Send and receive files

Applies to: v0.4.0. Both nodes need to be attached, members of the room, and appropriately
trusted. Examples act as the only attached node; with several, add `--node NAME`.

A file in Vox is never uploaded anywhere. Sharing posts one message to the room that carries the
file's name, size and SHA-256, and your daemon serves the bytes from your machine. Members whose
nodes trust you pull it from there, and each copy is checked against the announced SHA-256 before
it is kept.

## Share a file or a folder

```sh
vox share ROOM_ID ./report.txt -m "the report"
```

Vox first says who is to fetch it (`vox: about to share report.txt in "family"` / `the members of
it in your keyring are to fetch it: ann`), then hands the file to the daemon and returns once the
daemon serves it:

```text
vox: sharing report.txt (22 bytes) as file-ff174003a0a82197-58af8b08440c4061
     sha256 ff174003a0a82197a1b79af0b2085f06e933bbd447bcf95e5595ecd749bb5b17
     collect it with: vox room get ROOM_ID report.txt
     or through `vox up`: curl --socks5-hostname <proxy> http://file-ff174003a0a82197-58af8b08440c4061.<your-name-for-this-node>.<room>.vox/report.txt -o report.txt
     served until its message expires, `vox share stop ROOM_ID report.txt`, you leave the room, or it ends
```

Nothing has to keep running in your terminal. Your daemon serves the share while a node is
attached, until the first of these:

- the share's message expires under the room's retention;
- you run `vox share stop`;
- you leave the room, or it ends;
- `--count N` fetches have completed, or `--for` has passed (`90s`, `10m`, `2h`), if you gave either.

A folder is shared as one tar file named after it: `vox share ROOM_ID ./photos` shares
`photos.tar`.

The share is a message. `-m` adds a note, which members read with the file's name and size.
`--to` addresses it like a message: `--to carol` for one member, repeated for several. Give your
name for the member from `vox trust list`, or its fingerprint. Without `--to`, the share is for
the whole room. `--urgent` and `--re` work as they do for `vox room post` (see
[Agent communications](agents.md)).

Check the file before sharing it. A share addressed to one member is still readable by every
member of the room who can read you, and any of them can pull it. Do not change the source file
while it is shared; share it again when its content changes.

## Where a shared file lands

You do not have to fetch most shares. A node pulls a share **by itself** when both of these hold:

- the share is addressed to this node, or to no one;
- the sharer is in this node's keyring.

It pulls any size, file or folder. Each pulled copy goes to the node's files directory, one
directory per room, named by the room's full ID:

```text
DATA_ROOT/nodes/NODE/files/ROOM_ID/report.txt
```

`DATA_ROOT` is your data directory (see [Commands and local state](reference.md)). A name that is
already taken there gets a numbered alternative, such as `report (1).txt`. Nothing is ever
overwritten.

In `vox room read` and in the TUI, a share reads as `file offered: report.txt (22 bytes): the
report`. A share addressed to someone else has a `(to …)` line under it, naming them by your name
for them, or by fingerprint if you have not named them. Your node does not pull those by itself.

## Pull a share by hand

To pull a share your node did not pull, such as one addressed to someone else:

```sh
vox room get ROOM_ID notes.txt
```

The selector is the announced name (`photos.tar` for a shared folder), a SHA-256 prefix or the
share's tag. If names collide, use the more specific identifier. Without `--dir` or `--out`, the
file goes into the same files directory, and Vox prints its full path:

```text
vox: DATA_ROOT/nodes/ann/files/ROOM_ID/notes.txt (15 bytes) matches its announced SHA-256
```

`--dir ./incoming` puts it in another directory, under the sender's name made safe for local use.
`--out ./incoming/final.txt` names an exact path, which must not already exist: Vox refuses with
`already exists; vox room get never overwrites a file`. A copy you put elsewhere with `--dir` or
`--out` is yours, and Vox never removes it.

Every pull, by hand or automatic, writes to a hidden `.part` file first. The file appears under
its name only after its size **and** SHA-256 match the signed announcement. A hash match proves
these are the announced bytes, not that a document is harmless to open. Apply ordinary caution to
executable files, macros and unfamiliar formats.

## See and stop your shares

```sh
vox share list ROOM_ID
vox share stop ROOM_ID report.txt
```

`share list` prints each of your node's shares in the room with its tag, size and how many times
it was fetched. Under your own share, `vox room read` and the TUI name who has pulled it, by
your names for them: `pulled by ann`. `share stop` takes a name, a tag or a SHA-256 prefix, says
first `vox: about to stop sharing "report.txt" in "family"` / `no member is to fetch it from this
node after this`, then, for example,
`vox: no longer sharing report.txt (file-ff174003a0a82197-58af8b08440c4061; fetched 2 time(s))`.

A pull after that is told the share is gone. Copies already pulled stay where they are until the
message expires: stopping is not remote erasure.

## When a share's message expires

When a share's message expires under the retention a node applies to the room, that node deletes
its pulled copy from its files directory, and the sharer stops serving it. A copy put elsewhere
with `--dir` or `--out` is not touched. Retention is set per room (see
[Rooms and messages](rooms.md)); a modified node can keep everything, so this is housekeeping, not
a security property.

## Recover from an unavailable or bad transfer

- A share's message can outlive its serving. Pulling it then fails with
  `the offer of report.txt is gone: robertGPT no longer serves it`. When the sharer cannot be
  reached at all, it says `the offer of report.txt cannot be collected now` and why. Ask the sharer
  to share it again if appropriate.
- A share from a node your keyring does not hold is not pulled by itself. Decide whether to trust
  that node, or pull the one file by hand.
- Missing trust and unavailable serving can both prevent a pull. Check the named nodes and the
  room before deciding it is a network fault.
- A stalled, truncated, oversized or mismatched transfer is refused. Do not use a partial file
  or disable verification. An automatic pull that fails is tried again on its own, waiting longer
  each time; a pull by hand starts again from the beginning.

If it repeats, use [file troubleshooting](troubleshooting.md#the-file-is-unavailable-or-fails-verification)
and [safe reporting](getting-help.md). Keep file contents out of a public report unless you
have deliberately made a harmless reproduction file.

Source: [share](https://github.com/robertelee78/vox/blob/36649d812f2b19fe8c9bc35cad49e3c0d56bfe3a/crates/vox-tui/src/share_cli.rs),
[pulling a share by hand](https://github.com/robertelee78/vox/blob/36649d812f2b19fe8c9bc35cad49e3c0d56bfe3a/crates/vox-tui/src/room_cli.rs)
and [pulling a share by itself, and expiry](https://github.com/robertelee78/vox/blob/36649d812f2b19fe8c9bc35cad49e3c0d56bfe3a/crates/vox-core/src/node/pulls.rs).
