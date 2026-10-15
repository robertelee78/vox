# Send and receive files

This page shows how to share a file or folder with a room and how members pull it. robertgpt
shares in `family`, and ann pulls. Both nodes must be Ready, and ann's pull needs robertgpt's
trust.

A shared file is never uploaded anywhere. Sharing posts one message with the file's name, size
and SHA-256, and your daemon serves the bytes from your machine. Each member's copy is checked
against that SHA-256 before it is kept.

## Share a file or a folder

With the file you intend to share saved as `report.txt` in your current directory:

```sh
vox share family ./report.txt -m 'the report' --node robertgpt
```

Vox says who is to fetch it, hands the file to the daemon, and returns once the daemon serves it.
The output names its actual share tag, SHA-256 and collection command. Use the command from your
own output; a recipient uses their own node when collecting it. File names with spaces or shell
punctuation are quoted by the [same rule](reference.md#commands-you-can-paste).

Nothing has to keep running in your terminal. The daemon serves the share until the first of:

- the message expires under the room's retention;
- you run `vox share stop`;
- you leave the room, or it ends;
- `--count N` fetches complete, or `--for` (`90s`, `10m`, `2h`) passes, if you gave either.

`-m` adds a note. `--to carol` addresses the share to one member. Repeat it for several. Without
`--to` it is for the whole room. `--urgent` and `--re` work as they do for `vox room post`. Every
member who can read you can see and pull an addressed share too, so check what you share.

A folder is shared as its files. A member pulls it as a folder and checks each file. When you
share a changed folder again, members fetch only the files that are new or changed, and a pull
that was cut off resumes from the files it has.

An image share carries a small preview inside the message, so members see it before they pull it,
even while you are offline.

Do not change a file while it is shared. Share it again when it changes.

## Where a shared file lands

A node pulls a share by itself when both of these hold:

- the share is addressed to this node, or to no one;
- the sharer is in this node's keyring.

It pulls any size, file or folder, into the node's files directory, one directory per room:

```text
DATA_ROOT/nodes/ann/files/gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja/report.txt
```

`DATA_ROOT` is the data directory ([Commands and local state](reference.md#local-state)). A name
already taken gets a number, such as `report (1).txt`. Nothing is overwritten.

`vox room read` shows a share as `file offered: report.txt (21 bytes): the report`. A share
addressed to someone else has a `(to …)` line, and your node does not pull it by itself.

## Pull a share by hand

After `notes.txt` has actually been offered in `family`, ann can pull it with:

```sh
vox room get family notes.txt --node ann
```

Name the share by its file name, a SHA-256 prefix, or its tag. Vox prints where the file landed:

```text
vox: DATA_ROOT/nodes/ann/files/gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja/notes.txt (15 bytes) matches its announced SHA-256
```

`--dir ./incoming` puts it in another directory. `--out ./incoming/final.txt` names an exact path,
which must not exist yet. A copy put elsewhere this way is yours, and Vox never removes it.

Every pull writes to a hidden `.part` file first. The file takes its name only once its size and
SHA-256 match. A match proves these are the announced bytes, not that the file is safe to open.

## See and stop your shares

```sh
vox share list family --node robertgpt
vox share stop family report.txt --node robertgpt
```

`vox share list` shows each of your shares in the room, with its tag, size and fetch count.
`vox share stop` takes a name, tag or SHA-256 prefix and reports, for example,
`vox: no longer sharing report.txt (file-696123c9184755c8-36d75aac38e972eb; fetched 2 time(s))`.
Copies already pulled stay with their members.

When a share's message expires under a node's retention, that node deletes its pulled copy, and
the sharer stops serving it. Copies put elsewhere with `--dir` or `--out` stay.

## When a pull fails

- `the offer of report.txt is gone: robertGPT no longer serves it`: the sharer stopped. Ask them to
  share it again.
- `the offer of report.txt cannot be collected now`, with a reason: the sharer cannot be reached
  now.
- A share from a node not in your keyring is not pulled by itself. Trust the node, or pull the one
  file by hand.
- A stalled, cut, oversized or mismatched transfer is refused and its `.part` file removed. An
  automatic pull tries again, waiting longer each time. A pull by hand starts again from the
  beginning.

More in [the file is unavailable or fails verification](troubleshooting.md#the-file-is-unavailable-or-fails-verification).
