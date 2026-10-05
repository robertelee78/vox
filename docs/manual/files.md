# Send and receive files

Applies to: v0.3.1. Both nodes need to be attached, members of the room, and appropriately
trusted. Examples act as the only attached node; with several, add `--node NAME`.

A file in Vox is never uploaded anywhere. The sender's node serves it, the room carries an
announcement with its name, size and SHA-256, and a receiver fetches it while the sender is
still serving it.

## Offer one file

The sender runs:

```sh
vox room send ROOM_ID ./report.pdf
```

Vox hashes the file, starts a room-bound offer, and posts an announcement. It prints the size,
the SHA-256 and the command a receiver uses, for example `collect it with: vox room get ROOM_ID
report.pdf`. **Keep this command running** while people fetch it: Ctrl-C stops the offer, and
the announcement stays in the room. It is not a server-hosted attachment.

Check the file before sharing it. Its contents are available to the room members permitted
by your trust, not just one person mentioned in an accompanying message. Do not modify the
source file during the offer; re-offer deliberately when the content changes.

## Offer a folder, or a file for a limited time

```sh
vox share ROOM_ID ./photos --count 1
vox share ROOM_ID ./report.pdf --for 2h
```

`vox share` serves a file, or a folder as one tar file named after it (`photos.tar`), over HTTP
on a room-bound service. It stops after `--count` completed fetches, after `--for` (`90s`, `10m`,
`2h`), or on Ctrl-C, and says how many fetches it served. Members fetch it with `vox room get`,
or through `vox up` with the `curl` line it prints.

## Receive and verify

The receiver reads the announcement, then runs:

```sh
vox room get ROOM_ID report.pdf --dir ./incoming
```

The selector can be the announced name (`photos.tar` for a shared folder), a SHA-256 prefix or a
service tag. If names collide, use the more specific identifier from the offer. Do not assume
similarly named files from different authors are interchangeable.

Without `--dir` or `--out`, Vox uses the node's configured downloads location, or
`~/Downloads`. The sender's filename is made safe for local placement. In a destination
directory, an existing name causes a numbered alternative, such as `report (1).pdf`, rather
than replacement.

For an exact destination:

```sh
vox room get ROOM_ID report.pdf --out ./incoming/final-report.pdf
```

That exact path must not already exist. `--out` refuses an existing destination with
`already exists; vox room get never overwrites a file`. Choose another path instead of deleting
a valuable file to satisfy the example.

Vox writes to a hidden temporary `.part` file and exposes the destination only after the
received size **and** SHA-256 match the signed announcement. Success reads, for example,
`./incoming/report.pdf (18 bytes) matches its announced SHA-256`. A hash match establishes that these are the
announced bytes, not that a document is harmless to open. Apply ordinary caution to executable
files, macros and unfamiliar formats.

## Stop an offer

The sender stops `room send` or `share` with Ctrl-C. Vox withdraws the offer. People who
already downloaded it retain their copy; withdrawal is not remote erasure.

Do not promise automatic serving after the command exits. In this release an offer lasts only
as long as its command runs; files are not shown inline and are not fetched automatically.

## Recover from an unavailable or bad transfer

- An old announcement can outlive its offer. Fetching it then fails with, for example,
  `the offer of report.pdf is gone: robertGPT no longer serves it`. When the sender cannot be
  reached at all, it says `the offer of report.pdf cannot be collected now` and why. Ask the
  sender to re-offer if appropriate.
- Missing trust and unavailable serving can both prevent reach. Check the named identities
  and room before deciding it is a network fault.
- A stalled, truncated, oversized or mismatched transfer is refused. Do not use a partial
  file or disable verification. Confirm the sender's source and live offer, then fetch again.
- This release does not resume an interrupted transfer; fetch again from the start.

If it repeats, use [file troubleshooting](troubleshooting.md#the-file-is-unavailable-or-fails-verification)
and [safe reporting](getting-help.md). Keep file contents out of a public report unless you
have deliberately made a harmless reproduction file.

Source: [file exchange implementation](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/room_cli.rs)
and [share](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/share_cli.rs).
