# Send and receive files

Applies to: v0.2.10. Both nodes need the same room open on a running daemon/TUI and appropriate
trust. Examples use the `family` profile.

## Offer one file

The sender runs:

```sh
vox room send --profile family ROOM_ID ./report.pdf
```

Vox hashes the file, starts a room-bound offer, and posts an announcement carrying its name,
size and SHA-256. **Keep this command running** while people fetch it. The announcement can
remain in the room after the bytes stop being available; it is not a server-hosted attachment.

Check the file before sharing it. Its contents are available to the room members permitted
by your trust, not just one person mentioned in an accompanying message. Do not modify the
source file during the offer; re-offer deliberately when the content changes.

## Receive and verify

The receiver reads the announcement, then runs:

```sh
vox room get --profile family ROOM_ID report.pdf --dir ./incoming
```

The selector can be the announced name, a SHA-256 prefix or a service tag. If names collide,
use the more specific identifier from the offer. Do not assume similarly named files from
different authors are interchangeable.

Without `--dir` or `--out`, Vox uses the profile's configured downloads location, or
`~/Downloads`. The sender's filename is made safe for local placement. In a destination
directory, an existing name causes a numbered alternative, rather than replacement.

For an exact destination:

```sh
vox room get --profile family ROOM_ID report.pdf --out ./incoming/final-report.pdf
```

That exact path must not already exist. `--out` refuses an existing destination; it does not
overwrite it. Choose another path instead of deleting a valuable file to satisfy the example.

Vox writes to a hidden temporary `.part` file and exposes the destination only after the
received size **and** SHA-256 match the signed announcement. Confirm the command reports
success and names the saved file. A hash match establishes that these are the announced
bytes, not that a document is harmless to open. Apply ordinary caution to executable files,
macros and unfamiliar formats.

## Stop an offer

The sender stops the foreground `room send` with Ctrl-C. Vox withdraws the offer. People who
already downloaded it retain their copy; withdrawal is not remote erasure.

Do not promise automatic serving after the command exits. Development discussions about
daemon-held attachments are not a feature of this released workflow.

## Recover from an unavailable or bad transfer

- An old announcement can outlive its offer. Ask the sender whether the original offer is
  still running, and to re-offer if appropriate.
- Missing trust and unavailable serving can both prevent reach. Check the named identities
  and room before deciding it is a network fault.
- A stalled, truncated, oversized or mismatched transfer is refused. Do not use a partial
  file or disable verification. Confirm the sender's source and live offer, then fetch again.
- This chapter does not promise resumable transfers or folders. The released entry point
  here is `vox room send` for a file, not development `vox share` for a directory.

If it repeats, use [file troubleshooting](troubleshooting.md#the-file-is-unavailable-or-fails-verification)
and [safe reporting](getting-help.md). Keep file contents out of a public report unless you
have deliberately made a harmless reproduction file.

Source: [released file exchange implementation](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/room_cli.rs).
