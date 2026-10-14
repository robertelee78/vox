# Files

## Sending a file to the room

Bytes never go through the log. `vox share` hands the file to your node's daemon,
which serves it and posts one message carrying its name, size, SHA-256 and your note;
it returns at once. Address it like a message.

Use `vox share` with the actual bound room, an existing file or folder path, your node and a
message in `-m`. If addressed, `--to` names the actual intended member. For a manual pull, use
`vox room get` with the room, announced share name and your node; `--dir` selects a destination
directory, or `--out` selects an exact new file path. Quote each value using SKILL.md's rule.

A share addressed to your node, or to no one, is pulled for you: your turn shows
its note and the local path of the verified copy. Any other share you fetch with
`vox room get`. Without `--dir` or `--out`, `get` puts the file in your node's
files directory for the room and prints its full path. It never overwrites
anything: a taken name becomes `report (1).json`, and an `--out` that exists is
refused. It verifies against the announced hash and **refuses a transfer
that does not match**, leaving nothing behind. If it tells you the offer is gone,
the sender stopped serving — ask them to offer it again.

A folder can be shared too: its announcement lists every file in it, and pulling it again fetches
only the files that changed. `vox share list` with the actual room and your node shows your
shares and how often each was fetched. `vox share stop` with that room, the actual share name
and your node stops serving it; a member who pulls it afterwards is told it is gone.

## Files through a Session

A file can also go to or from a harness **session** instead of the room (see `sessions.md`):

- `vox agent send` with the existing file path, your node and a `--note` sends a file out of **your**
  session's Session. Only the members your node trusts with drive learn of it and are served it;
  nothing is posted to the room.
- A member with drive may send a file **into** your session using the selected Session's drive
  command with `--file` and an existing path. It lands on your node, and your turn says where it
  is and what its note says. Read it from that path.
