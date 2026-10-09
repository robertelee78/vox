# The Vox app on a Mac

Applies to: v0.4.1, Apple Silicon Macs with macOS 13 or later. The app does what the `vox`
commands do; this chapter describes where each thing is in the app. The other chapters explain
nodes, rooms, trust, services and files.

## What the app is

Vox.app is a window onto the account's vox daemon, the same daemon `vox` commands and `vox tui`
use. The app holds no node of its own. It acts as **one node** on this Mac, which you make or choose the
first time you open it, and everything you post, trust and share in the app is that node's. Your
other nodes, such as an agent's, appear under **nodes on this Mac** in the sidebar and stay with
the `vox` commands.

## Install

On a Mac the installer installs the app and `vox` together (see [Install and update](install.md)
for how to run it). It puts `Vox.app` in `/Applications`, or in `~/Applications` when it cannot
write there, and makes `~/.local/bin/vox` a link to the `vox` inside the app, so the app, the
daemon and the CLI are one binary of one version. Before anything is replaced it checks the
app's size and SHA-256, and that it is signed by Vox's Developer ID and notarized:

```text
verified: Vox.app and its vox, Developer ID TEAM_ID, notarized
installed: /Applications/Vox.app (Vox VERSION)
linked: ~/.local/bin/vox -> /Applications/Vox.app/Contents/Helpers/vox (vox VERSION)
```

On an Intel Mac, or before macOS 13, it stops before downloading anything: `this Mac is not
supported: Vox needs a Mac with Apple Silicon and macOS 13 or later`. It also refuses to replace a
`Vox.app` it did not install.

## Update

`vox update` replaces the whole app, with the `vox` inside it, and keeps the previous app for
`vox update --rollback`:

```text
updated: /Applications/Vox.app -> Vox VERSION
         the previous Vox.app is kept at … for `vox update --rollback`
```

Then it restarts the vox daemon onto the new version. Stopping the daemon detaches every node.
The new daemon attaches again each node whose passphrase it keeps: one kept with the Keychain from
the app, or with `vox node attach --keep`. Any other node comes back detached, and the update
names it with the command that attaches it again:

```text
node NAME is detached: the daemon keeps no passphrase for it. Attach it again: vox node attach NAME
```

How the daemon comes back depends on how it was started. The login item's daemon is started again
by macOS from the new app. A daemon a client started (the app, `vox tui` or another `vox` command)
is started again the same way, or, if it has no node to attach again, left stopped until the next
command needs it. A daemon you started yourself in a terminal (`vox daemon`) is left running the
old version, and the update says so: stop it and start it again. An open Vox keeps running the old
version too, until you quit it and open it again.

## The first run

1. **Keep Vox running while you're logged in?** The app asks this once: "Keep Running keeps Vox
   running in the background while you're logged in, even with the app closed, so your rooms stay
   reachable."
   - **Keep Running** registers Vox's login item, which starts the daemon each time you log in.
     macOS may want your approval first: the app then says **Allow Vox in Login Items**, with a
     button that opens System Settings, General, Login Items. Until you approve it, Vox runs
     while the app is open.
   - **Not Now** registers nothing. The app starts the daemon as `vox` does, if none is running,
     and uses the one already running if there is one.

   The same screen offers **Show Vox in the menu bar**, off unless you turn it on (see
   [The menu bar item](#the-menu-bar-item)).
2. **Welcome to Vox.** With no node on this Mac yet, the app makes one in its window, as
   `vox node create` does; nothing sends you to Terminal. Type a **Name** (lowercase letters,
   digits, dots, dashes and underscores) and the identity passphrase twice, then choose
   **Make Node**. The passphrase unlocks your node on this Mac, and nobody can recover it for you.
   The app says, as `vox node create` does, that there is no backup of a node: if this Mac is
   lost, so is the node. Two passphrases that differ are refused, and nothing is created:

   ```text
   The two passphrases differ; nothing was created.
   ```

   The app then attaches the new node with that passphrase and opens its window.
3. **Which node are you?** With several nodes on this Mac, the app lists them: pick the one you
   post, trust and share as here. With exactly one, the app uses it without asking.
4. **Attach node NAME.** For a node that is not attached yet, type its identity passphrase. The app
   hands the passphrase to the daemon and does not store it. A wrong one is refused in the daemon's
   own words, under the field:

   ```text
   That passphrase does not open node NAME's identity.
   ```

The app remembers the node you chose, and attaches it each time it opens. The answers are kept
in Vox's config directory, under `app/` (`login-item`, `node`, `menubar`).

A new node is in no room yet. Its window says **You are in no room yet.**, with
**New Room…** to make a room and share its link, and **Join Room…** to join one with the link
and passphrase someone sent you (see [Rooms from the menus](#rooms-from-the-menus)).

### A node from an earlier Vox

If the data root still holds nodes kept the way an earlier release kept them, which this version
cannot read, the app says **This Mac has a node from an earlier Vox**, names the directories, and
offers **Move It Aside and Start Fresh**. That moves each of them, whole and untouched, into
`moved-aside/` in the data root, as `NAME-YYYY-MM-DD` (with `-2`, `-3` and so on if that name is
taken); nothing in them is deleted. The welcome that follows says what moved where, as full paths:

```text
Moved aside, untouched: DATA_ROOT/NAME is now DATA_ROOT/moved-aside/NAME-YYYY-MM-DD.
```

Your new node is a new identity: people you shared rooms with add it to their keyring again.
**Try Again** looks again without moving anything.

### When Vox cannot start

If the app cannot reach the daemon, it shows a card with a plain headline, one line of likely
cause, and **Try Again**:

| Headline | Cause |
|---|---|
| Vox can't start its background service | It stopped as it started. Your rooms are unreachable until it runs. |
| Vox's background service isn't answering | It may still be starting, or be stuck. Your rooms are unreachable until it answers. |
| Another copy of Vox is using this node | Only one copy may act as a node at a time: a command that has not finished, or another copy of Vox, holds it. |
| Vox can't reach its background service | Your rooms are unreachable until it answers. |

Under **DETAILS** is the daemon's own sentence, which you can select, and **Copy** puts it on the
clipboard for a bug report. If you chose Keep Running and the login item stopped for a reason a
restart cannot fix, the card also quotes the login item's last word on it, with
**Turn Keep Running Off** and **Show Log in Finder** (`~/Library/Logs/Vox/login-item.log`).

## Opening and quitting

- **Opening** the app attaches its node, as `vox tui` does. A node already attached is used as
  it is, without asking for its passphrase.
- **Quitting** (⌘Q, or a stop signal) lets go of the node. The daemon detaches it unless
  something else keeps it attached: a `vox tui`, `vox serve` or `vox forward` still running, an
  attach by hand with `vox node attach`, or a kept node (below). `vox node list` shows the
  node's state.
- **Node > Detach** detaches the node at once: its connections close and its keys are wiped from
  memory. The app then asks which node to act as. **Node > Attach…** asks again.

### Keep a node attached when the app quits

This is offered only if you chose Keep Running. On the passphrase screen, turn on **Store the
passphrase in the Keychain, so node NAME stays attached when Vox quits**. The app says what that
costs before you attach:

```text
Anyone who can unlock this Mac's login keychain can then attach node NAME.
```

With it off, the app says: "Without it, your rooms are reachable only while Vox is open."

With it on, the daemon stores the passphrase in your login keychain (item `us.vox.node`), keeps
the node attached when the app quits, and attaches it again at login without asking.
`vox node list` shows the node `(kept)`. The stored passphrase is used only to attach the node:
changing who you trust still asks for your passphrase (see
[The keyring view](#the-keyring-view)). Detaching the node by hand, with Node > Detach or
`vox node detach NAME`, removes the passphrase from the Keychain.

A node with no identity passphrase needs no Keychain: with Keep Running chosen, it is kept as it
attaches.

## The main window

The window has four parts: a sidebar, the room on screen, the room's members beside it, and a
status bar along the bottom.

### The sidebar

- At the top, your node: `node NAME, attached`.
- Your rooms, in three groups, each with its count:
  - **needs you**: a message addressed to your node is unread.
  - **active**: new messages are unread.
  - **quiet**: nothing is unread.

  A room that is not quiet shows its unread in words under its name. **Next Room That Needs
  You** (⌘J, or Control-N as in the TUI) opens the first room in **needs you**.
- Trust offers, first under **needs you**: `offer: xgfm gktt… joined`, or `… trusts you` (see
  [Trust offers](#trust-offers)).
- **Keyring**, **Decision record** and **Services**: views of this window, described below.
- **nodes on this Mac**, each with whether it is attached.

### The room

Above the timeline, the room's title says how long it keeps messages, as the TUI does:
`Timeline · ⏱ 1 week`. If anyone in the room shares a service, its cards run along the top: the
service's address, who shares it, and its kind. Click one to select it; **Room > Copy Selected
Service's Address** (⌘⇧C) copies its full address.

Each message shows its author (`you` for your own), and marks it **urgent**, **to you**, or
**arrived late** (it took its place above messages already shown). A message whose text has not
arrived yet says `not received yet`, and is replaced when it does. What was done to the room,
such as its retention set or its name changed, appears in italics right after the message it
followed in the room:

```text
you named the room family
you set the room's retention to 1 week: messages older than 1 week are removed from now on
```

Under your own messages and shares the timeline says what happened to them:

- `read by NAME, NAME` once members' nodes say they showed it to a person.
- `pulled by NAME` once a member has pulled your share and checked its bytes.

A message counts as read only while the window is in front of you: Vox in front, the window
key, not minimized and not covered, and the message at least half in view. Nothing is read while
the app is hidden.

A shared file or folder is a card with its name, size and the start of its SHA-256. An image
shows its preview, carried in the share, even while the sharer is offline. Once your node has
pulled a copy and checked it, the card offers **Quick Look** and **Show in Finder**.

A message that starts with a link may carry a card for the page: its title, description and
picture, found by the sender's node when it posted, so showing it fetches nothing. Only `http`
and `https` links can be opened from a card; any other link is shown as text.

### Posting

Type in **Say something to the room** and press Return. Beside the field:

- **To:** opens the room's members to tick the ones the message is addressed to. With none
  ticked it goes to the room.
- **Urgent** marks it urgent. ⌘Return sends it urgent at once.

You can dictate into the composer as into any text field, with the 🎤 key or **Edit > Start
Dictation**. macOS decides whether dictation runs on the Mac or on Apple's servers (Keyboard
Settings shows which), and no app can require it to stay on the Mac; for dictation that does, use
swictation.

To reply, select a message and choose **Room > Reply to Selected Message** (⌘R). The composer
says `Replying to NAME: …` until you send or choose **Cancel**.

### Files: drag, paste, Attach or Share

Drop a file or folder on the timeline, paste one into it, or choose the paper clip
(**File > Attach File…**, ⌘O). The app asks for a **To:** and an optional **Note**, then
**Share** sends them as one share: the note and the addressees travel in the share, never as a
message of their own. With no one ticked the share is for the whole room; with members ticked
the room still sees it. It is the same as `vox share` (see [Send and receive files](files.md)).

From the Finder or any other app, choose **Share**, then **Vox**: a sheet titled **Share to a Vox
room** asks for the room, who it is for (none ticked: the whole room) and a note, and **Send**
shares it. The app need not be open, but its node must be attached; otherwise the sheet says
`Open Vox to attach node NAME first.` and sends nothing. It never asks for a passphrase. It acts as
the node the app chose, in your account's own Vox data. Sent, it says `Shared NAME (SHA-256 …)`.

In the Finder, **Services > Share to Vox Room** sends the file to the app instead, which asks for
its To: and note in the room on screen (or the next room you open).

### Members and trust

Beside the timeline, **MEMBERS** lists the room's other members with their trust: ⇄ for a member
in your keyring that trusts you back, → for one in your keyring that does not yet, and · with a
dimmed name marked `not in keyring` for one you have not trusted. Under a member in your keyring,
its entry's grant:
`read` or `read + drive`. Under a member whose node has said which machine it runs on, that
claim: `says it runs on macOS 26.2 (aarch64)`.

Under the members, **FAMILY LAN** offers the room's family LAN. Before Vox's LAN helper is
approved, it says what approving grants: one root process that creates network interfaces for
Vox and nothing else. **Allow the LAN Helper** asks macOS, which asks you in System Settings.

### The status bar

The status bar says the node, how many peers it has, and the keyring window: `keyring open 23m`
while a keyring change needs no passphrase, `keyring asks for the passphrase` once it will ask.
It also shows the last thing the app did (`Room link copied.`, `Copied: …`) and the last thing
that failed, in the daemon's words. If macOS does not let Vox notify, it says
`notifications off (System Settings, Notifications, Vox)`.

## Rooms from the menus

- **File > New Room…** (⌘N): the room's name, as every member sees it, and a passphrase for it.
  Send the passphrase another way than the link.
- **File > Join Room…** (⌘⇧J): the room link and its passphrase. A joined room keeps the name
  its members gave it.
- **Room > Copy Room Link** (⌘L).
- **Room > Rename…**: the room's one name, as every member sees it, in their sidebar and in
  every address of the room's services. Only the room's creator or an admin may rename it.
- **Room > Retention…**: 1 day, 7 days, 30 days, 1 year or forever. The sheet says what it does
  before you set it: "Every member deletes a message's text 7 days after it was sent, and older
  ones at once. Deleted text cannot be read again." Neither rename nor retention asks for a
  passphrase.
- **Room > Admins…**: the creator first, then the members it made admins. An admin may end the
  room and set its retention.
- **Room > Leave…** and **Room > End for Everyone…**, each saying what it does first.

## The keyring view

**Keyring** in the sidebar, or **View > Keyring** (⌘⇧K), lists the nodes yours trusts: each by
your alias for it, with its fingerprint art and its fingerprint in groups, and an arrow saying
whether it trusts you back (⇄) or not yet (→), and what its entry grants: `read` or `read +
drive`. See [Identity and keyring](keyring.md) for what trust grants.

- **Add a node**: paste or type its fingerprint, give it an alias, and choose what it
  **Grants**: `read` or `read + drive`. Before you choose **Trust**, the view says what trusting
  does: it may read what you write in every room you share, now and later; you read what it
  writes once it trusts you too; and it reaches every service you bind to a room you are both in.
- **Change…**: switch between read and read + drive, saying first what that does: "With drive,
  NAME also sees inside your Sessions and may type into them, interrupt or stop them, answer their
  approvals and questions, and send and receive their files." or "With read only, NAME sees each
  of your Sessions' name and whether it is open, and nothing inside it." Then **Give drive** or
  **Read only**.
- **Compare…**: paste or type the fingerprint the person gave you another way. Case, spaces and
  dashes do not count. A match says `Matches NAME's fingerprint.`; a mismatch says
  `Does not match. This is not the node you trusted as NAME: do not trust it.` and offers to
  remove it.
- **Rename…**: the new alias, and that the node's services are then reachable as
  `<service>.NEWALIAS.<room>.vox`.
- **Remove…**: the sheet asks `Remove NAME from your keyring?` and says what removing does before
  you confirm: it reads nothing you write from now on, and you read nothing it writes; what it
  already read stays read; its live sessions into your services are cut; your sender key is
  rotated, and everyone you still trust is re-keyed.

The **Keyring** menu does the same for the row selected in this view.

Changing who you trust needs your identity passphrase once the keyring window has closed. The
view then asks for it, and makes the change you were making when you choose **Continue**.

**Node > Show Fingerprint** (⌘I) shows your own fingerprint with its art, and **Copy**.

### Trust offers

A node that joined a room after yours, or that trusts you, and is not in your keyring, waits as
an offer under **needs you** in the sidebar (see [Offers](keyring.md#offers-nodes-waiting-for-your-trust)).
Select it to see a **Trust offer**: its fingerprint with its art, the same sentence `vox trust
offers` prints (`ben joined. ann trusts it.`), the rooms you share (`In: family`), and what
trusting and dismissing do. Give it an alias, choose **Grants** (`read` or `read + drive`), and
**Trust**; the view says what that grant does first, and asks for your identity passphrase if the
keyring window has closed. You are not asked to compare fingerprints. **Dismiss** removes the offer
on your node alone: it is not told, and stays out of your keyring.

## The services view

**Services** in the sidebar, or **View > Services** (⌘⇧S), lists every service in your open
rooms (see [Reach a shared service](services.md)):

- **SHARED WITH YOU**: each service's readable address, who shares it, in which room, and its
  kind; its commands, each with **Copy**; and what reaching it needs, each saying whether it holds
  (`needs …: yes`, or `needs …: no — …` with what to do). A command is shown with the readable
  address and copied with the full one, so it works however you named the node.
- **YOUR SHARES**: each one with **Stop**.
- **SHARE A SERVICE**: what is listening on this Mac, with its program. Pick one, and the view
  suggests a name, lets you pick the room, and says before you share it: the address members
  will use (`NAME.NODE.ROOM.vox`, each by their own name for your node), any warning about the
  service, who in the room can reach it (the members you trust), and who cannot (`not in your
  keyring`). **File > Share Service…** opens this view.

## The decision record

**Decision record** in the sidebar, or **View > Decision Record** (⌘⇧D), shows what your node
refused and every change of who reaches it, newest first: what was decided, what was asked, who
it was about (your alias for them, or the start of the fingerprint marked `(not in keyring)`),
when, and why. Filter it by node with **About** and by room with **Room**. The record is kept 14
days on this Mac and never sent anywhere. It is the same record the TUI shows with `d` (see
[Commands and local state](reference.md#the-decision-record)).

## The command palette and keys

**View > Command Palette** (⌘K) finds any action by typing; Return runs the first one listed.
Every action is in the menus, and the palette lists the same actions.

| Key | Action |
|---|---|
| ⌘N | New Room |
| ⌘⇧J | Join Room |
| ⌘O | Attach File |
| ⌘L | Copy Room Link |
| ⌘R | Reply to Selected Message |
| ⌘Return | Send Urgent |
| ⌘⇧C | Copy Selected Service's Address |
| ⌘J, Control-N | Next Room That Needs You |
| ⌘I | Show Fingerprint |
| ⌘K | Command Palette |
| ⌘⇧K | Keyring |
| ⌘⇧S | Services |
| ⌘⇧D | Decision Record |
| ⌘1 to ⌘9 | The first to ninth room, in the sidebar's order |
| ⌃⌘T | Focus Timeline |
| ⌘+, ⌘-, ⌘0 | Bigger, Smaller, Actual Size |

## The menu bar item

The menu bar item is off until you turn it on, at first run or later. It shows your node and the
keyring window, the rooms that need you (choose one to open it), the services shared with you
with **Copy** (it copies the full address), your shares with **Stop**, and your live tunnels.
**Hide This Menu Bar Item** turns it off again.

## Notifications

The app notifies you of a message that arrives in a room you are not looking at: never your own,
and never coordination traffic. A notification is made on this Mac only; nothing is pushed from
elsewhere. It is titled with the room's name and grouped by room, and it says who wrote and
whether to you or urgent, never what the message says:

```text
ben wrote to you, urgent
ben shared a file
```

An urgent message addressed to you also plays a sound. Clicking a notification opens its room.
macOS asks once whether Vox may notify; to change your answer, use System Settings,
Notifications, Vox.

## Contrast and display settings

Text is drawn at a contrast of 4.5:1 or more against its background, and card outlines at 4.5:1
or more. A selected sidebar row is a grey fill with a blue bar along its leading edge; its text
reads at 7.86:1 and its second line at 6.47:1. A selected row or card always has that bar, so a
selection never rests on colour alone.

The app follows your Mac's display settings (System Settings, Accessibility, Display):

- **Increase Contrast** switches to brighter colours: every text colour at 7:1 or more against
  its background (an error on a selected row at 6:1), outlines at 3.9:1 or more, the selected
  sidebar row's text at 7.20:1 and its second line at 5.33:1, and the selection marked with the
  focus colour.
- **Reduce Motion** stops its animations.
- **Reduce Transparency**: content is drawn in opaque colours only.

**View > Bigger** (⌘+), **Smaller** (⌘-) and **Actual Size** (⌘0) change the size of the
conversation, the messages and the composer, up to twice the usual size, as in Messages. The
sidebar keeps macOS's sidebar size (System Settings, Appearance) and the inspector a steady size.
**Vox > Settings…** (⌘,) sets the same size, and also turns Keep Running and the menu bar item on
or off.

The timeline works from the keyboard. **View > Focus Timeline** (⌃⌘T), Tab, or a click on a
message puts the keyboard on it; ↑ and ↓ select a message, Space opens its pulled file in Quick
Look, Return (or Enter) opens the file, or else the link on its card, and Tab or ⇧Tab moves on.
Escape or Space closes a preview however it was opened; one the keyboard opened gives the keyboard
back to the timeline.

The app is dark only.

## Sessions

Beside a room's timeline, above its members, **SESSIONS** lists the room's Sessions as the TUI
does: **General** (the room's own conversation), **All** (the conversation with each Session's
opening and end among it), each open Session (`● LABEL`, or `! LABEL · waiting on you` when it is
waiting for you), and **Ended (N)**, folded until you open it. See [Sessions](sessions.md) for what
a Session is.

Choose a Session to show it in the timeline. Its title says which: `Timeline — LABEL · open`. To a member its node trusts with **read + drive**, a Session shows each entry as one
line, word for word as `vox room session` prints it, with **Details** for its full input and
output, and a file the session sent offers **Quick Look** and **Show in Finder** once your node
has a checked copy. The header says that the Session's name and id are its node's claim:
`LABEL — name and id as NODE says`. To anyone else it shows only that it opened (and ended), and
`Only members NODE trusts with drive see inside this Session.`

With drive, an open Session has its own composer, `Composer — to LABEL`, in place of the room's:

- What you type goes to the session as its operator's input; a line starting with `/` is sent as
  a slash command.
- **Interrupt** stops the turn it is running, as Esc does; **Stop** stops it, as Ctrl-C does.
- The paper clip sends the session a file.
- An approval it asks for shows **Approve** and **Reject** (with an optional reason, told to the
  model); a question shows each part's options, and **Send answers** once each part has one. Once
  it is settled, the entry says what became of it.

Under the composer the app says what came of the last thing you sent, as the CLI and the TUI say
it: the session's node's answer, `not sent to LABEL: …`, or `no answer from LABEL: it may or may
not have been delivered`.
