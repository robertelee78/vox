# The Vox app on a Mac

Applies to: v0.4.0, Apple Silicon Macs with macOS 13 or later. The app does what the `vox`
commands do; this chapter describes where each thing is in the app. The other chapters explain
nodes, rooms, trust, services and files.

## What the app is

Vox.app is a window onto the account's vox daemon, the same daemon `vox` commands and `vox tui`
use. The app holds no node of its own. It acts as **one node** on this Mac, which you choose the
first time you open it, and everything you post, trust and share in the app is that node's. Your
other nodes, such as an agent's, appear under **nodes on this Mac** in the sidebar and stay with
the `vox` commands.

## Install

The installer is to install the app: on a Mac it is to put `Vox.app` in `/Applications` (or
`~/Applications`) and make `~/.local/bin/vox` a link to the `vox` inside it, so the app, the
daemon and the CLI are one binary of one version. That part of the installer has not landed yet;
this section is to say how once it has.

## The first run

1. **Keep Vox running while you're logged in?** The app asks this once: "Vox keeps your rooms
   reachable while you are logged in, even with the app closed."
   - **Keep Running** registers Vox's login item, which starts the daemon each time you log in.
     macOS may want your approval first: the app then says **Allow Vox in Login Items**, with a
     button that opens System Settings, General, Login Items. Until you approve it, Vox runs
     while the app is open.
   - **Not Now** registers nothing. The app starts the daemon as `vox` does, if none is running,
     and uses the one already running if there is one.

   The same screen offers **Show Vox in the menu bar**, off unless you turn it on (see
   [The menu bar item](#the-menu-bar-item)).
2. **Which node is this app?** The app lists the nodes in this data root. Pick yours. With no
   node yet, it says so: make one in Terminal with `vox node create NAME`, then choose
   **Try Again**.
3. **Attach node NAME.** Type the node's identity passphrase. The app hands the passphrase to the
   daemon and does not store it. A wrong one is refused in the daemon's own words, under the field:

   ```text
   that passphrase does not open node NAME's identity
   ```

The app remembers the node you chose, and attaches it each time it opens. The answers are kept
in Vox's config directory, under `app/` (`login-item`, `node`, `menubar`).

If the app cannot reach the daemon it says **Vox could not reach the vox daemon.**, with the
daemon's own reason and a **Try Again** button. If you chose Keep Running and the login item
stopped for a reason a restart cannot fix, the app quotes the login item's last word on it (with
when) and offers **Turn Keep Running Off**.

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
such as its retention set or its name changed, appears between the messages in italics, by time:

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

- **To:** ticks the members the message is addressed to. With none ticked it goes to the room.
- **Urgent** marks it urgent. ⌘Return sends it urgent at once.

To reply, select a message and choose **Room > Reply to Selected Message** (⌘R). The composer
says `Replying to NAME: …` until you send or choose **Cancel**.

### Files: drag, paste or Attach

Drop a file or folder on the timeline, paste one into it, or choose the paper clip
(**File > Attach File…**, ⌘O). The app asks for a **To:** and an optional **Note**, then
**Share** sends them as one share: the note and the addressees travel in the share, never as a
message of their own. With no one ticked the share is for the whole room; with members ticked
the room still sees it. It is the same as `vox share` (see [Send and receive files](files.md)).

### Members and trust

Beside the timeline, **MEMBERS** lists the room's other members with their trust: ⇄ for a member
in your keyring that trusts you back, → for one in your keyring that does not yet, and · with a
dimmed name marked `not in keyring` for one you have not trusted. VoiceOver says the first two as
`in keyring, trusts you` and `in keyring`.

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
whether it trusts you back (⇄) or not yet (→). See [Identity and keyring](keyring.md) for what
trust grants.

- **Add a node**: paste or type its fingerprint and give it an alias. Before you choose
  **Trust**, the view says what trusting does: it may read what you write in every room you
  share, now and later; you read what it writes once it trusts you too; and it reaches every
  service you bind to a room you are both in.
- **Compare…**: paste or type the fingerprint the person gave you another way. Case, spaces and
  dashes do not count. A match says `Matches NAME's fingerprint.`; a mismatch says
  `Does not match. This is not the node you trusted as NAME: do not trust it.` and offers to
  untrust it.
- **Rename…**: the new alias, and that the node's services are then reachable as
  `<service>.NEWALIAS.<room>.vox`.
- **Remove…**: the sheet says what untrusting does before you confirm: it reads nothing you
  write from now on, and you read nothing it writes; what it already read stays read; its live
  sessions into your services are cut; your sender key is rotated, and everyone you still trust is
  re-keyed.

The **Keyring** menu does the same for the row selected in this view.

Changing who you trust needs your identity passphrase once the keyring window has closed. The
view then asks for it, and makes the change you were making when you choose **Continue**.

**Node > Show Fingerprint** (⌘I) shows your own fingerprint with its art, and **Copy**.

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

## Accessibility

The app follows your Mac's settings:

- **Reduce Motion** stops its animations.
- **Increase Contrast** lifts secondary text to the primary colour, strengthens outlines, and
  marks the selection with the focus colour.
- **Reduce Transparency**: content is drawn in opaque colours only.
- Running text follows the system text size.

Every control has a VoiceOver label in words: a room says its group and unread, a member its
trust, a service card its address, who shares it and its kind, and the status bar reads as one
sentence. The app is dark only.

## Not in the app yet

These are to come, and this chapter is to describe them when they land: Sessions in the app
(see [Sessions](sessions.md) for the CLI and the TUI), sharing from the Finder's Share menu and
Services item, and the installer for the app.
