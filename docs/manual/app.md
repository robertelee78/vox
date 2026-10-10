# The Vox app on a Mac

This page says where each thing is in Vox.app. The app does what the `vox` commands do. The other
chapters explain nodes, rooms, trust, services and files. The app runs on Macs with Apple Silicon
and macOS 13 or later, and the installer installs it with `vox` ([Install and update](install.md)).

## What the app is

Vox.app is a window onto your account's Vox daemon, the same daemon the `vox` commands and the
terminal interface use. The app acts as **one node** on this Mac, which you make or choose the
first time you open it. Everything you post, trust and share in the app is that node's. The other
nodes on this Mac are listed under **ON THIS MACHINE**, with **Attach…** for each one that is not attached.

## The first run

1. **Keep Vox running while you're logged in?** **Keep Running** registers Vox's login item,
   which starts the daemon each time you log in. If macOS wants your approval first, the app says
   **Allow Vox in Login Items** with a button that opens System Settings. **Not Now** registers
   nothing, and Vox runs while the app is open. The same screen offers **Show Vox in the menu
   bar**.
2. **Welcome to Vox.** With no node on this Mac yet, type a **Name** and the identity passphrase
   twice, then choose **Make Node**. You may leave the passphrase empty. The form then says the
   node's key is kept unencrypted. There is no backup of a node: if this Mac is lost, so is the
   node.
3. **Which node are you?** With several nodes on this Mac, pick the one you post, trust and share
   as. With one, the app uses it.
4. **Attach node NAME.** For a node that is not attached, type its identity passphrase, or leave it
   empty for a node made with none. **Remember the passphrase in the Keychain** is on unless you
   turn it off. With it on, the node attaches again by itself after Vox quits or the Mac restarts,
   and anyone who can unlock this Mac's login keychain can attach it. With it off, your rooms are
   reachable only while Vox is open.

A new node is in no room yet. Its window offers **New Room…** and **Join Room…**.

If the app cannot reach the daemon, it shows a card with a headline, a likely cause and **Try
Again**. **DETAILS** holds the daemon's own sentence, with **Copy** for a report.

## Open, quit and detach

- **Opening** the app attaches its node. A node already attached is used as it is.
- **Quitting** (⌘Q) lets go of the node. The daemon detaches it unless something else keeps it:
  a remembered passphrase, a running `vox tui`, `vox serve` or `vox forward`, or a node attached
  by hand.
- **Node > Detach** detaches the node at once and forgets its passphrase. The window then offers
  **Attach NAME Again** and **Quit Vox**.
- **Node > Forget Passphrase** removes the passphrase from the Keychain. The node stays attached
  until it is detached, and the daemon stops attaching it by itself.
- **Node > Sign Out…** detaches the node, forgets its passphrase, and makes the app forget it chose
  it. Its rooms and messages stay on this Mac.

If the node stops while the window is open, a banner says why, with **Attach Again** and **Start
Over**. What you typed is kept.

## The main window

The window has a sidebar, the room on screen, the room's members beside it, and a status bar.

### The sidebar

- At the top: your node's mark, its name and `node attached`, and a **+** with **New Room…** and
  **Join Room…**.
- Your rooms, in one list, newest message first. Each row shows the room's name and the time of
  its newest message, then that message as `who: text`, and a badge with the unread count. The
  badge and time are brighter when something waits on you there: a message addressed to you, a
  Session waiting on you, or a trust offer. The second line then says what waits, such as
  `a Session needs you` or `f7l2q44… joined — trust?`.
- **Keyring**, **Decision record** and **Services**.
- At the foot, **ON THIS MACHINE**: every node on this Mac, `attached` or `detached`. A node that
  is not attached has **Attach…**, which asks for its passphrase and remembers it. Right-click a
  remembered node for **Forget Passphrase**.

A message stops being unread once at least half of it has been in view, with the window in front.
**Next Room That Needs You** (⌘J or Control-N) opens the next room where something waits on you.
The Dock icon shows how many things wait on you. Right-click a room, node or member to copy its
name or fingerprint.

### A repository with no room

When an agent session starts in a repository Vox has no room for, a banner across the window says
so, such as `Claude Code in /opt/vox has no room`. A notification, `Which room is this repo in?`,
brings you to it.

- **Choose a room…** binds the repository to one of your node's rooms, or to a room whose link you
  paste, with the room's passphrase typed there. The banner says first that the passphrase is
  saved for this repository in the room map, which every node on this Mac can read. Every session
  waiting there moves into the room.
- **Not this repo** says no. No session started there asks again.
- **Join It**, for a repository bound to a room its node is not in, joins with what the room map
  holds.

See [the room a session works in](sessions.md#the-room-a-session-works-in).

### The room

The header names the room, its member count, what is shown (General, All or a Session), and how
long the room keeps messages (`⏱ 1 week`). Services shared in the room appear as cards along the
top. **Room > Copy Selected Service's Address** (⌘⇧C) copies the selected one's address.

Each message shows its author and time. It is marked **urgent**, **to you**, or **arrived late**.
A reply shows the message it answers above it. Click the quote, or press ⌘↑, to go there. Under
your own messages the timeline says `read by NAME`, or where the message is so far (`only on this
machine`, `on N of M members' nodes`). Under your shares it says `pulled by NAME`. Room changes,
such as a new retention, appear in italics.

A shared file is a card with its name and size. **Download** pulls it and shows progress. Once
your node has checked the copy's SHA-256, the card offers **Quick Look**, **Show in Finder** and
**Save a Copy…**. Nothing unchecked opens.

A trust offer from a member is shown at the top of the room's conversation as one line, such as
`f7l2q44… joined — trust?`, with **Review…** ([Trust offers](#trust-offers)).

### Posting

Type in the field at the bottom and press Return. ⇧Return starts a new line. Type `@` and a name
to address a member you trust. **To:** picks members, or one of their open Sessions, to address.
**Urgent** marks the message urgent, and ⌘Return sends it urgent. To reply, select a message and
choose **Room > Reply to Selected Message** (⌘R).

When a member cannot read you, or you them, a line above the field says which way trust is
missing, such as `ann trusts you. Trust ann too, and you can read each other.`, with **Trust
ann…**.

To share a file, drop it on the timeline, paste it, or choose **File > Attach File…** (⌘O). The
app asks for **To:** and a **Note**, then **Share** sends one share. From the Finder or another
app, choose **Share > Vox**. This works while the app's node is attached, even with the app
closed.

### Members and trust

**MEMBERS** lists the room's other members: ⇄ for a member in your keyring that trusts you back,
→ for one that does not yet, and a dimmed name marked `not in keyring` for one you have not
trusted. Under a member in your keyring, its grant: `read` or `read + drive`. Click a member to
open its card: its fingerprint with its picture, who reads whom, and **Trust…**. Trusting from a card
asks only for a name and gives read.

**FAMILY LAN**, under the members, puts this Mac on the room's local network
([Reach a shared service](services.md#put-a-room-on-one-local-network)). The first time, the app
asks you to allow its LAN helper in System Settings, General, Login Items & Extensions.

### The status bar

The status bar shows the node, its peer count, and the keyring window: `keyring open 23m`, or
`keyring asks for the passphrase`. It also shows the result of your last action: done, refused
with the reason, or that Vox cannot tell. If macOS does not let Vox notify, it says so.

## Rooms from the menus

- **Room > New Room…** (⌘N): a name and a passphrase. Left empty, anyone with the link can join.
- **Room > Join Room…** (⌘⇧J): the room link and its passphrase. Clicking a `vox://` link in Mail,
  Messages or a browser opens this sheet with the link filled in.
- **Room > Copy Room Link** (⌘L).
- **Room > Rename…**, for the creator or an admin.
- **Room > Retention…**: 1 day, 7 days, 30 days, 1 year or forever. The sheet says what the choice
  deletes before you set it.
- **Room > Admins…**: make a member an admin, or take it away.
- **Room > Leave…** and **Room > End for Everyone…**, each saying first what it does.

## The keyring view

**Keyring** in the sidebar, or **View > Keyring** (⌘⇧K), lists the nodes yours trusts, each with
its name, fingerprint and picture, ⇄ or →, and `read` or `read + drive`.

- **Add a node:** paste its fingerprint and give it a name. The app gives read only. Drive is
  given with `vox trust drive`.
- **Compare…:** paste the fingerprint the person gave you. Case, spaces and dashes do not count.
  It shows how many of the 13 groups match, and names the group that differs.
- **Rename…** and **Remove…**, each saying first what it changes.
- **Make Read Only…** takes drive back from a node.

**Node > Show Fingerprint** (⌘I) shows your own fingerprint, with **Copy**.

A keyring change asks for your identity passphrase once the keyring window has closed. The prompt
names the change. Leave the field empty only if your node has no passphrase.

### Trust offers

A node that joined a room after yours, or that trusts you, and is not in your keyring, is offered
to you ([Offers](keyring.md#offers-nodes-waiting-for-your-trust)). The offer shows at the top of
its room, and its room's sidebar row says so. An offer from a node that shares no room in the
list is its own row at the top of the sidebar. **Review…** opens it: the fingerprint with
**Compare…**, why it is offered, the rooms you share, and what trusting and dismissing do. Give it
a name and choose **Trust** to give it read, or **Dismiss**.

## The services view

**Services** in the sidebar, or **View > Services** (⌘⇧S), has three parts:

- **SHARED WITH YOU:** each service's address with **Copy Address**, who shares it and in which
  room, its commands with **Copy**, and what reaching it needs, as `vox service list` shows it.
- **YOUR SHARES:** each with **Stop**.
- **SHARE A SERVICE:** what listens on this Mac. Pick one, name it, and pick the room. The view
  shows the address members will use and who can reach it before you share. **File > Share
  Service…** opens it.

## The decision record

**Decision record** in the sidebar, or **View > Decision Record** (⌘⇧D), lists what your node
refused and every change of who reaches it, newest first: what, about whom, when and why. Filter
by node with **About** and by room with **Room**. It is kept 14 days on this Mac and never sent
anywhere ([the decision record](reference.md#the-decision-record)).

## Sessions

Beside the timeline, **SESSIONS** lists **General**, **All**, each open Session (`● LABEL`, or
`! LABEL · waiting on you`), and **Ended (N)**. Choose a Session to show it in the timeline
([Sessions](sessions.md)).

If its node trusts you with **read + drive**, each entry is one line, with **Details** for its full
input and output, and the Session has its own composer:

- What you type goes to the session as its operator's input. A line starting with `/` is a slash
  command. If no answer comes, the text stays, marked `delivery unknown`, and is never sent again
  by itself.
- **Interrupt** (Esc) stops the turn. **Stop** (⌃C) asks first, because it ends the session.
- The paper clip, or **File > Attach File to LABEL…** (⌘O), sends the session a file.
- A waiting approval shows **Approve** (⌥⌘Y) and **Reject** (⌥⌘N). A question shows each part's
  options, and **Send answers**.

Without drive, the Session shows only that it opened and ended, and
`Only members NODE trusts with drive see inside this Session.` It then gives the command that
gives your node drive, with **Copy**: for a node on this Mac, `vox trust drive` with your
fingerprint and `--node` with that node's name, to run in a terminal on this Mac. The app itself
never gives drive. When drive is given or taken back, the Session changes at once.

## Notifications

The app notifies you of a message in a room you are not looking at, never your own. A
notification names the room and who wrote, and whether to you or urgent, never the text. An
urgent message to you plays a sound. A Session request waiting on you notifies you once, with a
sound. Clicking a notification opens the room, Session or request.

Two notifications ask something of you:

- `Node NAME needs its passphrase`, when a node on this Mac waits for it. **Attach…** opens the
  sheet that attaches it.
- `Which room is this repo in?`, when an agent session starts in a repository with no room.

To change whether Vox may notify, use System Settings, Notifications, Vox.

## The menu bar item

Turn it on at the first run or in **Vox > Settings…**. It shows your node and the keyring window,
the rooms that need you, the services shared with you with **Copy**, your shares with **Stop**,
and your live tunnels. **Hide This Menu Bar Item** turns it off.

## Keys

**View > Command Palette** (⌘K) finds any action by typing.

| Key | Action |
|---|---|
| ⌘N | New Room |
| ⌘⇧J | Join Room |
| ⌘O | Attach File |
| ⌘L | Copy Room Link |
| ⌘R | Reply to Selected Message |
| ⌘↑ | Go to the message a reply quotes |
| ⌘Return | Send Urgent |
| ⌘⇧C | Copy Selected Service's Address |
| ⌘J, Control-N | Next Room That Needs You |
| ⌘I | Show Fingerprint |
| ⌥⌘I | Hide or Show Inspector |
| ⌥⌘Y, ⌥⌘N | Approve or Reject a Session's waiting request |
| ⌘K | Command Palette |
| ⌘⇧K | Keyring |
| ⌘⇧S | Services |
| ⌘⇧D | Decision Record |
| ⌘1 to ⌘9 | The first to ninth room in the sidebar |
| ⌃⌘T | Focus Timeline |
| ⌘+, ⌘-, ⌘0 | Bigger, Smaller, Actual Size |
| ⌘, | Settings |

## Display

The app is dark only. Text meets a contrast of at least 4.5:1, and a selection is never shown by
colour alone. It follows **Increase Contrast**, **Reduce Motion** and **Reduce Transparency** in
System Settings, Accessibility, Display. **View > Bigger**, **Smaller** and **Actual Size** change
the conversation's size, up to twice the usual.
