//! The navigation / input state machine (ADR-015 §"Navigation & input").
//!
//! This is pure interaction logic — no terminal, no core. It owns *UI* state
//! (which screen/pane has focus, the command-palette overlay, selection indices)
//! and translates input into either a navigation mutation or a [`Command`] for the
//! core. The authoritative data (members, timeline, trust) lives in the
//! [`ViewModel`] pushed from the core; this module never invents trust state.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use secrecy::SecretString;
use vox_core::hash::Digest32;
use zeroize::Zeroizing;

use crate::session_cli::Waiting;
use crate::viewmodel::{Command, DriveAct, SessionView, ViewModel};

/// How many lines PageUp/PageDown scroll the timeline.
pub const TIMELINE_PAGE: usize = 10;

/// Which masked onboarding/attach prompt is open (ADR-015: passphrases are entered
/// through a masked prompt, never on the palette line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptKind {
    /// Attach the node: `[passphrase]`, given once (ADR-026 N-2).
    Attach,
    /// Create the identity: `[passphrase, confirm]`.
    CreateIdentity,
    /// Create a channel: `[name, passphrase, confirm]`.
    CreateChannel,
    /// Open a closed channel: `[passphrase]` for `Prompt::target`.
    OpenChannel,
    /// Join from a `vox://` room link: `[link, passphrase]`. The room keeps its own name.
    ///
    /// The link is shown as it is typed because it carries no secret (ADR-016); the
    /// channel passphrase that follows is masked, because it travels out of band and
    /// is the one thing the link deliberately does not contain.
    JoinChannel,
    /// Rename the room `Prompt::target` for every member: `[name, identity passphrase]`
    /// (ADR-028 R-1), as `vox room rename` asks.
    RenameRoom,
    /// Leave `Prompt::target`: `[the word "leave"]`, typed to confirm what the title says it does
    /// (ADR-028 E-5).
    LeaveRoom,
    /// End `Prompt::target` for everyone: `[the word "end"]`, typed to confirm what the title says
    /// it does (ADR-028 E-5).
    EndRoom,
    /// Trust the node `Prompt::target` (ADR-028 K-5): `[its fingerprint as they gave it, a
    /// name, identity passphrase]`. The fingerprint is compared before anything is added.
    Trust,
    /// Accept the offer of the node `Prompt::target` (ADR-028 K-16): `[a name, read or read +
    /// drive, identity passphrase]`. Its fingerprint is shown, grouped with its art; no comparison
    /// is asked for (the member pane's trust action keeps one).
    AcceptOffer,
}

impl PromptKind {
    /// The field labels, in order.
    #[must_use]
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            PromptKind::Attach => &["identity passphrase"],
            PromptKind::CreateIdentity => &["new identity passphrase", "confirm passphrase"],
            PromptKind::CreateChannel => &["room name", "room passphrase", "confirm passphrase"],
            PromptKind::OpenChannel => &["room passphrase"],
            PromptKind::JoinChannel => &["room link (vox://…)", "room passphrase"],
            PromptKind::RenameRoom => &["new room name"],
            PromptKind::LeaveRoom => &["type leave to leave it"],
            PromptKind::EndRoom => &["type end to end it for everyone"],
            PromptKind::AcceptOffer => &[
                "your name for them",
                "read, or read + drive (Enter or r: read · d: read + drive)",
                "identity passphrase (Enter alone while the keyring is open)",
            ],
            PromptKind::Trust => &[
                "their fingerprint, as they gave it to you (paste or type it)",
                "your name for them",
                "identity passphrase (Enter alone while the keyring is open)",
            ],
        }
    }

    /// Whether field `i` is secret (masked while typing, zeroized after).
    #[must_use]
    pub fn is_secret(self, i: usize) -> bool {
        match self {
            // A room's name is not a secret.
            PromptKind::CreateChannel => i != 0,
            PromptKind::RenameRoom => false,
            // The link is not; only the passphrase.
            PromptKind::JoinChannel => i == 1,
            // A confirming word is no secret.
            PromptKind::LeaveRoom | PromptKind::EndRoom => false,
            // A fingerprint and a name are not; only the passphrase.
            PromptKind::Trust | PromptKind::AcceptOffer => i == 2,
            _ => true,
        }
    }

    /// What the prompt says under its field, before the person goes on: making a node says it
    /// has no backup (ADR-028 K-8).
    #[must_use]
    pub fn note(self) -> Option<&'static str> {
        match self {
            PromptKind::CreateIdentity => Some(crate::ident::NO_BACKUP),
            _ => None,
        }
    }

    /// The prompt's title.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            PromptKind::Attach => "Attach node",
            PromptKind::CreateIdentity => "Create identity",
            PromptKind::CreateChannel => "Create room",
            PromptKind::OpenChannel => "Open room",
            PromptKind::JoinChannel => "Join room",
            PromptKind::RenameRoom => "Rename room",
            // What it is to do, said before it is done (ADR-028 E-5).
            PromptKind::LeaveRoom => {
                "Leave this room? Its other members are to see that you left, and this node is \
                 to delete it with everything it holds of it"
            }
            PromptKind::EndRoom => {
                "End this room for everyone? Every member's node is to take no new message in it \
                 and delete it"
            }
            PromptKind::Trust => {
                "Trust this node? Compare its fingerprint with the one they gave you"
            }
            PromptKind::AcceptOffer => {
                "Trust this node? It is to read what you write in every room you share, now and \
                 later"
            }
        }
    }
}

/// The most a prompt field holds, in bytes. Each field is given all of it when the prompt opens and
/// never grows past it (V210-94): a `String` that outgrows its buffer moves to a bigger one and frees
/// the old one as it was, so a passphrase typed a key at a time would leave its earlier prefixes in
/// freed memory, which [`Zeroizing`] never reaches.
pub const PROMPT_FIELD_CAPACITY: usize = 1024;

/// A masked multi-field prompt. Every field buffer is [`Zeroizing`], so a
/// cancelled or submitted prompt leaves no passphrase in memory; the values never
/// appear in a status string or the palette line.
#[derive(Clone, Debug)]
pub struct Prompt {
    /// What the prompt is for.
    pub kind: PromptKind,
    /// The field being edited.
    pub step: usize,
    /// The field buffers (zeroized on drop).
    pub fields: Vec<Zeroizing<String>>,
    /// The channel a per-channel prompt targets.
    pub target: Option<Digest32>,
}

impl Prompt {
    /// A fresh prompt of `kind` (optionally targeting a channel).
    #[must_use]
    pub fn new(kind: PromptKind, target: Option<Digest32>) -> Self {
        Self {
            kind,
            step: 0,
            fields: kind
                .fields()
                .iter()
                .map(|_| Zeroizing::new(String::with_capacity(PROMPT_FIELD_CAPACITY)))
                .collect(),
            target,
        }
    }

    /// The label of the current field.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.kind.fields().get(self.step).copied().unwrap_or("")
    }

    /// The current field rendered for display: masked (`•` per char) if secret.
    #[must_use]
    pub fn display(&self) -> String {
        let v = self.fields.get(self.step).map_or("", |f| f.as_str());
        if self.kind.is_secret(self.step) {
            "•".repeat(v.chars().count())
        } else {
            v.to_owned()
        }
    }
}

/// Which screen is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Home: the channel (swarm) list.
    ChannelList,
    /// An open channel: timeline + composer + member pane.
    Channel,
    /// The live tunnels, to see and close (V030-11): `t` on the channel list, or `:tunnels`.
    Tunnels,
    /// The trust keyring, each node with its fingerprint grouped and its art (ADR-028 W-1, K-1):
    /// `k` on the channel list, or `:keyring`.
    Keyring,
    /// What this node decided, newest first (ADR-028 D-3): `d` on the channel list, or
    /// `:decisions`.
    Decisions,
    /// Sharing a service listening on this machine into the room on screen (ADR-028 S-4):
    /// `:serve`, or `:serve <port>` for one directly.
    Serve,
}

/// Which pane has focus within the channel screen (cycled by `Tab`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// The message timeline.
    Timeline,
    /// The message composer.
    Composer,
    /// The member pane.
    Members,
    /// What is shared in the room (ADR-028 S-3): Up/Down select, `y` copies its command.
    Shared,
    /// The room's Sessions (ADR-029 CL-2): Up/Down select, Enter shows the one selected.
    Sessions,
}

impl Focus {
    /// The next pane in the `Tab` cycle.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Focus::Timeline => Focus::Composer,
            Focus::Composer => Focus::Members,
            Focus::Members => Focus::Shared,
            Focus::Shared => Focus::Sessions,
            Focus::Sessions => Focus::Timeline,
        }
    }
}

/// Input modality: normal navigation, the modal `:` command-palette overlay, or a
/// masked prompt.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Normal mode: chords navigate; the composer (when focused) inserts text.
    Normal,
    /// The command palette is open; the buffer holds the typed command line.
    CommandPalette(String),
    /// A masked onboarding/attach prompt is open (modal).
    Prompt(Prompt),
}

impl Mode {
    /// Whether the mode is `Normal`.
    #[must_use]
    pub fn is_normal(&self) -> bool {
        matches!(self, Mode::Normal)
    }
}

/// The outcome of handling one key event. (`Command` carries a redacted
/// [`secrecy::SecretString`] on some variants, so it is intentionally not
/// `PartialEq` — match on the variant rather than comparing for equality.)
#[derive(Debug)]
pub enum Action {
    /// Nothing actionable (state may have changed; redraw).
    Redraw,
    /// Dispatch this command to the core.
    Dispatch(Command),
    /// Quit the application.
    Quit,
    /// Put this text on the system clipboard (OSC 52) and say it on the status line
    /// (ADR-028 S-3): a shared service's command.
    Copy(String),
}

/// What a room's timeline shows (ADR-029 CL-2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Showing {
    /// The room's own conversation: **General**.
    #[default]
    General,
    /// **All**: the room's conversation with each Session's opening and end, in time order.
    All,
    /// One Session, by its node and the harness's session id.
    Session(Digest32, String),
}

/// One row of a room's Sessions pane, top to bottom (ADR-029 CL-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRow {
    /// The room's own conversation.
    General,
    /// Everything merged.
    All,
    /// The Session at this index of the room's `sessions`.
    Session(usize),
    /// The ended Sessions, apart (SE-5): this many; Enter shows or hides them.
    Ended(usize),
}

/// The Sessions pane's rows: General, All, the open Sessions, then "Ended (N)" when any has
/// ended, with the ended ones under it while `ended_open`.
#[must_use]
pub fn session_rows(sessions: &[SessionView], ended_open: bool) -> Vec<SessionRow> {
    let mut rows = vec![SessionRow::General, SessionRow::All];
    rows.extend(
        sessions
            .iter()
            .enumerate()
            .filter(|(_, x)| x.ended.is_none())
            .map(|(i, _)| SessionRow::Session(i)),
    );
    let ended: Vec<usize> = sessions
        .iter()
        .enumerate()
        .filter(|(_, x)| x.ended.is_some())
        .map(|(i, _)| i)
        .collect();
    if !ended.is_empty() {
        rows.push(SessionRow::Ended(ended.len()));
        if ended_open {
            rows.extend(ended.into_iter().map(SessionRow::Session));
        }
    }
    rows
}

/// The UI navigation state.
#[derive(Clone, Debug)]
pub struct UiState {
    /// The current screen.
    pub screen: Screen,
    /// The focused pane (meaningful on the channel screen).
    pub focus: Focus,
    /// The input mode.
    pub mode: Mode,
    /// Selected channel index in the home list.
    pub selected_channel: usize,
    /// The room selected, **by identity** (#511): the sidebar groups rooms by what they need, so
    /// an unread re-sorts it, and a position would then name another room. Each frame finds its
    /// index again ([`UiState::settle`]).
    pub selected_room: Option<Digest32>,
    /// The offer selected in the sidebar, when one is (ADR-028 K-15): offers come first, under
    /// "needs you", before the rooms.
    pub selected_offer: Option<Digest32>,
    /// The shared service selected in the room's Shared pane, by position (ADR-028 S-3).
    pub selected_share: usize,
    /// The member selected in the member pane, **by identity** (V210-82): the pane is in
    /// fingerprint order, so a join re-sorts it, and a position would then name someone else.
    /// `None` until the pane first has a member (see [`UiState::settle`]).
    pub selected_member: Option<Digest32>,
    /// How many lines the timeline is scrolled up from its newest; 0 follows new messages.
    pub timeline_scroll: usize,
    /// The message selected in the timeline, **by entry** (ADR-028 R-9, #485): what `r` replies
    /// to, and whose quote Enter jumps to. `None` follows the newest.
    pub selected_message: Option<Digest32>,
    /// The timeline must scroll to the selected message on its next draw: it was just selected.
    pub reveal_selected: bool,
    /// The message the composer is replying to, when it is.
    pub replying: Option<Digest32>,
    /// The images ready to draw inline, and how this terminal draws them (ADR-028 F-11).
    pub images: std::rc::Rc<std::cell::RefCell<crate::images::Images>>,
    /// A transient status/alert line shown at the bottom (e.g. the result of the
    /// last command, an error, a recovery hint). `None` when clear.
    pub status_message: Option<String>,
    /// The composer's pending text (single-line; Enter sends).
    pub composer: String,
    /// The tunnel selected in the tunnel list, **by its number**, so a tunnel that ends or opens
    /// does not move the selection onto another (V030-11).
    pub selected_tunnel: Option<u64>,
    /// The messages the last frame drew in the room on screen, by entry: what this node's
    /// person has been shown, for a read record (ADR-028 RR-1). Taken by the loop after each
    /// frame; empty when no room is on screen.
    pub on_screen: Vec<Digest32>,
    /// The service selected in the share flow's list, by its place in it (ADR-028 S-4).
    pub selected_listening: usize,
    /// The room the share flow offers into.
    pub serve_room: Option<Digest32>,
    /// Whom the composer's next message is to (ADR-028 W-4, `to`): `:to <name>…`.
    pub to: Vec<Digest32>,
    /// The composer's next message is urgent (W-4, ADR-020 4.5): `:urgent`.
    pub urgent: bool,
    /// What the room's timeline shows: General, All or one Session (ADR-029 CL-2).
    pub showing: Showing,
    /// The row selected in the Sessions pane, by position.
    pub selected_session_row: usize,
    /// The ended Sessions are listed under "Ended (N)" (SE-5).
    pub ended_open: bool,
    /// The line selected in the Session on screen, by position; `None` follows the newest.
    pub selected_session_line: Option<usize>,
    /// The selected line's Details are shown under it (SC-1).
    pub details_open: bool,
    /// The room the To: and urgent belong to: another room starts without them.
    pub compose_room: Option<Digest32>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            screen: Screen::ChannelList,
            focus: Focus::Timeline,
            mode: Mode::Normal,
            selected_channel: 0,
            selected_room: None,
            selected_offer: None,
            selected_share: 0,
            selected_member: None,
            timeline_scroll: 0,
            selected_message: None,
            reveal_selected: false,
            replying: None,
            images: std::rc::Rc::default(),
            status_message: None,
            composer: String::new(),
            selected_tunnel: None,
            on_screen: Vec::new(),
            selected_listening: 0,
            serve_room: None,
            to: Vec::new(),
            urgent: false,
            showing: Showing::General,
            selected_session_row: 0,
            ended_open: false,
            selected_session_line: None,
            details_open: false,
            compose_room: None,
        }
    }
}

impl UiState {
    /// A fresh UI state at the home channel list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold the latest `vm` into the selection: an open channel's first member is selected when
    /// nothing is, or when the member selected is no longer in the pane, so the marker the pane
    /// draws and the member a command acts on are one member, held by identity from then on.
    pub fn settle(&mut self, vm: &ViewModel) {
        // The To:, urgent and what the timeline shows are the room's: another room starts
        // without them, on General.
        let room = vm.active.as_ref().map(|c| c.channel_id);
        if room != self.compose_room {
            self.compose_room = room;
            self.to.clear();
            self.urgent = false;
            self.showing = Showing::General;
            self.selected_session_row = 0;
            self.ended_open = false;
            self.selected_session_line = None;
            self.details_open = false;
        }
        match self
            .selected_room
            .and_then(|id| vm.channels.iter().position(|c| c.channel_id == id))
        {
            Some(i) => self.selected_channel = i,
            None => {
                self.selected_channel = self
                    .selected_channel
                    .min(vm.channels.len().saturating_sub(1));
                self.selected_room = vm.channels.get(self.selected_channel).map(|c| c.channel_id);
            }
        }
        if self.screen == Screen::Tunnels {
            if self
                .selected_tunnel
                .is_none_or(|id| !vm.tunnels.iter().any(|t| t.id == id))
            {
                self.selected_tunnel = vm.tunnels.first().map(|t| t.id);
            }
            return;
        }
        if self.screen != Screen::Channel {
            return;
        }
        let Some(members) = vm.active.as_ref().map(|c| &c.members) else {
            return;
        };
        if self
            .selected_member
            .is_none_or(|id| !members.iter().any(|m| m.id == id))
        {
            self.selected_member = members.first().map(|m| m.id);
        }
    }

    /// Handle a key event against the current `vm`, returning the [`Action`].
    ///
    /// `vm` is read-only context (the active channel/members) used to resolve
    /// selection-relative commands; this method never mutates trust state.
    pub fn on_key(&mut self, key: KeyEvent, vm: &ViewModel) -> Action {
        // Ctrl-C always quits — from any mode, including an open prompt or palette
        // (the exit path restores the terminal; the node is the daemon's, and stays with it).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.mode = Mode::Normal;
            return Action::Quit;
        }
        // Modal overlays intercept all other keys while open.
        match self.mode {
            Mode::CommandPalette(_) => return self.on_palette_key(key, vm),
            Mode::Prompt(_) => return self.on_prompt_key(key),
            Mode::Normal => {}
        }
        // **Ctrl-N: the next room with a message addressed to this node** (ADR-028 R-8, #484),
        // from the room list or a room, after the one selected and round again: a room with only
        // new messages is passed over.
        if key.code == KeyCode::Char('n') && key.modifiers.contains(KeyModifiers::CONTROL) {
            let n = vm.channels.len();
            let next = (1..=n)
                .map(|k| (self.selected_channel + k) % n.max(1))
                .find(|i| vm.channels.get(*i).is_some_and(|c| c.to_you > 0));
            return match next {
                Some(i) => {
                    self.selected_channel = i;
                    self.selected_room = vm.channels.get(i).map(|c| c.channel_id);
                    self.open_selected(vm)
                }
                None => Action::Redraw,
            };
        }
        // The composer, when focused, owns printable keys, Backspace and Enter.
        if self.screen == Screen::Channel && self.focus == Focus::Composer {
            match key.code {
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.composer.push(c);
                    return Action::Redraw;
                }
                KeyCode::Backspace => {
                    self.composer.pop();
                    return Action::Redraw;
                }
                KeyCode::Enter => {
                    let text = self.composer.trim().to_owned();
                    if text.is_empty() {
                        return Action::Redraw;
                    }
                    let Some(channel_id) = self.active_channel_id(vm) else {
                        return Action::Redraw;
                    };
                    // In a Session, the composer types into the session as its operator, or sends
                    // it a slash command (ADR-029 DR-1.2, DR-1.6). Only a driver has one (CL-3).
                    if let Some(x) = showing_session(self, vm).filter(|x| x.can_drive) {
                        self.composer.clear();
                        let act = if text.starts_with('/') {
                            DriveAct::Slash(text)
                        } else {
                            DriveAct::Say(text)
                        };
                        return Action::Dispatch(Command::Drive {
                            channel_id,
                            session: (x.node, x.id.clone()),
                            act,
                        });
                    }
                    // `@alias` addresses a member (ADR-028 K-4): the whole fingerprint goes into
                    // `to`. One that names nobody, or more than one, keeps the text to fix.
                    let members: Vec<Digest32> = vm
                        .active
                        .as_ref()
                        .map(|c| c.members.iter().map(|m| m.id).collect())
                        .unwrap_or_default();
                    let to = match crate::ident::addressed_in(&text, &members, &vm.keyring) {
                        Ok(to) => to,
                        Err(why) => {
                            self.status_message = Some(why);
                            return Action::Redraw;
                        }
                    };
                    // Whom `@alias` names (K-4) join the To: (W-4): both are addressing.
                    for fp in to {
                        if let Ok(id) = vox_core::node::link::b32_decode(&fp, "member") {
                            if !self.to.contains(&id) {
                                self.to.push(id);
                            }
                        }
                    }
                    self.composer.clear();
                    let re = self.replying.take();
                    // Addressed or urgent, the message goes the one way a structured message is
                    // posted, as `vox room post --to … --urgent` posts it (ADR-028 W-4).
                    if !self.to.is_empty() || self.urgent {
                        let to = std::mem::take(&mut self.to);
                        let urgent = std::mem::replace(&mut self.urgent, false);
                        return Action::Dispatch(Command::PostAddressed {
                            channel_id,
                            text,
                            to,
                            urgent,
                            re,
                        });
                    }
                    return Action::Dispatch(match re {
                        Some(re) => Command::Reply {
                            channel_id,
                            re,
                            text,
                        },
                        None => Command::SendText { channel_id, text },
                    });
                }
                // Esc while replying drops the reply, not the room.
                KeyCode::Esc if self.replying.is_some() => {
                    self.replying = None;
                    return Action::Redraw;
                }
                _ => {}
            }
        }
        match key.code {
            KeyCode::Char(':') => {
                self.mode = Mode::CommandPalette(String::new());
                Action::Redraw
            }
            KeyCode::Char('t') if self.screen == Screen::ChannelList => {
                self.screen = Screen::Tunnels;
                self.settle(vm);
                Action::Redraw
            }
            // `t` on a member is the same trust action as `:trust` (ADR-028 K-5).
            KeyCode::Char('t')
                if self.screen == Screen::Channel && self.focus == Focus::Members =>
            {
                match self.selected_member {
                    Some(fp) => self.offer_trust(fp, vm),
                    None => Action::Redraw,
                }
            }
            KeyCode::Char('k') if self.screen == Screen::ChannelList => {
                self.screen = Screen::Keyring;
                Action::Redraw
            }
            KeyCode::Char('d') if self.screen == Screen::ChannelList => {
                self.screen = Screen::Decisions;
                Action::Redraw
            }
            // **An offer is accepted or dismissed where it waits** (ADR-028 K-16, K-18).
            KeyCode::Enter if self.screen == Screen::ChannelList && self.offer(vm).is_some() => {
                let member = self.offer(vm).map(|o| o.member);
                self.mode = Mode::Prompt(Prompt::new(PromptKind::AcceptOffer, member));
                Action::Redraw
            }
            KeyCode::Char('x')
                if self.screen == Screen::ChannelList && self.offer(vm).is_some() =>
            {
                match self.offer(vm).map(|o| o.member) {
                    Some(member) => Action::Dispatch(Command::DismissOffer { member }),
                    None => Action::Redraw,
                }
            }
            // The share flow (ADR-028 S-4): Enter previews the service selected, then offers it.
            KeyCode::Enter if self.screen == Screen::Serve => {
                if vm.serve_preview.is_some() {
                    self.screen = Screen::Channel;
                    return Action::Dispatch(Command::OfferService);
                }
                let (Some(channel_id), Some(l)) =
                    (self.serve_room, vm.listening.get(self.selected_listening))
                else {
                    return Action::Redraw;
                };
                Action::Dispatch(Command::PreviewServe {
                    channel_id,
                    port: l.port,
                    udp: Some(l.udp),
                })
            }
            KeyCode::Char('x') | KeyCode::Delete if self.screen == Screen::Tunnels => {
                self.close_selected_tunnel(vm)
            }
            // **A reply quotes one message** (ADR-028 R-9, #485): Ctrl-R replies to the message
            // selected, or the newest; the composer says which until it is sent. A control key, so
            // a message begun with the timeline focused is never turned into a reply by its first
            // letter.
            KeyCode::Char('r')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.screen == Screen::Channel =>
            {
                let newest = vm
                    .active
                    .as_ref()
                    .and_then(|c| c.timeline.last().map(|m| m.entry_hash));
                if let Some(re) = self.selected_message.or(newest) {
                    self.replying = Some(re);
                    self.focus = Focus::Composer;
                }
                Action::Redraw
            }
            KeyCode::Enter if self.screen == Screen::Channel && self.focus == Focus::Sessions => {
                let rows = vm
                    .active
                    .as_ref()
                    .map(|c| session_rows(&c.sessions, self.ended_open))
                    .unwrap_or_default();
                match rows.get(self.selected_session_row) {
                    Some(SessionRow::General) => self.show(Showing::General, vm),
                    Some(SessionRow::All) => self.show(Showing::All, vm),
                    Some(SessionRow::Session(i)) => {
                        match vm.active.as_ref().and_then(|c| c.sessions.get(*i)) {
                            Some(x) => self.show(Showing::Session(x.node, x.id.clone()), vm),
                            None => Action::Redraw,
                        }
                    }
                    Some(SessionRow::Ended(_)) => {
                        self.ended_open = !self.ended_open;
                        Action::Redraw
                    }
                    None => Action::Redraw,
                }
            }
            // In a Session, a driver answers the request on the selected line: `a` approves, `r`
            // rejects, a number picks an option of a one-question question (ADR-029 DR-1.4, 1.5).
            KeyCode::Char(c @ ('a' | 'r' | '1'..='9'))
                if self.screen == Screen::Channel
                    && self.focus == Focus::Timeline
                    && matches!(self.showing, Showing::Session(..)) =>
            {
                let Some(x) = showing_session(self, vm).filter(|x| x.can_drive) else {
                    return Action::Redraw;
                };
                let Some(line) = self
                    .selected_session_line
                    .and_then(|i| vm.active.as_ref()?.session_lines.get(i))
                else {
                    return Action::Redraw;
                };
                let act = match (line.waiting, c) {
                    (Some(Waiting::Approval), 'a') => DriveAct::Approve(line.reference.clone()),
                    (Some(Waiting::Approval), 'r') => {
                        DriveAct::Reject(line.reference.clone(), None)
                    }
                    (Some(Waiting::Question), '1'..='9') if line.questions.len() == 1 => {
                        DriveAct::Answer(
                            line.reference.clone(),
                            vec![(line.questions[0].clone(), c.to_string())],
                        )
                    }
                    _ => return Action::Redraw,
                };
                match self.active_channel_id(vm) {
                    Some(channel_id) => Action::Dispatch(Command::Drive {
                        channel_id,
                        session: (x.node, x.id.clone()),
                        act,
                    }),
                    None => Action::Redraw,
                }
            }
            // In a Session, Enter or `d` on a line shows its Details, or hides them (ADR-029 SC-1).
            KeyCode::Enter | KeyCode::Char('d')
                if self.screen == Screen::Channel
                    && self.focus == Focus::Timeline
                    && matches!(self.showing, Showing::Session(..)) =>
            {
                if self.selected_session_line.is_some() {
                    self.details_open = !self.details_open;
                }
                Action::Redraw
            }
            // Enter on a reply jumps to the message it quotes.
            KeyCode::Enter if self.screen == Screen::Channel && self.focus == Focus::Timeline => {
                self.jump_to_quote(vm);
                Action::Redraw
            }
            KeyCode::Tab if self.screen == Screen::Channel => {
                self.focus = self.focus.next();
                // The Shared pane is there only when something is shared.
                if self.focus == Focus::Shared
                    && vm.active.as_ref().is_none_or(|c| c.shared.is_empty())
                {
                    self.focus = self.focus.next();
                }
                // A Session has a composer only for a driver (ADR-029 DR-1, CL-3).
                if self.focus == Focus::Composer
                    && matches!(self.showing, Showing::Session(..))
                    && !showing_session(self, vm).is_some_and(|x| x.can_drive)
                {
                    self.focus = self.focus.next();
                }
                Action::Redraw
            }
            KeyCode::Char('y') if self.screen == Screen::Channel && self.focus == Focus::Shared => {
                match vm
                    .active
                    .as_ref()
                    .and_then(|c| c.shared.get(self.selected_share))
                {
                    Some(s) if !s.copy.is_empty() => Action::Copy(s.copy.clone()),
                    _ => Action::Redraw,
                }
            }
            KeyCode::Esc => {
                // Out of the share flow's preview, then out of the flow, back to the room.
                if self.screen == Screen::Serve {
                    if vm.serve_preview.is_some() {
                        return Action::Dispatch(Command::CancelServe);
                    }
                    self.screen = Screen::Channel;
                    return Action::Redraw;
                }
                if self.screen == Screen::Channel {
                    self.screen = Screen::ChannelList;
                    self.selected_message = None;
                    self.replying = None;
                    return Action::Dispatch(Command::SelectChannel { channel_id: None });
                }
                if matches!(
                    self.screen,
                    Screen::Tunnels | Screen::Keyring | Screen::Decisions
                ) {
                    self.screen = Screen::ChannelList;
                }
                Action::Redraw
            }
            KeyCode::Enter if self.screen == Screen::ChannelList => self.open_selected(vm),
            KeyCode::Up => {
                self.move_selection(vm, -1);
                Action::Redraw
            }
            KeyCode::Down => {
                self.move_selection(vm, 1);
                Action::Redraw
            }
            KeyCode::PageUp if self.screen == Screen::Channel => {
                self.timeline_scroll = self.timeline_scroll.saturating_add(TIMELINE_PAGE);
                Action::Redraw
            }
            KeyCode::PageDown if self.screen == Screen::Channel => {
                self.timeline_scroll = self.timeline_scroll.saturating_sub(TIMELINE_PAGE);
                Action::Redraw
            }
            KeyCode::End if self.screen == Screen::Channel => {
                self.timeline_scroll = 0;
                self.selected_message = None;
                Action::Redraw
            }
            _ => Action::Redraw,
        }
    }

    /// Enter / `:open` on the channel list: an **open** channel goes on screen
    /// (and the core is told which one is active); a **closed** channel needs its
    /// passphrase first (double-lock), so the masked prompt opens instead.
    fn open_selected(&mut self, vm: &ViewModel) -> Action {
        let Some(summary) = vm.channels.get(self.selected_channel) else {
            return Action::Redraw;
        };
        if summary.open {
            self.screen = Screen::Channel;
            self.focus = Focus::Timeline;
            self.selected_member = None;
            self.selected_share = 0;
            self.timeline_scroll = 0;
            self.selected_message = None;
            self.replying = None;
            Action::Dispatch(Command::SelectChannel {
                channel_id: Some(summary.channel_id),
            })
        } else {
            self.mode = Mode::Prompt(Prompt::new(
                PromptKind::OpenChannel,
                Some(summary.channel_id),
            ));
            Action::Redraw
        }
    }

    /// Whether the key being typed now goes into a secret field: the loop then reads it past the
    /// terminal library, which keeps whatever it reads in a buffer of its own (V210-94).
    #[must_use]
    pub fn typing_a_secret(&self) -> bool {
        matches!(&self.mode, Mode::Prompt(p) if p.kind.is_secret(p.step))
    }

    /// Open a masked prompt (also used by the loop for onboarding: no identity ⇒
    /// create; not attached ⇒ attach).
    pub fn start_prompt(&mut self, kind: PromptKind, target: Option<Digest32>) {
        self.mode = Mode::Prompt(Prompt::new(kind, target));
    }

    fn on_prompt_key(&mut self, key: KeyEvent) -> Action {
        let Mode::Prompt(ref mut p) = self.mode else {
            return Action::Redraw;
        };
        match key.code {
            KeyCode::Esc => {
                // Dropping the prompt zeroizes every field.
                self.mode = Mode::Normal;
                Action::Redraw
            }
            KeyCode::Char(c) => {
                // Never past the field's own buffer: see `PROMPT_FIELD_CAPACITY`.
                if let Some(f) = p.fields.get_mut(p.step) {
                    if f.len() + c.len_utf8() <= f.capacity() {
                        f.push(c);
                    }
                }
                Action::Redraw
            }
            KeyCode::Backspace => {
                if let Some(f) = p.fields.get_mut(p.step) {
                    f.pop();
                }
                Action::Redraw
            }
            KeyCode::Enter => {
                if p.step + 1 < p.fields.len() {
                    p.step += 1;
                    return Action::Redraw;
                }
                self.submit_prompt()
            }
            _ => Action::Redraw,
        }
    }

    /// Validate and turn the finished prompt into a [`Command`]. A confirm
    /// mismatch keeps the prompt open at the passphrase step with the secret
    /// fields cleared; the mismatch is reported through the status line without
    /// echoing anything typed.
    fn submit_prompt(&mut self) -> Action {
        let Mode::Prompt(p) = std::mem::replace(&mut self.mode, Mode::Normal) else {
            return Action::Redraw;
        };
        let secret = |s: &Zeroizing<String>| SecretString::from(s.as_str().to_owned());
        match p.kind {
            PromptKind::AcceptOffer => {
                let Some(target) = p.target else {
                    return Action::Redraw;
                };
                let petname = p.fields[0].trim().to_owned();
                if petname.is_empty() {
                    // A node in the keyring always has a name (ADR-028 K-3).
                    self.status_message = Some("a name is required: what do you call them?".into());
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::AcceptOffer, Some(target)));
                    return Action::Redraw;
                }
                let drive = match p.fields[1].trim().to_ascii_lowercase().as_str() {
                    "" | "r" | "read" => false,
                    "d" | "drive" | "read + drive" => true,
                    other => {
                        self.status_message = Some(format!(
                            "{other:?} is neither: r for read, d for read + drive"
                        ));
                        let mut again = Prompt::new(PromptKind::AcceptOffer, Some(target));
                        again.fields[0] = Zeroizing::new(petname);
                        again.step = 1;
                        self.mode = Mode::Prompt(again);
                        return Action::Redraw;
                    }
                };
                Action::Dispatch(Command::AcceptOffer {
                    target,
                    petname,
                    drive,
                    identity_passphrase: secret(&p.fields[2]),
                })
            }
            PromptKind::Trust => {
                let Some(target) = p.target else {
                    return Action::Redraw;
                };
                let theirs = vox_core::node::link::b32_encode(&target);
                let given = crate::ident::typed_fingerprint(&p.fields[0]);
                // **A mismatch is its own outcome** (ADR-028 K-5): nothing is added, and both are
                // shown, so the person sees that they differ.
                if given != theirs {
                    self.status_message = Some(format!(
                        "not trusted: the fingerprint you were given is not this node's — do not \
                         trust it; ask them for theirs again another way. given: {} · this node: \
                         {}",
                        vox_text::fingerprint::grouped(&given),
                        vox_text::fingerprint::grouped(&theirs)
                    ));
                    return Action::Redraw;
                }
                let petname = p.fields[1].trim().to_owned();
                if petname.is_empty() {
                    // A node in the keyring always has a name (ADR-028 K-3).
                    self.status_message = Some("a name is required: what do you call them?".into());
                    let mut again = Prompt::new(PromptKind::Trust, Some(target));
                    again.fields[0] = Zeroizing::new(p.fields[0].as_str().to_owned());
                    again.step = 1;
                    self.mode = Mode::Prompt(again);
                    return Action::Redraw;
                }
                Action::Dispatch(Command::Trust {
                    target,
                    petname,
                    identity_passphrase: secret(&p.fields[2]),
                })
            }
            PromptKind::Attach => Action::Dispatch(Command::Attach {
                passphrase: secret(&p.fields[0]),
            }),
            PromptKind::OpenChannel => match p.target {
                Some(channel_id) => Action::Dispatch(Command::OpenChannel {
                    channel_id,
                    passphrase: secret(&p.fields[0]),
                }),
                None => Action::Redraw,
            },
            PromptKind::CreateIdentity => {
                // **Every node has a passphrase** (ADR-028 K-11): an empty one is asked again.
                if p.fields[0].is_empty() {
                    self.status_message = Some(
                        "every node has an identity passphrase; an empty one is refused — type one"
                            .into(),
                    );
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::CreateIdentity, None));
                    return Action::Redraw;
                }
                if p.fields[0].as_str() != p.fields[1].as_str() {
                    self.status_message = Some("passphrases do not match — try again".into());
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::CreateIdentity, None));
                    return Action::Redraw;
                }
                Action::Dispatch(Command::CreateIdentity {
                    passphrase: secret(&p.fields[0]),
                })
            }
            PromptKind::CreateChannel => {
                // One DNS label, as every member sees it (ADR-028 R-1, R-2): said before the
                // passphrase is checked.
                let name = match vox_core::governance::name::room_name(&p.fields[0]) {
                    Ok(name) => name,
                    Err(why) => {
                        self.status_message = Some(why);
                        self.mode = Mode::Prompt(Prompt::new(PromptKind::CreateChannel, None));
                        return Action::Redraw;
                    }
                };
                if p.fields[1].as_str() != p.fields[2].as_str() {
                    self.status_message = Some("passphrases do not match — try again".into());
                    let mut again = Prompt::new(PromptKind::CreateChannel, None);
                    again.fields[0] = Zeroizing::new(name);
                    again.step = 1;
                    self.mode = Mode::Prompt(again);
                    return Action::Redraw;
                }
                self.status_message = no_passphrase_note(&p.fields[1]);
                Action::Dispatch(Command::CreateChannel {
                    name,
                    passphrase: secret(&p.fields[1]),
                })
            }
            PromptKind::JoinChannel => {
                let link = p.fields[0].trim().to_owned();
                if link.is_empty() {
                    self.status_message = Some("a room link is required".into());
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::JoinChannel, None));
                    return Action::Redraw;
                }
                self.status_message = no_passphrase_note(&p.fields[1]);
                Action::Dispatch(Command::Join {
                    link,
                    passphrase: secret(&p.fields[1]),
                })
            }
            PromptKind::RenameRoom => {
                let Some(channel_id) = p.target else {
                    return Action::Redraw;
                };
                match vox_core::governance::name::room_name(&p.fields[0]) {
                    Ok(name) => Action::Dispatch(Command::RenameRoom { channel_id, name }),
                    Err(why) => {
                        self.status_message = Some(why);
                        self.mode = Mode::Prompt(Prompt::new(PromptKind::RenameRoom, p.target));
                        Action::Redraw
                    }
                }
            }
            PromptKind::LeaveRoom | PromptKind::EndRoom => {
                let leave = p.kind == PromptKind::LeaveRoom;
                let word = if leave { "leave" } else { "end" };
                match p.target {
                    Some(channel_id) if p.fields[0].trim() == word => Action::Dispatch(if leave {
                        Command::LeaveRoom { channel_id }
                    } else {
                        Command::EndRoom { channel_id }
                    }),
                    _ => {
                        self.status_message =
                            Some(format!("nothing was done: type {word} to {word} the room"));
                        Action::Redraw
                    }
                }
            }
        }
    }

    /// Open the trust prompt on `fp`, unless it is this node or already in the keyring.
    fn offer_trust(&mut self, fp: Digest32, vm: &ViewModel) -> Action {
        let me = vm
            .active
            .as_ref()
            .and_then(|c| c.members.iter().find(|m| m.id == fp))
            .is_some_and(|m| m.trust == crate::viewmodel::Trust::You);
        if me {
            self.status_message = Some("that is this node".into());
            return Action::Redraw;
        }
        if vm.keyring.iter().any(|(id, _)| *id == fp) {
            self.status_message = Some(format!(
                "{} is already in your keyring",
                crate::ident::name_in(&vm.keyring, &fp)
            ));
            return Action::Redraw;
        }
        self.mode = Mode::Prompt(Prompt::new(PromptKind::Trust, Some(fp)));
        Action::Redraw
    }

    /// Close the tunnel selected in the tunnel list (V030-11).
    fn close_selected_tunnel(&mut self, vm: &ViewModel) -> Action {
        match self
            .selected_tunnel
            .filter(|id| vm.tunnels.iter().any(|t| t.id == *id))
        {
            Some(id) => Action::Dispatch(Command::CloseTunnel { id }),
            None => {
                self.status_message = Some("no tunnel is selected".into());
                Action::Redraw
            }
        }
    }

    /// Up/Down: the channel list's selection, or on a channel screen, the timeline's scroll while
    /// it has focus and the member selection otherwise.
    /// **Selecting a quote jumps to it** (ADR-028 R-9, #485): the message the selected reply
    /// quotes is selected and scrolled to.
    fn jump_to_quote(&mut self, vm: &ViewModel) {
        let Some(timeline) = vm.active.as_ref().map(|c| &c.timeline) else {
            return;
        };
        let Some(quote) = self
            .selected_message
            .and_then(|h| timeline.iter().find(|m| m.entry_hash == h))
            .and_then(|m| m.quote.as_ref())
        else {
            return;
        };
        if timeline.iter().any(|m| m.entry_hash == quote.entry_hash) {
            self.selected_message = Some(quote.entry_hash);
            self.reveal_selected = true;
        } else {
            self.status_message = Some("the quoted message is not in this room yet".into());
        }
    }

    /// The offer selected in the sidebar, while it is still offered.
    #[must_use]
    pub fn offer<'a>(&self, vm: &'a ViewModel) -> Option<&'a vox_core::node::api::Offer> {
        let member = self.selected_offer?;
        vm.offers.iter().find(|o| o.member == member)
    }

    fn move_selection(&mut self, vm: &ViewModel, delta: isize) {
        let step =
            |cur: usize, len: usize| (cur as isize + delta).rem_euclid(len as isize) as usize;
        match self.screen {
            // The offers first, then the rooms: one list, as the sidebar draws it.
            Screen::ChannelList => {
                let offers = vm.offers.len();
                let len = offers + vm.channels.len();
                if len > 0 {
                    let cur = match self.offer(vm) {
                        Some(o) => vm
                            .offers
                            .iter()
                            .position(|x| x.member == o.member)
                            .unwrap_or(0),
                        None => offers + self.selected_channel,
                    };
                    let next = step(cur, len);
                    if next < offers {
                        self.selected_offer = Some(vm.offers[next].member);
                    } else {
                        self.selected_offer = None;
                        self.selected_channel = next - offers;
                        self.selected_room =
                            vm.channels.get(self.selected_channel).map(|c| c.channel_id);
                    }
                }
            }
            Screen::Keyring => {}
            Screen::Serve => {
                if !vm.listening.is_empty() && vm.serve_preview.is_none() {
                    self.selected_listening = step(self.selected_listening, vm.listening.len());
                }
            }
            Screen::Tunnels => {
                if vm.tunnels.is_empty() {
                    return;
                }
                let cur = self
                    .selected_tunnel
                    .and_then(|id| vm.tunnels.iter().position(|t| t.id == id))
                    .unwrap_or(0);
                self.selected_tunnel = Some(vm.tunnels[step(cur, vm.tunnels.len())].id);
            }
            // The record is read newest first, and nothing in it is acted on.
            Screen::Decisions => {}
            Screen::Channel if self.focus == Focus::Shared => {
                let len = vm.active.as_ref().map_or(0, |c| c.shared.len());
                if len > 0 {
                    self.selected_share = step(self.selected_share.min(len - 1), len);
                }
            }
            Screen::Channel if self.focus == Focus::Sessions => {
                let len = vm
                    .active
                    .as_ref()
                    .map_or(0, |c| session_rows(&c.sessions, self.ended_open).len());
                if len > 0 {
                    self.selected_session_row = step(self.selected_session_row.min(len - 1), len);
                }
            }
            // In a Session, Up selects an older line and Down a newer one; past the newest follows
            // again (ADR-029 SC-1).
            Screen::Channel
                if self.focus == Focus::Timeline
                    && matches!(self.showing, Showing::Session(..)) =>
            {
                let len = vm.active.as_ref().map_or(0, |c| c.session_lines.len());
                self.details_open = false;
                self.selected_session_line = match (self.selected_session_line, delta < 0) {
                    (_, _) if len == 0 => None,
                    (None, true) => Some(len - 1),
                    (None, false) => None,
                    (Some(i), true) => Some(i.min(len - 1).saturating_sub(1)),
                    (Some(i), false) => Some(i + 1).filter(|n| *n < len),
                };
            }
            Screen::Channel if self.focus == Focus::Timeline => {
                // Up selects an older message, Down a newer one; past the newest follows again.
                let Some(timeline) = vm.active.as_ref().map(|c| &c.timeline) else {
                    return;
                };
                let at = self
                    .selected_message
                    .and_then(|h| timeline.iter().position(|m| m.entry_hash == h));
                let next = match (at, delta < 0) {
                    (None, true) => timeline.len().checked_sub(1),
                    (None, false) => None,
                    (Some(i), true) => Some(i.saturating_sub(1)),
                    (Some(i), false) => Some(i + 1).filter(|n| *n < timeline.len()),
                };
                self.selected_message = next.map(|i| timeline[i].entry_hash);
                if self.selected_message.is_none() {
                    self.timeline_scroll = 0;
                }
                self.reveal_selected = true;
            }
            Screen::Channel => {
                let Some(members) = vm.active.as_ref().map(|c| &c.members) else {
                    return;
                };
                if members.is_empty() {
                    return;
                }
                // From where the selected member is now, wherever a re-sort put it.
                let cur = self
                    .selected_member
                    .and_then(|id| members.iter().position(|m| m.id == id))
                    .unwrap_or(0);
                self.selected_member = Some(members[step(cur, members.len())].id);
            }
        }
    }

    fn on_palette_key(&mut self, key: KeyEvent, vm: &ViewModel) -> Action {
        let Mode::CommandPalette(ref mut buf) = self.mode else {
            return Action::Redraw;
        };
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                Action::Redraw
            }
            KeyCode::Char(c) => {
                buf.push(c);
                Action::Redraw
            }
            KeyCode::Backspace => {
                buf.pop();
                Action::Redraw
            }
            KeyCode::Enter => {
                let line = buf.clone();
                self.mode = Mode::Normal;
                match parse_command(&line, self, vm) {
                    Some(Parsed::Core(cmd)) => Action::Dispatch(cmd),
                    Some(Parsed::Quit) => Action::Quit,
                    Some(Parsed::Nav(Nav::Tunnels)) => {
                        self.screen = Screen::Tunnels;
                        self.settle(vm);
                        Action::Redraw
                    }
                    Some(Parsed::CloseTunnel) => self.close_selected_tunnel(vm),
                    Some(Parsed::Serve(channel_id, port)) => {
                        self.screen = Screen::Serve;
                        self.serve_room = Some(channel_id);
                        self.selected_listening = 0;
                        match port.map(|p| p.parse::<u16>()) {
                            None => Action::Dispatch(Command::ProbeListening),
                            Some(Ok(port)) => Action::Dispatch(Command::PreviewServe {
                                channel_id,
                                port,
                                udp: None,
                            }),
                            Some(Err(_)) => {
                                self.status_message =
                                    Some("`:serve` takes a port, or nothing for the list".into());
                                Action::Dispatch(Command::ProbeListening)
                            }
                        }
                    }
                    Some(Parsed::Confirm(kind, channel_id)) => {
                        self.mode = Mode::Prompt(Prompt::new(kind, Some(channel_id)));
                        Action::Redraw
                    }
                    Some(Parsed::Trust(fp)) => self.offer_trust(fp, vm),
                    Some(Parsed::Refused(why)) => {
                        self.status_message = Some(why);
                        Action::Redraw
                    }
                    Some(Parsed::Send(channel_id, text)) => {
                        if self.to.is_empty() && !self.urgent {
                            Action::Dispatch(Command::SendText { channel_id, text })
                        } else {
                            let to = std::mem::take(&mut self.to);
                            let urgent = std::mem::replace(&mut self.urgent, false);
                            Action::Dispatch(Command::PostAddressed {
                                channel_id,
                                text,
                                to,
                                urgent,
                                re: None,
                            })
                        }
                    }
                    Some(Parsed::Attach(channel_id, path)) => {
                        // The composer's words are the note, its To: and urgent the share's: one
                        // announcement carries all of them (F-1), and the composer is spent.
                        let note = std::mem::take(&mut self.composer).trim().to_owned();
                        let to = std::mem::take(&mut self.to);
                        let urgent = std::mem::replace(&mut self.urgent, false);
                        Action::Dispatch(Command::ShareFile {
                            channel_id,
                            path,
                            note,
                            to,
                            urgent,
                        })
                    }
                    Some(Parsed::Show(showing)) => self.show(showing, vm),
                    Some(Parsed::Drive(channel_id, session, act)) => {
                        // A file's note is the composer's words: spent with it.
                        if matches!(act, DriveAct::File(..)) {
                            self.composer.clear();
                        }
                        Action::Dispatch(Command::Drive {
                            channel_id,
                            session,
                            act,
                        })
                    }
                    Some(Parsed::To(names)) => {
                        self.set_to(&names, vm);
                        Action::Redraw
                    }
                    Some(Parsed::Urgent) => {
                        self.urgent = !self.urgent;
                        self.status_message = Some(
                            if self.urgent {
                                "the next message is urgent"
                            } else {
                                "the next message is not urgent"
                            }
                            .into(),
                        );
                        Action::Redraw
                    }
                    Some(Parsed::Nav(nav)) => self.apply_nav(nav, vm),
                    Some(Parsed::Prompt(kind, name)) => {
                        // A rename is of the room on screen.
                        let target = (kind == PromptKind::RenameRoom)
                            .then(|| self.active_channel_id(vm))
                            .flatten();
                        let mut p = Prompt::new(kind, target);
                        let named = name.is_some();
                        if let Some(n) = name {
                            p.fields[0] = Zeroizing::new(n);
                            p.step = 1;
                        }
                        // Nothing left to ask once the name is given (`:rename home`): it is
                        // made, as typed (ADR-028 K-11: a rename asks for no passphrase).
                        let done = named && p.step >= p.fields.len();
                        self.mode = Mode::Prompt(p);
                        if done {
                            return self.submit_prompt();
                        }
                        Action::Redraw
                    }
                    None => {
                        self.status_message = Some("unknown command".into());
                        Action::Redraw
                    }
                }
            }
            _ => Action::Redraw,
        }
    }

    /// Show General, All or one Session; the composer is not a Session's (ADR-029 DR-1).
    fn show(&mut self, showing: Showing, vm: &ViewModel) -> Action {
        if matches!(showing, Showing::Session(..)) && self.focus == Focus::Composer {
            self.focus = Focus::Timeline;
        }
        self.composer.clear();
        self.selected_message = None;
        self.selected_session_line = None;
        self.details_open = false;
        self.timeline_scroll = 0;
        self.replying = None;
        let session = match &showing {
            Showing::Session(node, id) => Some((*node, id.clone())),
            Showing::General | Showing::All => None,
        };
        self.showing = showing;
        // The core reads the Session's entries while it is shown (SC-1).
        match self.active_channel_id(vm) {
            Some(channel_id) => Action::Dispatch(Command::ShowSession {
                channel_id,
                session,
            }),
            None => Action::Redraw,
        }
    }

    /// Set the composer's To: from `names`, this node's names for members of the room or the
    /// start of their fingerprints (as `vox room post --to` takes them); none clears it. A name
    /// that is no member, or that names more than one, is refused with a sentence, and changes
    /// nothing: the next message goes nowhere it was not meant to.
    fn set_to(&mut self, names: &str, vm: &ViewModel) {
        let Some(c) = vm.active.as_ref() else {
            return;
        };
        let mut to = Vec::new();
        for name in names.split([',', ' ']).filter(|n| !n.is_empty()) {
            let found: Vec<&crate::viewmodel::MemberView> = c
                .members
                .iter()
                .filter(|m| {
                    m.trust != crate::viewmodel::Trust::You
                        && (m.nickname == name
                            || (name.len() >= 8
                                && vox_core::node::link::b32_encode(&m.id).starts_with(name)))
                })
                .collect();
            match found[..] {
                [m] => {
                    if !to.contains(&m.id) {
                        to.push(m.id);
                    }
                }
                [] => {
                    self.status_message = Some(format!(
                        "no member of this room is named {name}: the next message's To: is \
                         unchanged"
                    ));
                    return;
                }
                _ => {
                    self.status_message = Some(format!(
                        "{name} names {} members of this room; give more of a fingerprint: the \
                         next message's To: is unchanged",
                        found.len()
                    ));
                    return;
                }
            }
        }
        self.to = to;
        self.status_message = Some(if self.to.is_empty() {
            "the next message is to the room".into()
        } else {
            format!("the next message is to {}", names.trim())
        });
    }

    /// Apply a navigation action (the typed-command equivalents of the chord
    /// navigation, so every action is reachable by command — ADR-015 a11y).
    fn apply_nav(&mut self, nav: Nav, vm: &ViewModel) -> Action {
        match nav {
            Nav::Open => {
                if self.screen == Screen::ChannelList {
                    return self.open_selected(vm);
                }
            }
            Nav::Back => {
                if self.screen == Screen::Channel {
                    self.screen = Screen::ChannelList;
                    self.selected_message = None;
                    self.replying = None;
                    return Action::Dispatch(Command::SelectChannel { channel_id: None });
                }
            }
            Nav::FocusNext => {
                if self.screen == Screen::Channel {
                    self.focus = self.focus.next();
                }
            }
            Nav::Up => self.move_selection(vm, -1),
            Nav::Down => self.move_selection(vm, 1),
            Nav::Tunnels => {
                self.screen = Screen::Tunnels;
                self.settle(vm);
            }
            Nav::Keyring => self.screen = Screen::Keyring,
            Nav::Decisions => self.screen = Screen::Decisions,
        }
        Action::Redraw
    }

    /// The channelID of the active channel, if one is open.
    #[must_use]
    pub fn active_channel_id(&self, vm: &ViewModel) -> Option<Digest32> {
        vm.active.as_ref().map(|c| c.channel_id)
    }
}

/// A navigation action issuable by a typed command (the command-equivalents of the
/// chord navigation, ADR-015 a11y "every action reachable by typed command").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nav {
    /// Open the selected channel.
    Open,
    /// Return to the channel list.
    Back,
    /// Cycle focus to the next pane.
    FocusNext,
    /// Move selection up.
    Up,
    /// Move selection down.
    Down,
    /// Show the live tunnels (V030-11).
    Tunnels,
    /// Show the trust keyring (ADR-028 W-1).
    Keyring,
    /// Show what this node decided (ADR-028 D-3).
    Decisions,
}

/// The result of parsing a `:`-command line.
#[derive(Debug)]
pub enum Parsed {
    /// A core command to dispatch.
    Core(Command),
    /// Quit the application.
    Quit,
    /// A UI navigation action.
    Nav(Nav),
    /// Open a masked prompt (with an optional prefilled non-secret first field).
    Prompt(PromptKind, Option<String>),
    /// Close the tunnel selected in the tunnel list (V030-11).
    CloseTunnel,
    /// Ask the person to confirm a change of access to a room, saying what it does (ADR-028 E-5).
    Confirm(PromptKind, Digest32),
    /// Refused, saying why in the status line.
    Refused(String),
    /// Share a service listening here into this room (ADR-028 S-4): the list, or the one on the
    /// port given.
    Serve(Digest32, Option<String>),
    /// Open the trust prompt on this node (ADR-028 K-5).
    Trust(Digest32),
    /// Send a message to this room, with the composer's To: and urgent (ADR-028 W-4).
    Send(Digest32, String),
    /// Share the file or folder at this path in the room, from the composer (ADR-028 F-1).
    Attach(Digest32, String),
    /// Set the composer's To: from these names (W-4); none clears it.
    To(String),
    /// Switch the composer's urgent on or off (W-4).
    Urgent,
    /// Show General, All or one Session in the room's timeline (ADR-029 CL-2).
    Show(Showing),
    /// Drive the Session on screen (ADR-029 DR-1).
    Drive(Digest32, (Digest32, String), DriveAct),
}

/// The Session the room's timeline shows, while it shows one that the room still lists.
#[must_use]
pub fn showing_session<'a>(ui: &UiState, vm: &'a ViewModel) -> Option<&'a SessionView> {
    let Showing::Session(node, id) = &ui.showing else {
        return None;
    };
    vm.active
        .as_ref()?
        .sessions
        .iter()
        .find(|x| x.node == *node && x.id == *id)
}

/// The one Session `name` names: its whole id, the first 8 or more characters of it, or its
/// name. One that names none, or more than one, is refused, never guessed (ADR-029 DR-5).
fn find_session<'a>(sessions: &'a [SessionView], name: &str) -> Result<&'a SessionView, String> {
    if name.is_empty() {
        return Err("which Session? :session <name or short id>".into());
    }
    let by_id: Vec<&SessionView> = sessions
        .iter()
        .filter(|x| x.id == name || (name.len() >= 8 && x.id.starts_with(name)))
        .collect();
    let found = if by_id.is_empty() {
        sessions
            .iter()
            .filter(|x| x.name.as_deref() == Some(name))
            .collect()
    } else {
        by_id
    };
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("no Session in this room is named {name}")),
        many => Err(format!(
            "more than one Session is named {name}: {}",
            many.iter()
                .map(|x| x.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Parse a `:`-command line, resolving selection-relative targets from `ui`/`vm`.
/// Returns `None` for an empty/unknown command or one missing a required target.
///
/// Per ADR-015 every action MUST be reachable by a typed command. Channel-
/// independent verbs work anywhere (incl. the channel list):
/// - `quit` / `q` — exit
/// - `open` / `back` / `focus` / `up` / `down` — navigation
///
/// Channel-scoped verbs require an active channel:
/// - `send <text…>`, `link`, `rename [name]` (opens a prompt for the identity passphrase).
///
/// **Create / join / attach / init are not one-line palette commands.** They require
/// a passphrase, which ADR-015 mandates be entered through a **masked** prompt and
/// shared out-of-band — never echoed on the palette line or stored in a status
/// string. The verbs `init`, `attach`, `new <name>` therefore *open the prompt*;
/// the secret is typed there — and so does `join`, whose prompt takes the `vox://`
/// link in the clear (it carries no secret) and the passphrase masked. This is a
/// security-driven exception to "one-line command", not a chord-only path. Every *non-secret* action is reachable here by
/// a typed command. `close` closes the active channel (wipes its SEK).
pub fn parse_command(line: &str, ui: &UiState, vm: &ViewModel) -> Option<Parsed> {
    let line = line.trim();
    let (verb, rest) = match line.split_once(char::is_whitespace) {
        Some((v, r)) => (v, r.trim()),
        None => (line, ""),
    };
    // Channel-independent verbs first — these must not require an open channel.
    match verb {
        "quit" | "q" => return Some(Parsed::Quit),
        "attach" => return Some(Parsed::Prompt(PromptKind::Attach, None)),
        // **One node per client** (ADR-028 E-4, #470): this TUI acts only as the node it was
        // opened with. Another node is a member of the rooms it shares with this one, never a
        // node to act as.
        "node" => {
            return Some(Parsed::Refused(format!(
                "this window acts only as node {}; to act as {}, open `vox tui --node {}`",
                vm.node,
                if rest.is_empty() { "another" } else { rest },
                if rest.is_empty() { "NAME" } else { rest },
            )))
        }
        // The one trust action (ADR-028 K-5): a member of the room on screen, by the start of its
        // fingerprint as the screen offers it, or by name.
        "trust" => {
            let Some(room) = vm.active.as_ref() else {
                return Some(Parsed::Refused(
                    "open the room the node is in, then :trust it".into(),
                ));
            };
            if rest.is_empty() {
                return Some(Parsed::Refused(
                    ":trust takes the start of the node's fingerprint, as the screen shows it"
                        .into(),
                ));
            }
            let members: Vec<Digest32> = room.members.iter().map(|m| m.id).collect();
            return Some(
                match crate::ident::resolve_member(rest, &members, &vm.keyring) {
                    Ok(fp) => Parsed::Trust(fp),
                    Err(why) => Parsed::Refused(why),
                },
            );
        }
        "init" => return Some(Parsed::Prompt(PromptKind::CreateIdentity, None)),
        "new" if !rest.is_empty() => {
            return Some(Parsed::Prompt(
                PromptKind::CreateChannel,
                Some(rest.to_owned()),
            ))
        }
        "new" => return Some(Parsed::Prompt(PromptKind::CreateChannel, None)),
        // Joining needs the channel passphrase, so like `new` it opens the masked
        // prompt (the link itself is not secret and is typed there in the clear).
        "join" => return Some(Parsed::Prompt(PromptKind::JoinChannel, None)),
        "open" => return Some(Parsed::Nav(Nav::Open)),
        "back" => return Some(Parsed::Nav(Nav::Back)),
        "focus" => return Some(Parsed::Nav(Nav::FocusNext)),
        "up" => return Some(Parsed::Nav(Nav::Up)),
        "down" => return Some(Parsed::Nav(Nav::Down)),
        "tunnels" => return Some(Parsed::Nav(Nav::Tunnels)),
        "keyring" => return Some(Parsed::Nav(Nav::Keyring)),
        "decisions" => return Some(Parsed::Nav(Nav::Decisions)),
        // On the tunnel list, `close` closes the selected tunnel, not a channel.
        "close" if ui.screen == Screen::Tunnels => return Some(Parsed::CloseTunnel),
        _ => {}
    }
    // Channel-scoped verbs require an active channel.
    let channel = ui.active_channel_id(vm)?;
    // Interrupting or stopping is driving the Session on screen (DR-1.3); without drive it is
    // refused (CL-3), and outside a Session there is nothing to send it to.
    if let (Showing::Session(..), "interrupt" | "stop" | "approve" | "reject" | "answer") =
        (&ui.showing, verb)
    {
        let Some(x) = showing_session(ui, vm) else {
            return Some(Parsed::Refused("this Session is no longer listed".into()));
        };
        if !x.can_drive {
            return Some(Parsed::Refused(format!(
                "you cannot drive this Session: {} has not given you drive",
                x.node_alias
            )));
        }
        // `:approve`, `:reject` and `:answer` act on the oldest request still waiting.
        let lines = vm.active.as_ref().map_or(&[][..], |c| &c.session_lines[..]);
        let oldest = |w: Waiting| lines.iter().find(|l| l.waiting == Some(w));
        let act = match verb {
            "stop" => DriveAct::Stop,
            "interrupt" => DriveAct::Interrupt,
            "approve" | "reject" => {
                let Some(l) = oldest(Waiting::Approval) else {
                    return Some(Parsed::Refused(format!(
                        "no approval in {} waits on you",
                        x.label
                    )));
                };
                if verb == "approve" {
                    DriveAct::Approve(l.reference.clone())
                } else {
                    DriveAct::Reject(
                        l.reference.clone(),
                        Some(rest.to_owned()).filter(|w| !w.is_empty()),
                    )
                }
            }
            _ => {
                let Some(l) = oldest(Waiting::Question) else {
                    return Some(Parsed::Refused(format!(
                        "no question in {} waits on you",
                        x.label
                    )));
                };
                // One answer per question, in order, separated by `;`: an option's number or the
                // answer's text. A `;` always separates, so one question given two answers is
                // refused, never sent as the text "1; 2".
                let given: Vec<&str> = rest.split(';').map(str::trim).collect();
                if given.len() != l.questions.len() || given.iter().any(|g| g.is_empty()) {
                    return Some(Parsed::Refused(format!(
                        "not sent to {}: the question asks {} thing(s); answer each, separated by ;",
                        x.label,
                        l.questions.len()
                    )));
                }
                DriveAct::Answer(
                    l.reference.clone(),
                    l.questions
                        .iter()
                        .cloned()
                        .zip(given.into_iter().map(str::to_owned))
                        .collect(),
                )
            }
        };
        return Some(Parsed::Drive(channel, (x.node, x.id.clone()), act));
    }
    // In a Session, `:share <path>` sends the session a file, for a driver (ADR-029 DR-1.7): the
    // composer's words its note, as `:share` in a room takes them (ADR-028 F-1).
    if let (Showing::Session(..), "share") = (&ui.showing, verb) {
        if let Some(x) = showing_session(ui, vm) {
            if !x.can_drive {
                return Some(Parsed::Refused(format!(
                    "you cannot drive this Session: {} has not given you drive",
                    x.node_alias
                )));
            }
            if !rest.is_empty() {
                let note = Some(ui.composer.trim().to_owned()).filter(|n| !n.is_empty());
                return Some(Parsed::Drive(
                    channel,
                    (x.node, x.id.clone()),
                    DriveAct::File(rest.to_owned(), note),
                ));
            }
        }
    }
    // In a Session, the composer's verbs would write to the room, not the session: refused.
    if let (Showing::Session(..), "send" | "share") = (&ui.showing, verb) {
        let label = showing_session(ui, vm).map_or("this Session", |x| x.label.as_str());
        return Some(Parsed::Refused(format!(
            "not sent: this is {label}; :general writes to the room"
        )));
    }
    match verb {
        "general" => return Some(Parsed::Show(Showing::General)),
        "all" => return Some(Parsed::Show(Showing::All)),
        "session" => {
            let sessions = vm.active.as_ref().map_or(&[][..], |c| &c.sessions[..]);
            return Some(match find_session(sessions, rest) {
                Ok(x) => Parsed::Show(Showing::Session(x.node, x.id.clone())),
                Err(why) => Parsed::Refused(why),
            });
        }
        "send" if !rest.is_empty() => return Some(Parsed::Send(channel, rest.to_owned())),
        // Share a file or folder here, from the composer (F-1): its words the note. `share`, as
        // `vox share` is; `:attach` is the node's.
        "share" if !rest.is_empty() => return Some(Parsed::Attach(channel, rest.to_owned())),
        "to" => return Some(Parsed::To(rest.to_owned())),
        "urgent" => return Some(Parsed::Urgent),
        _ => {}
    }
    let cmd = match verb {
        "close" => Command::CloseChannel {
            channel_id: channel,
        },
        // Each says what it does and waits for the person to confirm it (ADR-028 E-5).
        "leave" => return Some(Parsed::Confirm(PromptKind::LeaveRoom, channel)),
        "end" => return Some(Parsed::Confirm(PromptKind::EndRoom, channel)),
        // The room's new name, filled in for the person to confirm: no passphrase follows
        // (ADR-028 K-11).
        "rename" => {
            return Some(Parsed::Prompt(
                PromptKind::RenameRoom,
                Some(rest.to_owned()).filter(|r| !r.is_empty()),
            ))
        }
        // Share a service listening here into this room (ADR-028 S-4): the list, or one port.
        "serve" if rest.is_empty() => return Some(Parsed::Serve(channel, None)),
        "serve" => return Some(Parsed::Serve(channel, Some(rest.to_owned()))),
        // The link is public; it can be produced by a one-line command.
        "link" => Command::Invite {
            channel_id: channel,
        },
        _ => return None,
    };
    Some(Parsed::Core(cmd))
}

/// The status line for a room passphrase left empty: it is accepted, and one is encouraged
/// (V030-36's room half; an identity passphrase is never empty, ADR-028 K-11).
fn no_passphrase_note(passphrase: &Zeroizing<String>) -> Option<String> {
    passphrase
        .is_empty()
        .then(|| "no passphrase; going on without one. A passphrase is encouraged.".into())
}
