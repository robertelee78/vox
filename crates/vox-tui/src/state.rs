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

use crate::viewmodel::{Command, ViewModel};

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
            PromptKind::RenameRoom => &["new room name", "identity passphrase"],
        }
    }

    /// Whether field `i` is secret (masked while typing, zeroized after).
    #[must_use]
    pub fn is_secret(self, i: usize) -> bool {
        match self {
            // A room's name is not a secret.
            PromptKind::CreateChannel | PromptKind::RenameRoom => i != 0,
            // The link is not; only the passphrase.
            PromptKind::JoinChannel => i == 1,
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
}

impl Focus {
    /// The next pane in the `Tab` cycle.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Focus::Timeline => Focus::Composer,
            Focus::Composer => Focus::Members,
            Focus::Members => Focus::Shared,
            Focus::Shared => Focus::Timeline,
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
    /// The shared service selected in the room's Shared pane, by position (ADR-028 S-3).
    pub selected_share: usize,
    /// The member selected in the member pane, **by identity** (V210-82): the pane is in
    /// fingerprint order, so a join re-sorts it, and a position would then name someone else.
    /// `None` until the pane first has a member (see [`UiState::settle`]).
    pub selected_member: Option<Digest32>,
    /// How many lines the timeline is scrolled up from its newest; 0 follows new messages.
    pub timeline_scroll: usize,
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
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            screen: Screen::ChannelList,
            focus: Focus::Timeline,
            mode: Mode::Normal,
            selected_channel: 0,
            selected_room: None,
            selected_share: 0,
            selected_member: None,
            timeline_scroll: 0,
            status_message: None,
            composer: String::new(),
            selected_tunnel: None,
            on_screen: Vec::new(),
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
                    self.composer.clear();
                    return Action::Dispatch(Command::SendText { channel_id, text });
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
            KeyCode::Char('k') if self.screen == Screen::ChannelList => {
                self.screen = Screen::Keyring;
                Action::Redraw
            }
            KeyCode::Char('x') | KeyCode::Delete if self.screen == Screen::Tunnels => {
                self.close_selected_tunnel(vm)
            }
            KeyCode::Tab if self.screen == Screen::Channel => {
                self.focus = self.focus.next();
                // The Shared pane is there only when something is shared.
                if self.focus == Focus::Shared
                    && vm.active.as_ref().is_none_or(|c| c.shared.is_empty())
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
                if self.screen == Screen::Channel {
                    self.screen = Screen::ChannelList;
                    return Action::Dispatch(Command::SelectChannel { channel_id: None });
                }
                if matches!(self.screen, Screen::Tunnels | Screen::Keyring) {
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
                // An empty passphrase is accepted, and encouraged against (V030-36).
                if p.fields[0].as_str() != p.fields[1].as_str() {
                    self.status_message = Some("passphrases do not match — try again".into());
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::CreateIdentity, None));
                    return Action::Redraw;
                }
                self.status_message = no_passphrase_note(&p.fields[0]);
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
                    Ok(name) => Action::Dispatch(Command::RenameRoom {
                        channel_id,
                        name,
                        identity_passphrase: secret(&p.fields[1]),
                    }),
                    Err(why) => {
                        self.status_message = Some(why);
                        self.mode = Mode::Prompt(Prompt::new(PromptKind::RenameRoom, p.target));
                        Action::Redraw
                    }
                }
            }
        }
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
    fn move_selection(&mut self, vm: &ViewModel, delta: isize) {
        let step =
            |cur: usize, len: usize| (cur as isize + delta).rem_euclid(len as isize) as usize;
        match self.screen {
            Screen::ChannelList => {
                let len = vm.channels.len();
                if len > 0 {
                    self.selected_channel = step(self.selected_channel, len);
                    self.selected_room =
                        vm.channels.get(self.selected_channel).map(|c| c.channel_id);
                }
            }
            Screen::Keyring => {}
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
            Screen::Channel if self.focus == Focus::Shared => {
                let len = vm.active.as_ref().map_or(0, |c| c.shared.len());
                if len > 0 {
                    self.selected_share = step(self.selected_share.min(len - 1), len);
                }
            }
            Screen::Channel if self.focus == Focus::Timeline => {
                // Up scrolls toward older messages.
                self.timeline_scroll = if delta < 0 {
                    self.timeline_scroll.saturating_add(1)
                } else {
                    self.timeline_scroll.saturating_sub(1)
                };
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
                    Some(Parsed::Nav(nav)) => self.apply_nav(nav, vm),
                    Some(Parsed::Prompt(kind, name)) => {
                        // A rename is of the room on screen.
                        let target = (kind == PromptKind::RenameRoom)
                            .then(|| self.active_channel_id(vm))
                            .flatten();
                        let mut p = Prompt::new(kind, target);
                        if let Some(n) = name {
                            p.fields[0] = Zeroizing::new(n);
                            p.step = 1;
                        }
                        self.mode = Mode::Prompt(p);
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
}

/// Parse a `:`-command line, resolving selection-relative targets from `ui`/`vm`.
/// Returns `None` for an empty/unknown command or one missing a required target.
///
/// Per ADR-015 every action MUST be reachable by a typed command. Channel-
/// independent verbs work anywhere (incl. the channel list):
/// - `quit` / `q` — exit
/// - `node <name>` — act as another node of this account
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
        "node" if !rest.is_empty() => {
            return Some(Parsed::Core(Command::UseNode {
                name: rest.to_owned(),
            }))
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
        // On the tunnel list, `close` closes the selected tunnel, not a channel.
        "close" if ui.screen == Screen::Tunnels => return Some(Parsed::CloseTunnel),
        _ => {}
    }
    // Channel-scoped verbs require an active channel.
    let channel = ui.active_channel_id(vm)?;
    let cmd = match verb {
        "send" if !rest.is_empty() => Command::SendText {
            channel_id: channel,
            text: rest.to_owned(),
        },
        "close" => Command::CloseChannel {
            channel_id: channel,
        },
        "leave" => Command::LeaveRoom {
            channel_id: channel,
        },
        "end" => Command::EndRoom {
            channel_id: channel,
        },
        // The room's new name is not secret; the identity passphrase that follows is, so like
        // `new` it opens the masked prompt.
        "rename" => {
            return Some(Parsed::Prompt(
                PromptKind::RenameRoom,
                Some(rest.to_owned()).filter(|r| !r.is_empty()),
            ))
        }
        // The link is public; it can be produced by a one-line command.
        "link" => Command::Invite {
            channel_id: channel,
        },
        _ => return None,
    };
    Some(Parsed::Core(cmd))
}

/// The status line for a passphrase left empty: it is accepted, and one is encouraged (V030-36,
/// decider 2026-10-02: "passphrase is a good idea, but is technically optional").
fn no_passphrase_note(passphrase: &Zeroizing<String>) -> Option<String> {
    passphrase
        .is_empty()
        .then(|| "no passphrase; going on without one. A passphrase is encouraged.".into())
}
