//! The navigation / input state machine and the local verification transitions
//! (ADR-015 §"Navigation & input", §"Verification ceremony").
//!
//! This is pure interaction logic — no terminal, no core — so it is driven by
//! injected key events in tests (the ADR-015 input-injection state-machine gate).
//! It owns *UI* state (which screen/pane has focus, the command-palette overlay,
//! selection indices) and translates input into either a navigation mutation or a
//! [`Command`] for the core. The authoritative data (members, timeline, consent,
//! verification) lives in the [`ViewModel`] pushed from the core; this module never
//! invents trust state.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use secrecy::SecretString;
use vox_core::hash::Digest32;
use zeroize::Zeroizing;

use crate::viewmodel::{Command, InboundVisibility, Verification, ViewModel};

/// Idle time after which the app locks itself (ADR-015 §Screen security: 5 min).
pub const IDLE_LOCK_SECS: u64 = 5 * 60;

/// Whether the idle-lock timer has elapsed.
#[must_use]
pub fn idle_lock_due(last_input_secs: u64, now_secs: u64) -> bool {
    now_secs.saturating_sub(last_input_secs) >= IDLE_LOCK_SECS
}

/// Which masked onboarding/unlock prompt is open (ADR-015: passphrases are entered
/// through a masked prompt, never on the palette line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptKind {
    /// Unlock the identity: `[passphrase]`.
    Unlock,
    /// Create the identity: `[passphrase, confirm]`.
    CreateIdentity,
    /// Create a channel: `[name, passphrase, confirm]`.
    CreateChannel,
    /// Open a closed channel: `[passphrase]` for `Prompt::target`.
    OpenChannel,
    /// Join from a `vox://` invite link: `[link, name, passphrase]`.
    ///
    /// The link is shown as it is typed because it carries no secret (ADR-016); the
    /// channel passphrase that follows is masked, because it travels out of band and
    /// is the one thing the link deliberately does not contain.
    JoinChannel,
}

impl PromptKind {
    /// The field labels, in order.
    #[must_use]
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            PromptKind::Unlock => &["identity passphrase"],
            PromptKind::CreateIdentity => &["new identity passphrase", "confirm passphrase"],
            PromptKind::CreateChannel => {
                &["channel name", "channel passphrase", "confirm passphrase"]
            }
            PromptKind::OpenChannel => &["channel passphrase"],
            PromptKind::JoinChannel => &[
                "invite link (vox://…)",
                "channel name",
                "channel passphrase",
            ],
        }
    }

    /// Whether field `i` is secret (masked while typing, zeroized after).
    #[must_use]
    pub fn is_secret(self, i: usize) -> bool {
        match self {
            // A channel's local name is not a secret.
            PromptKind::CreateChannel => i != 0,
            // Neither the link nor the local name is; only the passphrase.
            PromptKind::JoinChannel => i == 2,
            _ => true,
        }
    }

    /// The prompt's title.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            PromptKind::Unlock => "Unlock",
            PromptKind::CreateIdentity => "Create identity",
            PromptKind::CreateChannel => "Create channel",
            PromptKind::OpenChannel => "Open channel",
            PromptKind::JoinChannel => "Join channel",
        }
    }
}

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
                .map(|_| Zeroizing::new(String::new()))
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
}

impl Focus {
    /// The next pane in the `Tab` cycle.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Focus::Timeline => Focus::Composer,
            Focus::Composer => Focus::Members,
            Focus::Members => Focus::Timeline,
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
    /// A masked onboarding/unlock prompt is open (modal).
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
    /// Selected member index in the member pane.
    pub selected_member: usize,
    /// A transient status/alert line shown at the bottom (e.g. the result of the
    /// last command, an error, a recovery hint). `None` when clear.
    pub status_message: Option<String>,
    /// The composer's pending text (single-line; Enter sends).
    pub composer: String,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            screen: Screen::ChannelList,
            focus: Focus::Timeline,
            mode: Mode::Normal,
            selected_channel: 0,
            selected_member: 0,
            status_message: None,
            composer: String::new(),
        }
    }
}

impl UiState {
    /// A fresh UI state at the home channel list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle a key event against the current `vm`, returning the [`Action`].
    ///
    /// `vm` is read-only context (the active channel/members) used to resolve
    /// selection-relative commands; this method never mutates trust state.
    pub fn on_key(&mut self, key: KeyEvent, vm: &ViewModel) -> Action {
        // Ctrl-C always quits — from any mode, including an open prompt or palette
        // (the exit path restores the terminal and the node shuts down locked).
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
            KeyCode::Tab if self.screen == Screen::Channel => {
                self.focus = self.focus.next();
                Action::Redraw
            }
            KeyCode::Esc => {
                if self.screen == Screen::Channel {
                    self.screen = Screen::ChannelList;
                    return Action::Dispatch(Command::SelectChannel { channel_id: None });
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
            self.selected_member = 0;
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

    /// Open a masked prompt (also used by the loop for onboarding: no identity ⇒
    /// create; locked ⇒ unlock).
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
                if let Some(f) = p.fields.get_mut(p.step) {
                    f.push(c);
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
            PromptKind::Unlock => Action::Dispatch(Command::Unlock {
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
                if p.fields[0].as_str() != p.fields[1].as_str() || p.fields[0].is_empty() {
                    self.status_message =
                        Some("passphrases do not match (or empty) — try again".into());
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::CreateIdentity, None));
                    return Action::Redraw;
                }
                Action::Dispatch(Command::CreateIdentity {
                    passphrase: secret(&p.fields[0]),
                })
            }
            PromptKind::CreateChannel => {
                let name = p.fields[0].trim().to_owned();
                if name.is_empty() {
                    self.status_message = Some("channel name is required".into());
                    self.mode = Mode::Prompt(Prompt::new(PromptKind::CreateChannel, None));
                    return Action::Redraw;
                }
                if p.fields[1].as_str() != p.fields[2].as_str() || p.fields[1].is_empty() {
                    self.status_message =
                        Some("passphrases do not match (or empty) — try again".into());
                    let mut again = Prompt::new(PromptKind::CreateChannel, None);
                    again.fields[0] = Zeroizing::new(name);
                    again.step = 1;
                    self.mode = Mode::Prompt(again);
                    return Action::Redraw;
                }
                Action::Dispatch(Command::CreateChannel {
                    local_name: name,
                    passphrase: secret(&p.fields[1]),
                    deniable: false,
                })
            }
            PromptKind::JoinChannel => {
                let link = p.fields[0].trim().to_owned();
                let name = p.fields[1].trim().to_owned();
                if link.is_empty() || name.is_empty() {
                    self.status_message = Some("a link and a channel name are required".into());
                    let mut again = Prompt::new(PromptKind::JoinChannel, None);
                    again.fields[0] = Zeroizing::new(link);
                    self.mode = Mode::Prompt(again);
                    return Action::Redraw;
                }
                Action::Dispatch(Command::Join {
                    local_name: name,
                    link,
                    passphrase: secret(&p.fields[2]),
                })
            }
        }
    }

    fn move_selection(&mut self, vm: &ViewModel, delta: isize) {
        let (cur, len) = match self.screen {
            Screen::ChannelList => (&mut self.selected_channel, vm.channels.len()),
            Screen::Channel => (
                &mut self.selected_member,
                vm.active.as_ref().map_or(0, |c| c.members.len()),
            ),
        };
        if len == 0 {
            return;
        }
        let next = (*cur as isize + delta).rem_euclid(len as isize);
        *cur = next as usize;
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
                    Some(Parsed::Nav(nav)) => self.apply_nav(nav, vm),
                    Some(Parsed::Prompt(kind, name)) => {
                        let mut p = Prompt::new(kind, None);
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
        }
        Action::Redraw
    }

    /// The fingerprint of the currently-selected member, if any.
    #[must_use]
    pub fn selected_member_id(&self, vm: &ViewModel) -> Option<Digest32> {
        vm.active
            .as_ref()
            .and_then(|c| c.members.get(self.selected_member))
            .map(|m| m.id)
    }

    /// The channelID of the active channel, if one is open.
    #[must_use]
    pub fn active_channel_id(&self, vm: &ViewModel) -> Option<Digest32> {
        vm.active.as_ref().map(|c| c.channel_id)
    }
}

/// The local verification-state transition (ADR-015 acceptance state machine):
/// a successful scan/compare → `Verified`; a key change always → `KeyChanged`
/// (must re-verify), regardless of prior state.
#[must_use]
pub fn on_verified(_current: Verification) -> Verification {
    Verification::Verified
}

/// A key change resets verification to `KeyChanged` from any prior state.
#[must_use]
pub fn on_key_change(_current: Verification) -> Verification {
    Verification::KeyChanged
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
}

/// Parse a `:`-command line, resolving selection-relative targets from `ui`/`vm`.
/// Returns `None` for an empty/unknown command or one missing a required target.
///
/// Per ADR-015 every action MUST be reachable by a typed command. Channel-
/// independent verbs work anywhere (incl. the channel list):
/// - `quit` / `q` — exit
/// - `lock` — lock the app
/// - `open` / `back` / `focus` / `up` / `down` — navigation
///
/// Channel-scoped verbs require an active channel:
/// - `send <text…>`, `invite`, `consent grant|revoke`, `show` / `hide`,
///   `block` / `unblock`, `verify` (acts on the selected member).
///
/// **Create / join / unlock / init are not one-line palette commands.** They require
/// a passphrase, which ADR-015 mandates be entered through a **masked** prompt and
/// shared out-of-band — never echoed on the palette line or stored in a status
/// string. The verbs `init`, `unlock`, `new <name>` therefore *open the prompt*;
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
        "lock" => return Some(Parsed::Core(Command::Lock)),
        "unlock" => return Some(Parsed::Prompt(PromptKind::Unlock, None)),
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
        // The link is public; it can be produced by a one-line command.
        "invite" => Command::Invite {
            channel_id: channel,
        },
        "consent" => match rest {
            "grant" => Command::GrantConsent {
                channel_id: channel,
                member: ui.selected_member_id(vm)?,
            },
            "revoke" => Command::RevokeConsent {
                channel_id: channel,
                member: ui.selected_member_id(vm)?,
            },
            _ => return None,
        },
        "show" => Command::SetVisibility {
            channel_id: channel,
            member: ui.selected_member_id(vm)?,
            visibility: InboundVisibility::Visible,
        },
        "hide" => Command::SetVisibility {
            channel_id: channel,
            member: ui.selected_member_id(vm)?,
            visibility: InboundVisibility::Hidden,
        },
        "block" => Command::Block {
            channel_id: channel,
            member: ui.selected_member_id(vm)?,
        },
        "unblock" => Command::Unblock {
            channel_id: channel,
            member: ui.selected_member_id(vm)?,
        },
        "verify" => Command::MarkVerified {
            channel_id: channel,
            member: ui.selected_member_id(vm)?,
        },
        _ => return None,
    };
    Some(Parsed::Core(cmd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viewmodel::{ChannelView, MemberView, OutboundConsent, Reachability};
    use secrecy::ExposeSecret;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn member(id: u8, nick: &str) -> MemberView {
        MemberView {
            id: [id; 32],
            nickname: nick.into(),
            verification: Verification::UnverifiedTofu,
            outbound: OutboundConsent::Revoked,
            inbound: InboundVisibility::Visible,
            blocked: false,
            safety_code: "00000 00000".into(),
        }
    }

    fn vm_with_channel() -> ViewModel {
        ViewModel {
            notice: None,
            channels: vec![crate::viewmodel::ChannelSummary {
                open: true,
                channel_id: [7; 32],
                local_name: "team".into(),
                unread: 0,
                reachability: Reachability::Online,
            }],
            active: Some(ChannelView {
                channel_id: [7; 32],
                local_name: "team".into(),
                members: vec![member(1, "alice"), member(2, "bob")],
                timeline: vec![],
                reachability: Reachability::Online,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn focus_cycles_with_tab() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        assert_eq!(ui.focus, Focus::Timeline);
        ui.on_key(key(KeyCode::Tab), &vm_with_channel());
        assert_eq!(ui.focus, Focus::Composer);
        ui.on_key(key(KeyCode::Tab), &vm_with_channel());
        assert_eq!(ui.focus, Focus::Members);
        ui.on_key(key(KeyCode::Tab), &vm_with_channel());
        assert_eq!(ui.focus, Focus::Timeline);
    }

    #[test]
    fn esc_returns_to_channel_list() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        ui.on_key(key(KeyCode::Esc), &vm_with_channel());
        assert_eq!(ui.screen, Screen::ChannelList);
    }

    #[test]
    fn ctrl_c_quits() {
        let mut ui = UiState::new();
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(ui.on_key(k, &ViewModel::default()), Action::Quit));
    }

    #[test]
    fn member_selection_wraps() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        ui.focus = Focus::Members;
        let vm = vm_with_channel();
        assert_eq!(ui.selected_member, 0);
        ui.on_key(key(KeyCode::Down), &vm);
        assert_eq!(ui.selected_member, 1);
        ui.on_key(key(KeyCode::Down), &vm); // wraps
        assert_eq!(ui.selected_member, 0);
        ui.on_key(key(KeyCode::Up), &vm); // wraps backward
        assert_eq!(ui.selected_member, 1);
    }

    #[test]
    fn palette_typed_command_dispatches_send() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        let vm = vm_with_channel();
        // Open palette, type "send hello", Enter.
        ui.on_key(key(KeyCode::Char(':')), &vm);
        assert!(matches!(ui.mode, Mode::CommandPalette(_)));
        for c in "send hello world".chars() {
            ui.on_key(key(KeyCode::Char(c)), &vm);
        }
        let action = ui.on_key(key(KeyCode::Enter), &vm);
        match action {
            Action::Dispatch(Command::SendText { channel_id, text }) => {
                assert_eq!(channel_id, [7; 32]);
                assert_eq!(text, "hello world");
            }
            other => panic!("expected SendText, got {other:?}"),
        }
        assert!(ui.mode.is_normal(), "palette closes after Enter");
    }

    #[test]
    fn palette_consent_and_block_resolve_selected_member() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        ui.focus = Focus::Members;
        ui.selected_member = 1; // bob
        let vm = vm_with_channel();
        assert!(matches!(
            parse_command("consent grant", &ui, &vm),
            Some(Parsed::Core(Command::GrantConsent { channel_id, member })) if channel_id == [7; 32] && member == [2; 32]
        ));
        assert!(matches!(
            parse_command("block", &ui, &vm),
            Some(Parsed::Core(Command::Block { channel_id, member })) if channel_id == [7; 32] && member == [2; 32]
        ));
        assert!(matches!(
            parse_command("verify", &ui, &vm),
            Some(Parsed::Core(Command::MarkVerified { channel_id, member })) if channel_id == [7; 32] && member == [2; 32]
        ));
    }

    #[test]
    fn channel_independent_commands_work_without_active_channel() {
        let ui = UiState::new(); // channel list, no active channel
        let vm = ViewModel::default();
        // quit and lock and navigation must parse with no channel open.
        assert!(matches!(
            parse_command("quit", &ui, &vm),
            Some(Parsed::Quit)
        ));
        assert!(matches!(parse_command("q", &ui, &vm), Some(Parsed::Quit)));
        assert!(matches!(
            parse_command("lock", &ui, &vm),
            Some(Parsed::Core(Command::Lock))
        ));
        assert!(matches!(
            parse_command("open", &ui, &vm),
            Some(Parsed::Nav(Nav::Open))
        ));
        assert!(matches!(
            parse_command("focus", &ui, &vm),
            Some(Parsed::Nav(Nav::FocusNext))
        ));
    }

    #[test]
    fn palette_quit_command_quits() {
        let mut ui = UiState::new();
        let vm = ViewModel::default();
        ui.on_key(key(KeyCode::Char(':')), &vm);
        for c in "quit".chars() {
            ui.on_key(key(KeyCode::Char(c)), &vm);
        }
        assert!(matches!(ui.on_key(key(KeyCode::Enter), &vm), Action::Quit));
    }

    #[test]
    fn palette_open_navigates_from_list() {
        let mut ui = UiState::new();
        let vm = vm_with_channel();
        ui.on_key(key(KeyCode::Char(':')), &vm);
        for c in "open".chars() {
            ui.on_key(key(KeyCode::Char(c)), &vm);
        }
        ui.on_key(key(KeyCode::Enter), &vm);
        assert_eq!(ui.screen, Screen::Channel);
    }

    #[test]
    fn palette_esc_cancels_without_dispatch() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        let vm = vm_with_channel();
        ui.on_key(key(KeyCode::Char(':')), &vm);
        ui.on_key(key(KeyCode::Char('x')), &vm);
        let a = ui.on_key(key(KeyCode::Esc), &vm);
        assert!(matches!(a, Action::Redraw));
        assert!(ui.mode.is_normal());
    }

    #[test]
    fn unknown_or_targetless_commands_do_not_dispatch() {
        let ui = UiState::new(); // no active channel
        let vm = ViewModel::default();
        assert!(parse_command("send hi", &ui, &vm).is_none());
        assert!(parse_command("frobnicate", &ui, &vm).is_none());
    }

    #[test]
    fn verification_transitions() {
        assert_eq!(
            on_verified(Verification::UnverifiedTofu),
            Verification::Verified
        );
        assert_eq!(
            on_key_change(Verification::Verified),
            Verification::KeyChanged
        );
        // A key change overrides even a verified state.
        assert_eq!(
            on_key_change(Verification::Verified),
            Verification::KeyChanged
        );
    }
    // ---- M13.5: prompts, composer, open/closed channels ----

    fn vm_locked_with_closed_channel() -> ViewModel {
        ViewModel {
            notice: None,
            channels: vec![crate::viewmodel::ChannelSummary {
                open: false,
                channel_id: [9; 32],
                local_name: "(locked 09090909)".into(),
                unread: 0,
                reachability: Reachability::Offline,
            }],
            active: None,
            sync: crate::viewmodel::SyncStatus::Idle,
            locked: false,
            mlock_active: true,
            has_identity: true,
        }
    }

    fn type_str(ui: &mut UiState, vm: &ViewModel, s: &str) -> Action {
        let mut last = Action::Redraw;
        for c in s.chars() {
            last = ui.on_key(key(KeyCode::Char(c)), vm);
        }
        last
    }

    #[test]
    fn enter_on_a_closed_channel_opens_the_passphrase_prompt_and_submits_open() {
        let mut ui = UiState::new();
        let vm = vm_locked_with_closed_channel();
        assert!(matches!(
            ui.on_key(key(KeyCode::Enter), &vm),
            Action::Redraw
        ));
        assert!(
            matches!(ui.mode, Mode::Prompt(ref p) if p.kind == PromptKind::OpenChannel && p.target == Some([9; 32]))
        );
        assert_eq!(
            ui.screen,
            Screen::ChannelList,
            "no screen change until opened"
        );
        type_str(&mut ui, &vm, "s3cret");
        // The prompt displays a mask, never the text.
        if let Mode::Prompt(ref p) = ui.mode {
            assert_eq!(p.display(), "••••••");
            assert!(!p.display().contains("s3cret"));
        }
        match ui.on_key(key(KeyCode::Enter), &vm) {
            Action::Dispatch(Command::OpenChannel {
                channel_id,
                passphrase,
            }) => {
                assert_eq!(channel_id, [9; 32]);
                assert_eq!(passphrase.expose_secret(), "s3cret");
            }
            other => panic!("expected OpenChannel, got {other:?}"),
        }
        assert!(ui.mode.is_normal());
    }

    #[test]
    fn enter_on_an_open_channel_selects_it_for_the_core() {
        let mut ui = UiState::new();
        let vm = vm_with_channel(); // open: true
        match ui.on_key(key(KeyCode::Enter), &vm) {
            Action::Dispatch(Command::SelectChannel { channel_id }) => {
                assert_eq!(channel_id, Some([7; 32]))
            }
            other => panic!("expected SelectChannel, got {other:?}"),
        }
        assert_eq!(ui.screen, Screen::Channel);
        // Esc back tells the core nothing is on screen.
        match ui.on_key(key(KeyCode::Esc), &vm) {
            Action::Dispatch(Command::SelectChannel { channel_id }) => assert_eq!(channel_id, None),
            other => panic!("expected SelectChannel(None), got {other:?}"),
        }
        assert_eq!(ui.screen, Screen::ChannelList);
    }

    #[test]
    fn escape_cancels_a_prompt_and_ctrl_c_quits_from_inside_one() {
        let mut ui = UiState::new();
        let vm = vm_locked_with_closed_channel();
        ui.start_prompt(PromptKind::Unlock, None);
        type_str(&mut ui, &vm, "half-typed");
        assert!(matches!(ui.on_key(key(KeyCode::Esc), &vm), Action::Redraw));
        assert!(ui.mode.is_normal(), "cancel drops the (zeroizing) fields");
        ui.start_prompt(PromptKind::Unlock, None);
        assert!(matches!(
            ui.on_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &vm
            ),
            Action::Quit
        ));
    }

    #[test]
    fn create_identity_prompt_requires_matching_non_empty_confirmation() {
        let mut ui = UiState::new();
        let vm = ViewModel::default();
        ui.start_prompt(PromptKind::CreateIdentity, None);
        type_str(&mut ui, &vm, "abc");
        ui.on_key(key(KeyCode::Enter), &vm); // to confirm step
        type_str(&mut ui, &vm, "abd");
        assert!(matches!(
            ui.on_key(key(KeyCode::Enter), &vm),
            Action::Redraw
        ));
        assert!(
            matches!(ui.mode, Mode::Prompt(ref p) if p.kind == PromptKind::CreateIdentity && p.step == 0)
        );
        assert!(ui
            .status_message
            .as_deref()
            .unwrap_or("")
            .contains("do not match"));
        // Status never echoes what was typed.
        assert!(!ui.status_message.as_deref().unwrap_or("").contains("abc"));
        type_str(&mut ui, &vm, "abc");
        ui.on_key(key(KeyCode::Enter), &vm);
        type_str(&mut ui, &vm, "abc");
        match ui.on_key(key(KeyCode::Enter), &vm) {
            Action::Dispatch(Command::CreateIdentity { passphrase }) => {
                assert_eq!(passphrase.expose_secret(), "abc")
            }
            other => panic!("expected CreateIdentity, got {other:?}"),
        }
    }

    #[test]
    fn new_verb_prefills_the_channel_name_and_collects_a_masked_passphrase() {
        let mut ui = UiState::new();
        let vm = vm_locked_with_closed_channel();
        ui.on_key(key(KeyCode::Char(':')), &vm);
        type_str(&mut ui, &vm, "new family chat");
        ui.on_key(key(KeyCode::Enter), &vm);
        assert!(
            matches!(ui.mode, Mode::Prompt(ref p) if p.kind == PromptKind::CreateChannel && p.step == 1 && p.fields[0].as_str() == "family chat")
        );
        type_str(&mut ui, &vm, "pw");
        ui.on_key(key(KeyCode::Enter), &vm);
        type_str(&mut ui, &vm, "pw");
        match ui.on_key(key(KeyCode::Enter), &vm) {
            Action::Dispatch(Command::CreateChannel {
                local_name,
                passphrase,
                deniable,
            }) => {
                assert_eq!(local_name, "family chat");
                assert_eq!(passphrase.expose_secret(), "pw");
                assert!(!deniable);
            }
            other => panic!("expected CreateChannel, got {other:?}"),
        }
    }

    #[test]
    fn unlock_and_init_verbs_open_prompts_not_commands() {
        let ui = UiState::new();
        let vm = ViewModel::default();
        assert!(matches!(
            parse_command("unlock", &ui, &vm),
            Some(Parsed::Prompt(PromptKind::Unlock, None))
        ));
        assert!(matches!(
            parse_command("init", &ui, &vm),
            Some(Parsed::Prompt(PromptKind::CreateIdentity, None))
        ));
        assert!(matches!(
            parse_command("new", &ui, &vm),
            Some(Parsed::Prompt(PromptKind::CreateChannel, None))
        ));
    }

    #[test]
    fn composer_collects_text_and_enter_sends_to_the_active_channel() {
        let mut ui = UiState::new();
        let vm = vm_with_channel();
        ui.screen = Screen::Channel;
        ui.focus = Focus::Composer;
        type_str(&mut ui, &vm, "hello there");
        assert_eq!(ui.composer, "hello there");
        // A colon in the composer is text, not the palette.
        ui.on_key(key(KeyCode::Char(':')), &vm);
        assert_eq!(ui.composer, "hello there:");
        assert!(ui.mode.is_normal());
        ui.on_key(key(KeyCode::Backspace), &vm);
        match ui.on_key(key(KeyCode::Enter), &vm) {
            Action::Dispatch(Command::SendText { channel_id, text }) => {
                assert_eq!(channel_id, [7; 32]);
                assert_eq!(text, "hello there");
            }
            other => panic!("expected SendText, got {other:?}"),
        }
        assert!(ui.composer.is_empty(), "composer clears after send");
        // Empty composer: Enter sends nothing.
        assert!(matches!(
            ui.on_key(key(KeyCode::Enter), &vm),
            Action::Redraw
        ));
        // Tab leaves the composer; then ':' opens the palette again.
        ui.on_key(key(KeyCode::Tab), &vm);
        assert_eq!(ui.focus, Focus::Members);
        ui.on_key(key(KeyCode::Char(':')), &vm);
        assert!(matches!(ui.mode, Mode::CommandPalette(_)));
    }

    #[test]
    fn idle_lock_threshold() {
        assert!(!idle_lock_due(1_000, 1_000 + IDLE_LOCK_SECS - 1));
        assert!(idle_lock_due(1_000, 1_000 + IDLE_LOCK_SECS));
        assert!(
            !idle_lock_due(2_000, 1_000),
            "clock going backwards never locks"
        );
    }
    #[test]
    fn the_join_prompt_shows_the_link_and_masks_only_the_passphrase() {
        // ADR-016: the link carries no secret, so it is typed in the clear; the
        // passphrase travels out of band and is masked.
        assert_eq!(PromptKind::JoinChannel.fields().len(), 3);
        assert!(!PromptKind::JoinChannel.is_secret(0), "the link is public");
        assert!(!PromptKind::JoinChannel.is_secret(1), "the name is local");
        assert!(
            PromptKind::JoinChannel.is_secret(2),
            "the passphrase is not"
        );
        assert_eq!(PromptKind::JoinChannel.title(), "Join channel");

        // `:join` opens the prompt rather than taking a passphrase on the palette.
        let vm = vm_with_channel();
        let ui = UiState::default();
        assert!(matches!(
            parse_command("join", &ui, &vm),
            Some(Parsed::Prompt(PromptKind::JoinChannel, None))
        ));

        // Completing it dispatches the link and the passphrase together.
        let mut ui = UiState {
            mode: Mode::Prompt(Prompt::new(PromptKind::JoinChannel, None)),
            ..UiState::default()
        };
        if let Mode::Prompt(p) = &mut ui.mode {
            p.fields[0] = Zeroizing::new("vox://abc?b=/ip4/10.0.0.1/udp/443".into());
            p.fields[1] = Zeroizing::new("team".into());
            p.fields[2] = Zeroizing::new("channel-pp".into());
        }
        match ui.submit_prompt() {
            Action::Dispatch(Command::Join {
                local_name,
                link,
                passphrase,
            }) => {
                assert_eq!(local_name, "team");
                assert_eq!(link, "vox://abc?b=/ip4/10.0.0.1/udp/443");
                use secrecy::ExposeSecret as _;
                assert_eq!(passphrase.expose_secret(), "channel-pp");
            }
            other => panic!("expected a join dispatch, got {other:?}"),
        }

        // A missing link or name re-opens the prompt instead of dispatching, keeping
        // the link that was already typed.
        let mut ui = UiState {
            mode: Mode::Prompt(Prompt::new(PromptKind::JoinChannel, None)),
            ..UiState::default()
        };
        if let Mode::Prompt(p) = &mut ui.mode {
            p.fields[0] = Zeroizing::new("vox://abc?b=/ip4/10.0.0.1/udp/443".into());
        }
        assert!(matches!(ui.submit_prompt(), Action::Redraw));
        match &ui.mode {
            Mode::Prompt(p) => {
                assert_eq!(p.kind, PromptKind::JoinChannel);
                assert_eq!(p.fields[0].as_str(), "vox://abc?b=/ip4/10.0.0.1/udp/443");
            }
            other => panic!("expected the prompt to reopen, got {other:?}"),
        }
        assert!(ui.status_message.is_some());
    }

    #[test]
    fn invite_is_a_one_line_command_because_the_link_is_public() {
        let vm = vm_with_channel();
        let ui = UiState {
            screen: Screen::Channel,
            selected_channel: 0,
            ..UiState::default()
        };
        let cid = vm.channels[0].channel_id;
        assert!(matches!(
            parse_command("invite", &ui, &vm),
            Some(Parsed::Core(Command::Invite { channel_id })) if channel_id == cid
        ));
        // And it needs an open channel, like every channel-scoped verb.
        let empty = ViewModel::default();
        assert!(parse_command("invite", &UiState::default(), &empty).is_none());
    }
}
