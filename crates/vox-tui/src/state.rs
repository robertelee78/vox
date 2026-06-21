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
use vox_core::hash::Digest32;

use crate::viewmodel::{Command, InboundVisibility, Verification, ViewModel};

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

/// Input modality: normal navigation, or the modal `:` command-palette overlay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Normal mode: chords navigate; the composer (when focused) inserts text.
    Normal,
    /// The command palette is open; the buffer holds the typed command line.
    CommandPalette(String),
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
        // The command palette is modal and intercepts all keys while open.
        if let Mode::CommandPalette(_) = self.mode {
            return self.on_palette_key(key, vm);
        }
        // Ctrl-C always quits.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
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
                }
                Action::Redraw
            }
            KeyCode::Enter if self.screen == Screen::ChannelList => {
                if self.selected_channel < vm.channels.len() {
                    self.screen = Screen::Channel;
                    self.focus = Focus::Timeline;
                    self.selected_member = 0;
                }
                Action::Redraw
            }
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
                    Some(Parsed::Nav(nav)) => {
                        self.apply_nav(nav, vm);
                        Action::Redraw
                    }
                    None => Action::Redraw,
                }
            }
            _ => Action::Redraw,
        }
    }

    /// Apply a navigation action (the typed-command equivalents of the chord
    /// navigation, so every action is reachable by command — ADR-015 a11y).
    fn apply_nav(&mut self, nav: Nav, vm: &ViewModel) {
        match nav {
            Nav::Open => {
                if self.screen == Screen::ChannelList && self.selected_channel < vm.channels.len() {
                    self.screen = Screen::Channel;
                    self.focus = Focus::Timeline;
                    self.selected_member = 0;
                }
            }
            Nav::Back => self.screen = Screen::ChannelList,
            Nav::FocusNext => {
                if self.screen == Screen::Channel {
                    self.focus = self.focus.next();
                }
            }
            Nav::Up => self.move_selection(vm, -1),
            Nav::Down => self.move_selection(vm, 1),
        }
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
/// - `send <text…>`, `consent grant|revoke`, `show` / `hide`, `block` / `unblock`,
///   `verify` (acts on the selected member).
///
/// **Create / join are intentionally not one-line palette commands.** They require
/// a channel passphrase, which ADR-015 mandates be entered through a **masked**
/// prompt and shared out-of-band — never echoed on the palette line or stored in a
/// status string. They are therefore initiated through the dedicated create/join
/// onboarding flow (with masked passphrase entry), which is wired with the live
/// core; this is a security-driven exception to "one-line command", not a chord-only
/// path. Every *non-secret* action is reachable here by a typed command.
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
            channels: vec![crate::viewmodel::ChannelSummary {
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
        assert_eq!(ui.mode, Mode::Normal, "palette closes after Enter");
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
        assert_eq!(ui.mode, Mode::Normal);
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
}
