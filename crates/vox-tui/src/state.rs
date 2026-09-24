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
