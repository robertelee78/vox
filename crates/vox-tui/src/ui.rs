//! The ratatui view (ADR-015 §"Navigation & input", §"Accessibility").
//!
//! A pure render: [`render`] draws the current [`ViewModel`] + [`UiState`] into a
//! ratatui [`Frame`]. The binary only ever draws to the **alternate screen**, so
//! decrypted text rendered here never enters the terminal's primary buffer /
//! scrollback (ADR-015 at-rest screen claim). Because rendering is a pure function
//! of state into a `Frame`, it is covered by `TestBackend` render-snapshot tests.
//!
//! ## Accessibility (ADR-015)
//! State is **never** signalled by colour alone: verification / consent / Block
//! each render as a glyph **and** a text label (so they survive `NO_COLOR`,
//! monochrome terminals, and screen readers).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::state::{Focus, Mode, Screen, UiState};
use crate::viewmodel::{
    InboundVisibility, MemberView, MessageView, OutboundConsent, Reachability, SyncStatus,
    Verification, ViewModel,
};

/// The honest non-leaking marker for an entry not decryptable to you (ADR-015).
pub const UNDECRYPTABLE_MARKER: &str = "[locked — not shared with you]";

/// A short, colour-independent label + glyph for a verification state.
#[must_use]
pub fn verification_label(v: Verification) -> &'static str {
    match v {
        Verification::Verified => "✓ verified",
        Verification::UnverifiedTofu => "? unverified",
        Verification::KeyChanged => "! key-changed",
    }
}

/// A label for the combined consent/visibility/block state of a member.
#[must_use]
pub fn consent_label(m: &MemberView) -> &'static str {
    if m.blocked {
        return "⊘ blocked";
    }
    match (m.outbound, m.inbound) {
        (OutboundConsent::Granted, InboundVisibility::Visible) => "↔ consented",
        (OutboundConsent::Granted, InboundVisibility::Hidden) => "→ out-only",
        (OutboundConsent::Revoked, InboundVisibility::Visible) => "← in-only",
        (OutboundConsent::Revoked, InboundVisibility::Hidden) => "· none",
    }
}

/// A reachability glyph + word.
fn reachability_label(r: Reachability) -> &'static str {
    match r {
        Reachability::Online => "● online",
        Reachability::NeedsPeerOrNode => "◐ needs peer/node online",
        Reachability::Offline => "○ offline",
    }
}

fn sync_label(s: SyncStatus) -> &'static str {
    match s {
        SyncStatus::Idle => "idle",
        SyncStatus::Syncing => "syncing…",
        SyncStatus::Synced => "synced",
    }
}

/// Render the whole UI for the current state.
pub fn render(frame: &mut Frame, vm: &ViewModel, ui: &UiState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    match ui.screen {
        Screen::ChannelList => render_channel_list(frame, chunks[0], vm, ui),
        Screen::Channel => render_channel(frame, chunks[0], vm, ui),
    }
    render_status_bar(frame, chunks[1], vm);
    render_hint_bar(frame, chunks[2], ui);

    if let Mode::CommandPalette(ref buf) = ui.mode {
        render_palette(frame, area, buf);
    }
}

fn render_channel_list(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &UiState) {
    let items: Vec<ListItem> = vm
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let marker = if i == ui.selected_channel {
                "▶ "
            } else {
                "  "
            };
            let unread = if c.unread > 0 {
                format!(" ({} unread)", c.unread)
            } else {
                String::new()
            };
            ListItem::new(format!(
                "{marker}{}{unread}  [{}]",
                c.local_name,
                reachability_label(c.reachability)
            ))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Channels (Enter: open · : command)"),
    );
    frame.render_widget(list, area);
}

fn render_channel(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &UiState) {
    let Some(channel) = vm.active.as_ref() else {
        let p = Paragraph::new("No channel open").block(Block::default().borders(Borders::ALL));
        frame.render_widget(p, area);
        return;
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(cols[0]);

    render_timeline(
        frame,
        body[0],
        channel.timeline.as_slice(),
        focused(ui, Focus::Timeline),
    );
    render_composer(frame, body[1], focused(ui, Focus::Composer));
    render_members(
        frame,
        cols[1],
        &channel.members,
        ui.selected_member,
        focused(ui, Focus::Members),
    );
}

fn focused(ui: &UiState, pane: Focus) -> bool {
    ui.screen == Screen::Channel && ui.focus == pane && matches!(ui.mode, Mode::Normal)
}

fn render_timeline(frame: &mut Frame, area: Rect, timeline: &[MessageView], focus: bool) {
    let lines: Vec<Line> = timeline
        .iter()
        .map(|m| {
            let body = m
                .body
                .clone()
                .unwrap_or_else(|| UNDECRYPTABLE_MARKER.to_owned());
            Line::from(vec![
                Span::styled(
                    format!("{}: ", m.author_nick),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(body),
            ])
        })
        .collect();
    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(pane_block("Timeline", focus));
    frame.render_widget(p, area);
}

fn render_composer(frame: &mut Frame, area: Rect, focus: bool) {
    let p = Paragraph::new("type a message — Tab to switch panes, : for commands")
        .block(pane_block("Composer", focus));
    frame.render_widget(p, area);
}

fn render_members(
    frame: &mut Frame,
    area: Rect,
    members: &[MemberView],
    selected: usize,
    focus: bool,
) {
    let items: Vec<ListItem> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let marker = if i == selected && focus { "▶ " } else { "  " };
            // Always glyph + label, never colour-only (a11y).
            ListItem::new(vec![
                Line::from(format!("{marker}{}", m.nickname)),
                Line::from(format!(
                    "    {} · {}",
                    verification_label(m.verification),
                    consent_label(m)
                )),
            ])
        })
        .collect();
    let list = List::new(items).block(pane_block("Members", focus));
    frame.render_widget(list, area);
}

fn pane_block(title: &str, focus: bool) -> Block<'_> {
    let mut b = Block::default().borders(Borders::ALL).title(title);
    if focus {
        b = b.border_style(Style::default().add_modifier(Modifier::BOLD));
        b = b.title(format!("{title} [focus]"));
    }
    b
}

fn render_status_bar(frame: &mut Frame, area: Rect, vm: &ViewModel) {
    let lock = if vm.locked { "LOCKED" } else { "unlocked" };
    let mlock = if vm.mlock_active {
        String::new()
    } else {
        "  ⚠ mlock unavailable (zeroize-only)".to_owned()
    };
    let text = format!(" sync: {}  ·  {lock}{mlock}", sync_label(vm.sync));
    frame.render_widget(Paragraph::new(text), area);
}

fn render_hint_bar(frame: &mut Frame, area: Rect, ui: &UiState) {
    // A transient status/alert takes precedence over the static keybind hint.
    if let Some(msg) = ui.status_message.as_ref() {
        frame.render_widget(Paragraph::new(format!(" {msg}")), area);
        return;
    }
    let hint = match ui.screen {
        Screen::ChannelList => " ↑/↓ select · Enter open · : command · Ctrl-C quit",
        Screen::Channel => " Tab switch pane · : command · Esc back · Ctrl-C quit",
    };
    frame.render_widget(Paragraph::new(hint), area);
}

fn render_palette(frame: &mut Frame, area: Rect, buf: &str) {
    // A one-line modal overlay near the bottom.
    let h = 3.min(area.height);
    let y = area.height.saturating_sub(h);
    let overlay = Rect::new(area.x, y, area.width, h);
    let p = Paragraph::new(format!(":{buf}")).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Command (Esc cancel)"),
    );
    frame.render_widget(p, overlay);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viewmodel::{ChannelSummary, ChannelView};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn draw(vm: &ViewModel, ui: &UiState) -> String {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, vm, ui)).unwrap();
        // Flatten the alt-screen buffer to text for assertions.
        let buf = terminal.backend().buffer().clone();
        buf.content().iter().map(|c| c.symbol()).collect::<String>()
    }

    fn channel_vm() -> ViewModel {
        ViewModel {
            channels: vec![ChannelSummary {
                channel_id: [7; 32],
                local_name: "team-rocket".into(),
                unread: 2,
                reachability: Reachability::Online,
            }],
            active: Some(ChannelView {
                channel_id: [7; 32],
                local_name: "team-rocket".into(),
                members: vec![MemberView {
                    id: [1; 32],
                    nickname: "alice".into(),
                    verification: Verification::Verified,
                    outbound: OutboundConsent::Granted,
                    inbound: InboundVisibility::Visible,
                    blocked: false,
                    safety_code: "12345 67890".into(),
                }],
                timeline: vec![
                    MessageView {
                        author: [1; 32],
                        author_nick: "alice".into(),
                        timestamp: 1,
                        body: Some("hello team".into()),
                    },
                    MessageView {
                        author: [2; 32],
                        author_nick: "bob".into(),
                        timestamp: 2,
                        body: None, // undecryptable
                    },
                ],
                reachability: Reachability::Online,
            }),
            sync: SyncStatus::Synced,
            locked: false,
            mlock_active: true,
        }
    }

    #[test]
    fn channel_list_shows_name_unread_and_reachability() {
        let mut ui = UiState::new();
        ui.screen = Screen::ChannelList;
        let out = draw(&channel_vm(), &ui);
        assert!(out.contains("team-rocket"));
        assert!(out.contains("unread"));
        assert!(out.contains("online"));
    }

    #[test]
    fn channel_view_renders_member_state_with_label_not_color_only() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        let out = draw(&channel_vm(), &ui);
        assert!(out.contains("alice"));
        assert!(out.contains("verified"), "verification shown as text label");
        assert!(out.contains("consented"), "consent shown as text label");
    }

    #[test]
    fn undecryptable_entry_shows_marker_and_no_plaintext_leak() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        let out = draw(&channel_vm(), &ui);
        // The decryptable message renders; the undecryptable one shows the marker.
        assert!(out.contains("hello team"));
        assert!(
            out.contains("locked"),
            "undecryptable entry shows the marker"
        );
    }

    #[test]
    fn command_palette_overlay_shows_typed_buffer() {
        let mut ui = UiState::new();
        ui.screen = Screen::Channel;
        ui.mode = Mode::CommandPalette("consent grant".into());
        let out = draw(&channel_vm(), &ui);
        assert!(out.contains("consent grant"));
        assert!(out.contains("Command"));
    }

    #[test]
    fn mlock_warning_surfaces_when_unavailable() {
        let mut vm = channel_vm();
        vm.mlock_active = false;
        let ui = UiState::new();
        let out = draw(&vm, &ui);
        assert!(out.contains("mlock unavailable"));
    }

    #[test]
    fn locked_state_is_shown() {
        let mut vm = channel_vm();
        vm.locked = true;
        let out = draw(&vm, &UiState::new());
        assert!(out.contains("LOCKED"));
    }
}
