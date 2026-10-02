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
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::state::{Focus, Mode, Prompt, Screen, UiState};
use crate::viewmodel::{
    InboundVisibility, MemberView, MessageView, OutboundConsent, Reachability, SyncStatus,
    Verification, ViewModel,
};

/// The honest non-leaking marker for an entry not decryptable to you (ADR-015).
pub const UNDECRYPTABLE_MARKER: &str = "[locked — not shared with you]";

/// Prefixed to a message that arrived after the rows below it were already shown — a member
/// who was offline, or a sync that caught up (ADR-023 decision 1). It sits in its true place in
/// history; without the marker it would go unseen above what the reader already read.
pub const LATE_MARKER: &str = "[late] ";

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

fn sync_label(s: SyncStatus) -> String {
    match s {
        SyncStatus::Idle => "idle — no peer connected".to_owned(),
        SyncStatus::Connected(1) => "connected to 1 peer".to_owned(),
        SyncStatus::Connected(n) => format!("connected to {n} peers"),
    }
}

/// Render the whole UI for the current state. The timeline's scroll is clamped to what it drew,
/// so scrolling up past the oldest line leaves nothing to scroll back through.
pub fn render(frame: &mut Frame, vm: &ViewModel, ui: &mut UiState) {
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
        Screen::Tunnels => render_tunnels(frame, chunks[0], vm, ui),
    }
    render_status_bar(frame, chunks[1], vm);
    render_hint_bar(frame, chunks[2], ui, vm);

    match ui.mode {
        Mode::CommandPalette(ref buf) => render_palette(frame, area, buf),
        Mode::Prompt(ref p) => render_prompt(frame, area, p),
        Mode::Normal => {}
    }
}

/// The masked onboarding/unlock prompt: the current field's label and its
/// **masked** value (one `•` per character for secret fields), never the text.
fn render_prompt(frame: &mut Frame, area: Rect, p: &Prompt) {
    let h = 5.min(area.height);
    let y = area.height.saturating_sub(h);
    let overlay = Rect::new(area.x, y, area.width, h);
    let step = format!("{}/{}", p.step + 1, p.kind.fields().len());
    let body = vec![
        Line::from(format!("{} ({step}): {}", p.label(), p.display())),
        Line::from("Enter: next/submit · Esc: cancel"),
    ];
    let widget =
        Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(p.kind.title()));
    frame.render_widget(widget, overlay);
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
            let lock = if c.open { "" } else { " 🔒" };
            ListItem::new(format!(
                "{marker}{}{lock}{unread}  [{}]",
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

/// The live tunnels, one per line with its number, member, service and how long it has been
/// still, then those that ended for a reason, with that reason (V030-11).
fn render_tunnels(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &UiState) {
    let now = vox_core::transport::quic::unix_now();
    let ago = |t: u64| {
        let s = now.saturating_sub(t);
        if s < 120 {
            format!("{s}s")
        } else if s < 7200 {
            format!("{}m", s / 60)
        } else {
            format!("{}h", s / 3600)
        }
    };
    let short = |p: &vox_core::hash::Digest32| -> String {
        vox_core::node::link::b32_encode(p)
            .chars()
            .take(12)
            .collect()
    };
    let mut items: Vec<ListItem> = vm
        .tunnels
        .iter()
        .map(|t| {
            let marker = if ui.selected_tunnel == Some(t.id) {
                "▶ "
            } else {
                "  "
            };
            let way = if t.outbound { "to" } else { "from" };
            ListItem::new(format!(
                "{marker}tunnel {} {way} {} for {}: open {}, last moved {} ago",
                t.id,
                short(&t.peer),
                t.service,
                ago(t.opened),
                ago(t.last_moved)
            ))
        })
        .collect();
    if items.is_empty() {
        items.push(ListItem::new("  no tunnel is open"));
    }
    for t in vm.closed_tunnels.iter().rev() {
        let way = if t.outbound { "to" } else { "from" };
        items.push(ListItem::new(format!(
            "  tunnel {} {way} {} for {} was {} {} ago",
            t.id,
            short(&t.peer),
            t.service,
            t.why,
            ago(t.closed)
        )));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Tunnels (x: close the selected one · Esc: back)"),
    );
    frame.render_widget(list, area);
}

fn render_channel(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &mut UiState) {
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

    ui.timeline_scroll = render_timeline(
        frame,
        body[0],
        &channel.held_back,
        channel.timeline.as_slice(),
        ui.timeline_scroll,
        focused(ui, Focus::Timeline),
    );
    render_composer(frame, body[1], &ui.composer, focused(ui, Focus::Composer));
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

fn render_timeline(
    frame: &mut Frame,
    area: Rect,
    held_back: &[String],
    timeline: &[MessageView],
    scroll: usize,
    focus: bool,
) -> usize {
    // Who this room holds back for equivocating comes first, one line each (V210-66).
    let notices = held_back.iter().map(|n| {
        Line::from(Span::styled(
            format!("! {n}"),
            Style::default().add_modifier(Modifier::BOLD),
        ))
    });
    let lines: Vec<Line> = notices
        .chain(timeline.iter().map(|m| {
            let body = m
                .body
                .clone()
                .unwrap_or_else(|| UNDECRYPTABLE_MARKER.to_owned());
            let mut spans = Vec::with_capacity(3);
            if m.late {
                // In its true place, above rows already read: say so, or it goes unseen.
                spans.push(Span::styled(
                    LATE_MARKER,
                    Style::default().add_modifier(Modifier::DIM | Modifier::ITALIC),
                ));
            }
            spans.push(Span::styled(
                format!("{}: ", m.author_nick),
                Style::default().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(body));
            Line::from(spans)
        }))
        .collect();
    // The pane shows its newest lines, `scroll` lines up from the end (V210-82): drawn from the
    // top, a room that outgrew the pane hid every new message below its bottom edge. The lines
    // are wrapped here, not by the widget, so the count the window is taken from is the count
    // drawn; only as many as the window reaches back are.
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let height = usize::from(area.height.saturating_sub(2));
    let want = height.saturating_add(scroll);
    let mut rows: Vec<Line> = Vec::new();
    for l in lines.into_iter().rev() {
        rows.extend(wrap(l, width).into_iter().rev());
        if rows.len() >= want {
            break;
        }
    }
    rows.reverse();
    // Only a window that reached the oldest line can be short of `want`, so this is the most
    // there is to scroll; the scroll drawn is returned, and PageDown moves from it at once.
    let scroll = scroll.min(rows.len().saturating_sub(height));
    let bottom = rows.len() - scroll;
    let shown: Vec<Line> = rows[bottom.saturating_sub(height)..bottom].to_vec();
    let title = if scroll > 0 {
        "Timeline (scrolled — End: newest)"
    } else {
        "Timeline"
    };
    let p = Paragraph::new(shown).block(pane_block(title, focus));
    frame.render_widget(p, area);
    scroll
}

/// `line` broken into rows of at most `width` display columns, its styles kept.
fn wrap(line: Line<'_>, width: usize) -> Vec<Line<'_>> {
    let mut rows = Vec::new();
    let mut row = Line::default();
    let mut used = 0;
    for span in line.spans {
        let mut piece = String::new();
        for ch in span.content.chars() {
            let w = Span::raw(&*ch.encode_utf8(&mut [0; 4])).width();
            if used + w > width && used > 0 {
                row.spans
                    .push(Span::styled(std::mem::take(&mut piece), span.style));
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
            piece.push(ch);
            used += w;
        }
        if !piece.is_empty() {
            row.spans.push(Span::styled(piece, span.style));
        }
    }
    rows.push(row);
    rows
}

fn render_composer(frame: &mut Frame, area: Rect, text: &str, focus: bool) {
    let shown = if text.is_empty() && !focus {
        "type a message — Tab to focus the composer, : for commands".to_owned()
    } else if focus {
        format!("{text}▏")
    } else {
        text.to_owned()
    };
    let p = Paragraph::new(shown).block(pane_block("Composer", focus));
    frame.render_widget(p, area);
}

fn render_members(
    frame: &mut Frame,
    area: Rect,
    members: &[MemberView],
    selected: Option<vox_core::hash::Digest32>,
    focus: bool,
) {
    let items: Vec<ListItem> = members
        .iter()
        .map(|m| {
            // The marker is on the member a command would act on: the same identity (V210-82).
            let marker = if selected == Some(m.id) && focus {
                "▶ "
            } else {
                "  "
            };
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
    let lock = if vm.locking {
        "locking… waiting for work that holds a secret to finish"
    } else if vm.locked {
        "LOCKED"
    } else {
        "unlocked"
    };
    let mlock = if vm.mlock_active {
        String::new()
    } else {
        "  ⚠ mlock unavailable (zeroize-only)".to_owned()
    };
    let text = format!(" sync: {}  ·  {lock}{mlock}", sync_label(vm.sync));
    frame.render_widget(Paragraph::new(text), area);
}

fn render_hint_bar(frame: &mut Frame, area: Rect, ui: &UiState, vm: &ViewModel) {
    // A transient status/alert takes precedence over the static keybind hint, and a
    // core notice (an invite link, a join, a consent) over the hint but not over a
    // status the user's own last command produced.
    if let Some(msg) = ui.status_message.as_ref() {
        frame.render_widget(Paragraph::new(format!(" {msg}")), area);
        return;
    }
    if let Some(notice) = vm.notice.as_ref() {
        frame.render_widget(Paragraph::new(format!(" {notice}")), area);
        return;
    }
    let hint = match ui.screen {
        Screen::ChannelList => {
            " ↑/↓ select · Enter open · t tunnels · :new <name> · :join · :unlock · :lock · Ctrl-C quit"
        }
        Screen::Channel => {
            " Tab switch pane · Enter send · PgUp/PgDn scroll · :invite · :consent grant · : command · Esc back"
        }
        Screen::Tunnels => " ↑/↓ select · x close the selected tunnel · : command · Esc back",
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
