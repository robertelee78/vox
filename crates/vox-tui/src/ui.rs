//! The ratatui view (ADR-015 §"Navigation & input", §"Accessibility").
//!
//! A pure render: [`render`] draws the current [`ViewModel`] + [`UiState`] into a
//! ratatui [`Frame`]. The binary only ever draws to the **alternate screen**, so
//! decrypted text rendered here never enters the terminal's primary buffer /
//! scrollback (ADR-015 at-rest screen claim). Because rendering is a pure function
//! of state into a `Frame`, it is covered by `TestBackend` render-snapshot tests.
//!
//! ## Accessibility (ADR-015, ADR-028 E-6, L-3, L-4, L-8)
//! State is **never** signalled by colour alone: trust renders as a glyph, a weight and words,
//! reachability as a glyph and a word, a warning as `▲` or `✕` and its words, so each survives
//! `NO_COLOR`, monochrome terminals and screen readers. The accent marks only the focused pane and
//! what is live; it never marks trust, a warning or decoration.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use vox_core::hash::Digest32;

use crate::state::{Focus, Mode, Prompt, PromptKind, Screen, UiState};
use crate::theme;
use crate::viewmodel::{
    ImageState, MemberView, MessageView, NoticeView, Reachability, SyncStatus, Trust, ViewModel,
};

/// The honest non-leaking marker for an entry not decryptable to you (ADR-015).
pub const UNDECRYPTABLE_MARKER: &str = "[locked — not shared with you]";

/// Prefixed to a message that arrived after the rows below it were already shown — a member
/// who was offline, or a sync that caught up (ADR-023 decision 1). It sits in its true place in
/// history; without the marker it would go unseen above what the reader already read.
pub const LATE_MARKER: &str = "[late] ";
/// What begins the line under a message this node sent that names who has read it (ADR-028 R-6).
pub const READ_BY: &str = "read by ";
/// What leads the list of who pulled a share whole (ADR-028 F-7).
pub const PULLED_BY: &str = "pulled by ";
/// What marks a room's retention in its header (ADR-028 R-7).
pub const RETENTION: &str = "⏱";

/// The mark before the message selected in the timeline (ADR-028 R-9, #485).
pub const SELECTED_MARKER: &str = "▶ ";

/// The mark before a reply's quote of the message it answers, on the row above it.
pub const QUOTE_MARKER: &str = "  ┆ ";

/// The mark before an image a message shares, when it is named rather than drawn (ADR-028 F-11).
pub const IMAGE_MARKER: &str = "\u{25a3} image ";

/// What is said of an image a message shares until this node's copy is verified (ADR-028 F-11).
pub const IMAGE_UNVERIFIED: &str = "drawn once it is pulled and verified";

/// Where a member stands with you, in words: who reads whom, and what is still to do (ADR-028
/// R-5, #481), the states `vox room join` names ([`crate::ident::Reading`]). Nothing for yourself.
#[must_use]
pub fn trust_label(t: Trust) -> Option<&'static str> {
    match t {
        Trust::You => None,
        Trust::Trusted {
            trusts_you: true,
            reads_you: true,
        } => Some("trusted both ways"),
        Trust::Trusted {
            trusts_you: true,
            reads_you: false,
        } => Some("trusted both ways · cannot read you yet"),
        Trust::Trusted {
            trusts_you: false, ..
        } => Some("waiting for the other side"),
        // A member untrusted after it took your key still holds it: said first.
        Trust::NotTrusted { reads_you: true } => Some("not in keyring · still reads you"),
        Trust::NotTrusted { reads_you: false } => Some("not in keyring: trust to read each other"),
    }
}

/// A member's trust glyph and the style of its name (ADR-028 L-4): in text.primary bold, `⇄` for a
/// node in your keyring that trusts you too and `→` for one that does not (yet); `·` in
/// text.secondary for one not in your keyring; nothing for yourself.
fn trust_mark(t: Trust) -> (&'static str, Style) {
    let ascii = theme::ascii();
    match t {
        Trust::You => ("", theme::fg(theme::TEXT_PRIMARY)),
        Trust::Trusted { trusts_you, .. } => (
            match (ascii, trusts_you) {
                (true, true) => "<> ",
                (true, false) => "-> ",
                (false, true) => "⇄ ",
                (false, false) => "→ ",
            },
            theme::strong(theme::TEXT_PRIMARY),
        ),
        Trust::NotTrusted { .. } => (
            if ascii { ". " } else { "· " },
            theme::fg(theme::TEXT_SECONDARY),
        ),
    }
}

/// A warning's glyph: `▲` for what needs attention, `✕` for danger (ADR-028 L-2), `!` where the
/// terminal takes ASCII alone.
fn warn_glyph(danger: bool) -> &'static str {
    match (theme::ascii(), danger) {
        (true, _) => "!",
        (false, true) => "✕",
        (false, false) => "▲",
    }
}

/// A reachability glyph + word, and its style: a room whose members are connected is live, so it
/// alone takes the accent (ADR-028 L-3).
fn reachability_label(r: Reachability) -> (&'static str, Style) {
    match r {
        Reachability::Online => ("● online", theme::fg(theme::ACCENT)),
        Reachability::NeedsPeerOrNode => {
            ("◐ needs peer/node online", theme::fg(theme::TEXT_SECONDARY))
        }
        Reachability::Offline => ("○ offline", theme::fg(theme::TEXT_SECONDARY)),
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
    // Only a room drawn in this frame has messages on screen.
    ui.on_screen.clear();
    let area = frame.area();
    // The whole screen is drawn on the theme's base, not the terminal's own background (ADR-028
    // L-2); with no colour (NO_COLOR, a dumb terminal) this draws nothing.
    frame.render_widget(Block::default().style(theme::base()), area);
    let hint = hint_text(ui, vm);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(hint_rows(&hint, area.width)),
        ])
        .split(area);

    // The window's regions (ADR-028 W-1, #511): the sidebar beside the room, its timeline and its
    // inspector; the tunnels view, the keyring view (#472) and the decision record (ADR-028 D-3)
    // have the window to themselves.
    if ui.screen == Screen::Tunnels {
        render_tunnels(frame, chunks[0], vm, ui);
    } else if ui.screen == Screen::Keyring {
        render_keyring(frame, chunks[0], vm);
    } else if ui.screen == Screen::Decisions {
        render_decisions(frame, chunks[0], vm);
    } else if ui.screen == Screen::Serve {
        render_serve(frame, chunks[0], vm, ui);
    } else {
        let regions = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(sidebar_cols(chunks[0].width)),
                Constraint::Min(1),
            ])
            .split(chunks[0]);
        render_sidebar(frame, regions[0], vm, ui);
        if ui.screen == Screen::Channel {
            render_channel(frame, regions[1], vm, ui);
        } else {
            let p = Paragraph::new("No room open — Enter opens the room selected in the sidebar")
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(p, regions[1]);
        }
    }
    render_status_bar(frame, chunks[1], vm);
    frame.render_widget(Paragraph::new(hint).wrap(Wrap { trim: false }), chunks[2]);

    match ui.mode {
        Mode::CommandPalette(ref buf) => render_palette(frame, area, buf),
        Mode::Prompt(ref p) => render_prompt(frame, area, p),
        Mode::Normal => {}
    }
}

/// The masked onboarding/attach prompt: the current field's label and its
/// **masked** value (one `•` per character for secret fields), never the text.
fn render_prompt(frame: &mut Frame, area: Rect, p: &Prompt) {
    // A note gets the rows it wraps onto at this width, under the field.
    let note_rows = p.kind.note().map_or(0, |n| {
        u16::try_from(
            n.chars()
                .count()
                .div_ceil(usize::from(area.width.saturating_sub(2).max(1))),
        )
        .unwrap_or(u16::MAX)
    });
    // The trust prompt shows the node's fingerprint, grouped, beside its art (ADR-028 K-5), so
    // the person compares it by eye as well as by what they paste.
    let card: Vec<String> = match (p.kind, p.target) {
        (PromptKind::Trust, Some(fp)) => {
            let mut c = vec!["this node:".to_owned()];
            c.extend(vox_text::fingerprint::card(
                &vox_core::node::link::b32_encode(&fp),
            ));
            c
        }
        _ => Vec::new(),
    };
    let card_rows = u16::try_from(card.len()).unwrap_or(u16::MAX);
    let h = 5u16
        .saturating_add(note_rows)
        .saturating_add(card_rows)
        .min(area.height);
    let y = area.height.saturating_sub(h);
    let overlay = Rect::new(area.x, y, area.width, h);
    let step = format!("{}/{}", p.step + 1, p.kind.fields().len());
    let mut body: Vec<Line> = card.into_iter().map(Line::from).collect();
    body.push(Line::from(format!(
        "{} ({step}): {}",
        p.label(),
        p.display()
    )));
    if let Some(note) = p.kind.note() {
        body.push(Line::from(note));
    }
    body.push(Line::from("Enter: next/submit · Esc: cancel"));
    let widget = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(p.kind.title()));
    frame.render_widget(widget, overlay);
}

/// The sidebar's width for a window `width` columns wide: 30 % of it, at least 28 columns and at
/// most 48, where a room row with its unread levels and its reachability fits; the timeline keeps
/// the most room.
fn sidebar_cols(width: u16) -> u16 {
    (width * 30 / 100).clamp(28, 48)
}

/// The inspector's width beside a room: 48 columns, where a member named by its trust glyph and
/// 26-character fingerprint, and the longest trust label under it, fit; half the room's
/// area where that is less.
fn inspector_cols(width: u16) -> u16 {
    48.min(width / 2)
}

/// **The sidebar** (ADR-028 W-1, W-2, #511): the node this TUI acts as and whether it is attached;
/// the rooms, grouped by what they need from the person, each group with its count; and every node
/// on this machine, attached or detached. Beside an open room as beside the list; it holds the
/// focus (L-3) and names its keys only while the list is the pane in use.
fn render_sidebar(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &UiState) {
    let mut items: Vec<ListItem> = vec![ListItem::new(format!(
        "node {} · {}",
        vm.node,
        if vm.attached {
            "attached"
        } else {
            "not attached"
        }
    ))];
    let mut group = None;
    for (i, c) in vm.channels.iter().enumerate() {
        if group != Some(c.group) {
            group = Some(c.group);
            let n = vm.channels.iter().filter(|o| o.group == c.group).count();
            items.push(
                ListItem::new(format!("{} ({n})", c.group.label()))
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            );
        }
        let marker = if i == ui.selected_channel {
            "▶ "
        } else {
            "  "
        };
        // The three unread levels (ADR-028 R-8, #484): to this node first.
        let levels: Vec<String> = [
            (c.to_you > 0).then(|| format!("to you {}", c.to_you)),
            (c.unread > 0).then(|| format!("{} new", c.unread)),
            (c.coordination > 0).then(|| format!("{} coordination", c.coordination)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let unread = if levels.is_empty() {
            String::new()
        } else {
            format!(" ({})", levels.join(" · "))
        };
        // In words, never a padlock (ADR-028 L-8).
        let closed = if c.open { "" } else { " (closed)" };
        let (reach, reach_style) = reachability_label(c.reachability);
        items.push(ListItem::new(Line::from(vec![
            Span::raw(format!("{marker}{}{closed}{unread}  [", c.name)),
            Span::styled(reach, reach_style),
            Span::raw("]"),
        ])));
    }
    if !vm.machine_nodes.is_empty() {
        items.push(
            ListItem::new("nodes on this machine")
                .style(Style::default().add_modifier(Modifier::BOLD)),
        );
        for (name, attached) in &vm.machine_nodes {
            items.push(ListItem::new(format!(
                "  {name}  {}",
                if *attached { "attached" } else { "detached" }
            )));
        }
    }
    let listing = ui.screen == Screen::ChannelList;
    let title = if listing {
        "Rooms (Enter: open · Ctrl-N: next room to you · : command)"
    } else {
        "Rooms"
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let list = List::new(items).block(if listing { focus_block(block) } else { block });
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

/// What this node decided, newest first, one line each (ADR-028 D-3): when, what, about whom (this
/// node's name for them, else their fingerprint's start), what was asked and why.
fn render_decisions(frame: &mut Frame, area: Rect, vm: &ViewModel) {
    let now_ms = vox_core::transport::quic::unix_now().saturating_mul(1_000);
    let ago = |at_ms: u64| {
        let s = now_ms.saturating_sub(at_ms) / 1_000;
        if s < 120 {
            format!("{s}s")
        } else if s < 7_200 {
            format!("{}m", s / 60)
        } else if s < 172_800 {
            format!("{}h", s / 3_600)
        } else {
            format!("{}d", s / 86_400)
        }
    };
    let mut items: Vec<ListItem> = vm
        .decisions
        .iter()
        .map(|e| {
            let short: String = e.by.chars().take(12).collect();
            let who = e
                .alias
                .as_ref()
                .map_or_else(|| short.clone(), |a| format!("{a} ({short})"));
            ListItem::new(format!(
                "  {:>4} ago  {} {who}: {} — {}",
                ago(e.at_ms),
                e.decided,
                e.asked,
                e.why
            ))
        })
        .collect();
    if items.is_empty() {
        items.push(ListItem::new(
            "  this node has decided nothing in the last 14 days",
        ));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Decisions (newest first · kept 14 days · Esc: back)"),
    );
    frame.render_widget(list, area);
}

/// Sharing a service listening on this machine into the room (ADR-028 S-4), as `vox serve` with
/// no name does: what listens here, then, for the one picked, what is said before it is shared.
fn render_serve(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &UiState) {
    if let Some(p) = vm.serve_preview.as_ref() {
        let lines: Vec<Line> = p
            .lines
            .iter()
            .map(|l| Line::from(format!("  {l}")))
            .chain(std::iter::once(Line::from("")))
            .chain(std::iter::once(Line::from(
                "  Enter: share it in this room · Esc: back to the list",
            )))
            .collect();
        let w = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(pane_block("Share a service", true));
        frame.render_widget(w, area);
        return;
    }
    let mut items: Vec<ListItem> = vm
        .listening
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let marker = if i == ui.selected_listening {
                "▶ "
            } else {
                "  "
            };
            ListItem::new(format!("{marker}{}", l.line))
        })
        .collect();
    if items.is_empty() {
        items.push(ListItem::new(
            "  nothing listening on this machine can be seen from here",
        ));
    }
    items.push(ListItem::new(format!(
        "  {}",
        crate::tunnel_cli::MAY_BE_MISSING
    )));
    let list = List::new(items).block(pane_block(
        "Services listening on this machine (Enter: preview · Esc: back)",
        true,
    ));
    frame.render_widget(list, area);
}

fn render_channel(frame: &mut Frame, area: Rect, vm: &ViewModel, ui: &mut UiState) {
    let Some(channel) = vm.active.as_ref() else {
        let p = Paragraph::new("No room open").block(Block::default().borders(Borders::ALL));
        frame.render_widget(p, area);
        return;
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(inspector_cols(area.width)),
        ])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(cols[0]);

    (ui.timeline_scroll, ui.on_screen) = render_timeline(
        frame,
        body[0],
        &channel.held_back,
        channel.timeline.as_slice(),
        (&channel.notices, &channel.retention),
        Selection {
            scroll: ui.timeline_scroll,
            selected: ui.selected_message,
            reveal: std::mem::take(&mut ui.reveal_selected),
            focus: focused(ui, Focus::Timeline),
        },
        &mut ui.images.borrow_mut(),
    );
    // Whom the next message is to, and whether it is urgent (ADR-028 W-4), by this node's names.
    let mut about = Vec::new();
    if !ui.to.is_empty() {
        let names: Vec<String> = ui
            .to
            .iter()
            .map(|id| {
                channel.members.iter().find(|m| m.id == *id).map_or_else(
                    || vox_core::node::link::b32_encode(id),
                    |m| m.nickname.clone(),
                )
            })
            .collect();
        about.push(format!("To: {}", names.join(", ")));
    }
    if ui.urgent {
        about.push("urgent".to_owned());
    }
    // What a reply answers, named in its composer's title until it is sent (ADR-028 R-9).
    let replying = ui.replying.map(|re| {
        channel
            .timeline
            .iter()
            .find(|m| m.entry_hash == re)
            .map_or_else(
                || "a message".to_owned(),
                |m| {
                    let words = m.body.as_deref().unwrap_or(UNDECRYPTABLE_MARKER);
                    let first: String = words
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .chars()
                        .take(40)
                        .collect();
                    format!("{}: {first}", m.author_nick)
                },
            )
    });
    render_composer(
        frame,
        body[1],
        &ui.composer,
        replying.as_deref(),
        &about.join(" · "),
        focused(ui, Focus::Composer),
    );
    // Members above, and under them what is shared in the room (V030-25), when anything is.
    let shared_focus = focused(ui, Focus::Shared);
    // The pane's inner width: the command under the selected service is printed in full there,
    // wrapped, since it is longer than a line (ADR-028 S-3).
    let inner = usize::from(cols[1].width.saturating_sub(2)).max(20);
    let shared_lines = shared_lines(&channel.shared, ui.selected_share, shared_focus, inner);
    let side = if channel.shared.is_empty() {
        vec![cols[1]]
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),
                Constraint::Length(
                    u16::try_from(shared_lines.len().saturating_add(2)).unwrap_or(u16::MAX),
                ),
            ])
            .split(cols[1])
            .to_vec()
    };
    render_members(
        frame,
        side[0],
        &channel.members,
        ui.selected_member,
        focused(ui, Focus::Members),
    );
    if let Some(area) = side.get(1) {
        let items: Vec<ListItem> = shared_lines.into_iter().map(ListItem::new).collect();
        frame.render_widget(
            List::new(items).block(pane_block("Shared", shared_focus)),
            *area,
        );
    }
}

/// The Shared pane's lines (ADR-028 S-3): each service, and under the one selected while the pane
/// has focus, what it needs that does not hold and, in full, the command `y` copies.
fn shared_lines(
    shared: &[crate::viewmodel::SharedView],
    selected: usize,
    focus: bool,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, s) in shared.iter().enumerate() {
        let here = focus && i == selected.min(shared.len().saturating_sub(1));
        lines.push(Line::from(format!(
            "{}{}",
            if here { "▶ " } else { "  " },
            s.line
        )));
        if here {
            for m in &s.missing {
                lines.push(Line::from(format!("    needs: {m}")));
            }
            lines.push(Line::from("    y copies:"));
            let chars: Vec<char> = s.copy.chars().collect();
            for chunk in chars.chunks(width.saturating_sub(6).max(10)) {
                lines.push(Line::from(format!(
                    "      {}",
                    chunk.iter().collect::<String>()
                )));
            }
        }
    }
    lines
}

fn focused(ui: &UiState, pane: Focus) -> bool {
    ui.screen == Screen::Channel && ui.focus == pane && matches!(ui.mode, Mode::Normal)
}

/// Where the timeline is: scrolled `scroll` lines up from its newest, and the message selected,
/// which `reveal` says to scroll into view on this draw; and whether it has the focus.
struct Selection {
    scroll: usize,
    selected: Option<Digest32>,
    reveal: bool,
    focus: bool,
}

fn render_timeline(
    frame: &mut Frame,
    area: Rect,
    held_back: &[String],
    timeline: &[MessageView],
    // What happened to the room, and its retention, for the header.
    (room_notices, retention): (&[NoticeView], &str),
    at: Selection,
    images: &mut crate::images::Images,
) -> (usize, Vec<Digest32>) {
    let Selection {
        mut scroll,
        selected,
        reveal,
        focus,
    } = at;
    // Who this room holds back for equivocating comes first, one line each (V210-66).
    let notices = held_back.iter().map(|n| {
        Line::from(Span::styled(
            format!("{} {n}", warn_glyph(true)),
            theme::strong(theme::DANGER),
        ))
    });
    // What happened to the room, one line each among the messages by time (ADR-028 E-5): `ann
    // renamed the room to family`. Never a message: no author, nothing to reply to.
    let notice_line = |n: &NoticeView| {
        Line::from(Span::styled(
            format!("· {}", n.text),
            Style::default().add_modifier(Modifier::DIM | Modifier::ITALIC),
        ))
    };
    let mut said = room_notices.iter().rev().peekable();
    // The pane shows its newest lines, `scroll` lines up from the end (V210-82): drawn from the
    // top, a room that outgrew the pane hid every new message below its bottom edge. The lines
    // are wrapped here, not by the widget, so the count the window is taken from is the count
    // drawn. Built newest first and only as far back as the window reaches (V210-120): every
    // frame built a line for every message the room had ever held, so a long room cost each
    // frame its history.
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let height = usize::from(area.height.saturating_sub(2));
    let want = height.saturating_add(scroll);
    let mut rows: Vec<Line> = Vec::new();
    // Which message each row belongs to, so the frame can say which messages it showed.
    let mut owners: Vec<Option<Digest32>> = Vec::new();
    // The rows kept for an image drawn over them, by which image (ADR-028 F-11).
    let mut pics: Vec<Option<usize>> = Vec::new();
    let mut drawn: Vec<(Digest32, std::sync::Arc<image::DynamicImage>)> = Vec::new();
    let mut push = |rows: &mut Vec<Line<'static>>,
                    owner: Option<Digest32>,
                    pic: Option<usize>,
                    l: Line<'static>| {
        for row in wrap(l, width).into_iter().rev() {
            rows.push(row);
            owners.push(owner);
            pics.push(pic);
        }
    };
    let mut reached_oldest = true;
    // While the selected message must be scrolled to, the rows go on until all of its are in.
    let seek = reveal && selected.is_some();
    let mut found = false;
    for m in timeline.iter().rev() {
        if rows.len() >= want && (!seek || found) {
            reached_oldest = false;
            break;
        }
        while let Some(n) = said.next_if(|n| n.timestamp > m.timestamp) {
            push(&mut rows, None, None, notice_line(n));
        }
        // Under a message it sent, who has read it, or where it is while nobody is known to
        // have (ADR-028 R-6). Rows run newest first here, so it goes before the message's own.
        // `pulled by agent-2 · read by ann` (ADR-028 F-7).
        let read = if m.read_by.is_empty() {
            m.whereabouts.clone()
        } else {
            format!("{READ_BY}{}", m.read_by)
        };
        let under = match (m.pulled_by.is_empty(), read.is_empty()) {
            (true, _) => read,
            (false, true) => format!("{PULLED_BY}{}", m.pulled_by),
            (false, false) => format!("{PULLED_BY}{} \u{b7} {read}", m.pulled_by),
        };
        if !under.is_empty() {
            let l = Line::from(Span::styled(
                format!("  {under}"),
                Style::default().add_modifier(Modifier::DIM),
            ));
            push(&mut rows, Some(m.entry_hash), None, l);
        }
        // **An image it shares, under it** (ADR-028 F-11): drawn once this node's copy is
        // verified, on a terminal that draws images; otherwise said in words.
        if let Some(img) = &m.image {
            match &img.state {
                ImageState::Ready(decoded) if images.draws() => {
                    let at = drawn.len();
                    drawn.push((m.entry_hash, std::sync::Arc::clone(decoded)));
                    for _ in 0..crate::images::IMAGE_ROWS {
                        push(&mut rows, Some(m.entry_hash), Some(at), Line::default());
                    }
                }
                state => {
                    let l = Line::from(Span::styled(
                        format!(
                            "  {IMAGE_MARKER}{} {}\u{d7}{} \u{2014} {}",
                            vox_agentcomms::envelope::reveal_keeping(&img.name, |_| false),
                            img.width,
                            img.height,
                            match state {
                                ImageState::Unverified => IMAGE_UNVERIFIED,
                                ImageState::Ready(_) => "verified; this terminal draws no images",
                                ImageState::NotDrawn(why) => why,
                            }
                        ),
                        Style::default().add_modifier(Modifier::DIM),
                    ));
                    push(&mut rows, Some(m.entry_hash), None, l);
                }
            }
        }
        let chosen = selected == Some(m.entry_hash);
        push(&mut rows, Some(m.entry_hash), None, message_line(m, chosen));
        // **The one message this replies to, quoted above it** (ADR-028 R-9, #485).
        if let Some(q) = &m.quote {
            let l = Line::from(Span::styled(
                format!(
                    "{QUOTE_MARKER}{}",
                    q.text.as_deref().map_or_else(
                        || "(a message this room does not hold yet)".to_owned(),
                        |t| vox_agentcomms::envelope::reveal_keeping(t, |_| false),
                    )
                ),
                Style::default().add_modifier(Modifier::DIM | Modifier::ITALIC),
            ));
            push(&mut rows, Some(m.entry_hash), None, l);
        }
        found |= chosen;
    }
    if reached_oldest {
        for l in said.map(notice_line).chain(notices.rev()) {
            push(&mut rows, None, None, l);
        }
    }
    rows.reverse();
    owners.reverse();
    pics.reverse();
    if seek {
        // Into view: its top row no higher than the window's, its bottom no lower. Counted up
        // from the newest row, as `scroll` is.
        let up = |i: usize| rows.len() - 1 - i;
        if let (Some(top), Some(low)) = (
            owners.iter().position(|o| o.is_some() && *o == selected),
            owners.iter().rposition(|o| o.is_some() && *o == selected),
        ) {
            let (from, to) = (up(low), up(top) + 1);
            if to > scroll + height {
                scroll = to.saturating_sub(height);
            }
            if from < scroll {
                scroll = from;
            }
        }
    }
    // Only a window that reached the oldest line can be short of `want`, so this is the most
    // there is to scroll; the scroll drawn is returned, and PageDown moves from it at once.
    let scroll = scroll.min(rows.len().saturating_sub(height));
    let bottom = rows.len() - scroll;
    let window = bottom.saturating_sub(height)..bottom;
    let shown: Vec<Line> = rows[window.clone()].to_vec();
    let mut on_screen: Vec<Digest32> = owners[window.clone()].iter().flatten().copied().collect();
    on_screen.dedup();
    // The room's header always says its retention (ADR-028 R-7).
    let title = if scroll > 0 {
        format!("Timeline · {RETENTION} {retention} (scrolled — End: newest)")
    } else {
        format!("Timeline · {RETENTION} {retention}")
    };
    let p = Paragraph::new(shown).block(pane_block(&title, focus));
    frame.render_widget(p, area);
    // Each image whose rows are all in the window is drawn over them; one cut by its edge is not.
    for (at, (entry, img)) in drawn.iter().enumerate() {
        let mine: Vec<usize> = window.clone().filter(|i| pics[*i] == Some(at)).collect();
        if mine.len() == usize::from(crate::images::IMAGE_ROWS) {
            let y = u16::try_from(mine[0] - window.start).unwrap_or(u16::MAX);
            let rect = Rect::new(
                area.x + 1,
                area.y.saturating_add(1).saturating_add(y),
                area.width.saturating_sub(2),
                crate::images::IMAGE_ROWS,
            );
            images.draw(frame, rect, *entry, img);
        }
    }
    (scroll, on_screen)
}

/// One message as the timeline draws it: who, to whom, and what it says; `chosen` marks it
/// selected.
fn message_line(m: &MessageView, chosen: bool) -> Line<'static> {
    // Characters a reader cannot see are shown as escapes (#331).
    let body = m.body.as_deref().map_or_else(
        || UNDECRYPTABLE_MARKER.to_owned(),
        |b| vox_agentcomms::envelope::reveal_keeping(b, |c| c == '\n' || c == '\t'),
    );
    let mut spans = Vec::with_capacity(3);
    if m.late {
        // In its true place, above rows already read: say so, or it goes unseen.
        spans.push(Span::styled(
            LATE_MARKER,
            Style::default().add_modifier(Modifier::DIM | Modifier::ITALIC),
        ));
    }
    spans.push(Span::styled(
        if m.addressed.is_empty() {
            format!("{}: ", m.author_nick)
        } else {
            format!("{} {}: ", m.author_nick, m.addressed)
        },
        Style::default().add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(body));
    if chosen {
        spans.insert(
            0,
            Span::styled(
                SELECTED_MARKER,
                Style::default().add_modifier(Modifier::BOLD),
            ),
        );
    }
    Line::from(spans)
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

fn render_composer(
    frame: &mut Frame,
    area: Rect,
    text: &str,
    replying: Option<&str>,
    about: &str,
    focus: bool,
) {
    let shown = if text.is_empty() && !focus {
        "type a message — Tab to focus the composer, : for commands".to_owned()
    } else if focus {
        format!("{text}▏")
    } else {
        text.to_owned()
    };
    // What a reply answers (ADR-028 R-9), and whom it is to and whether it is urgent (W-4).
    let mut said: Vec<String> = Vec::new();
    if let Some(r) = replying {
        said.push(format!("replying to {r} (Esc: not a reply)"));
    }
    if !about.is_empty() {
        said.push(about.to_owned());
    }
    let title = if said.is_empty() {
        "Composer".to_owned()
    } else {
        format!("Composer — {}", said.join(" · "))
    };
    let p = Paragraph::new(shown).block(pane_block(&title, focus));
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
            // Glyph, weight and words, never colour alone (ADR-028 L-4, E-6).
            let (glyph, style) = trust_mark(m.trust);
            let mut lines = vec![Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("{glyph}{}", m.nickname), style),
            ])];
            if let Some(label) = trust_label(m.trust) {
                lines.push(Line::from(Span::styled(
                    format!("    {label}"),
                    theme::fg(theme::TEXT_SECONDARY),
                )));
            }
            // The selected member's card (ADR-028 K-1, L-9): its fingerprint whole and grouped,
            // with its art beside it, never the art alone.
            if selected == Some(m.id) && focus {
                for row in vox_text::fingerprint::card(&vox_core::node::link::b32_encode(&m.id)) {
                    lines.push(Line::from(format!("    {row}")));
                }
            }
            ListItem::new(lines)
        })
        .collect();
    let list = List::new(items).block(pane_block("Members", focus));
    frame.render_widget(list, area);
}

/// The trust keyring (ADR-028 W-1, K-1): each node by your name for it, with its fingerprint
/// whole and grouped and its art beside it.
fn render_keyring(frame: &mut Frame, area: Rect, vm: &ViewModel) {
    let items: Vec<ListItem> = if vm.keyring.is_empty() {
        vec![ListItem::new(Line::from(
            "  you trust no node yet (`vox trust add`)",
        ))]
    } else {
        vm.keyring
            .iter()
            .map(|(fp, alias)| {
                // An alias another differs from only by case is told apart (ADR-028 K-4).
                let alias =
                    crate::ident::alias_of(&vm.keyring, fp).unwrap_or_else(|| alias.clone());
                let mut lines = vec![Line::from(format!("  {}", vox_text::shown(&alias, 64)))];
                for row in vox_text::fingerprint::card(&vox_core::node::link::b32_encode(fp)) {
                    lines.push(Line::from(format!("    {row}")));
                }
                lines.push(Line::from(""));
                ListItem::new(lines)
            })
            .collect()
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Keyring (Esc: back)"),
    );
    frame.render_widget(list, area);
}

/// A pane's frame, its title said once: "Members", or "Members [focus]" while it holds the focus.
fn pane_block(title: &str, focus: bool) -> Block<'static> {
    let b = Block::default().borders(Borders::ALL);
    if focus {
        focus_block(b.title(format!("{title} [focus]")))
    } else {
        b.title(title.to_owned())
            .border_style(theme::fg(theme::LINE_HAIR))
    }
}

/// A focused pane's border: the accent, bold, so focus reads by weight where there is no colour
/// (ADR-028 L-3, E-6).
fn focus_block(b: Block<'_>) -> Block<'_> {
    b.border_style(theme::fg(theme::ACCENT).add_modifier(Modifier::BOLD))
}

fn render_status_bar(frame: &mut Frame, area: Rect, vm: &ViewModel) {
    // Which node's rooms are on screen, and every node the daemon has attached (ADR-015 9.1,
    // ADR-026 S-4). There is no locked state: a node is attached, or waits for its passphrase.
    let node = if vm.attached {
        format!("node {}", vm.node)
    } else {
        format!("node {} (not attached)", vm.node)
    };
    let lock = if vm.nodes.is_empty() {
        format!("{node}  ·  attached: none")
    } else {
        format!("{node}  ·  attached: {}", vm.nodes.join(", "))
    };
    // The keyring window (ADR-028 K-9): whether a keyring change will ask for the passphrase.
    let keyring = if vm.attached {
        format!("  ·  {}", keyring_label(vm.keyring_open_secs))
    } else {
        String::new()
    };
    let mut spans = vec![Span::raw(format!(
        " sync: {}  ·  {lock}{keyring}",
        sync_label(vm.sync)
    ))];
    if !vm.mlock_active {
        spans.push(Span::styled(
            format!("  {} mlock unavailable (zeroize-only)", warn_glyph(false)),
            theme::fg(theme::ATTENTION),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The keyring window as the status bar and `vox status` say it (ADR-028 K-9): `keyring open 23m`
/// while a keyring change goes without the passphrase, rounded up so an open window never reads
/// `0m`; `keyring asks for the passphrase` once it will ask.
#[must_use]
pub fn keyring_label(open_secs: Option<u64>) -> String {
    match open_secs {
        Some(left) => format!("keyring open {}m", left.div_ceil(60).max(1)),
        None => "keyring asks for the passphrase".to_owned(),
    }
}

/// The most rows the line under the status bar takes: a long notice wraps onto as many as this,
/// and no more, so the screen above it keeps its room.
pub const HINT_ROWS_MAX: u16 = 4;

/// How many rows `hint` takes wrapped at `width` columns: at least one, at most [`HINT_ROWS_MAX`].
///
/// **A notice is read whole** (#410): what attaching a node said — the anchors file's path, each
/// line it skipped, that it carries on with no anchor — ran past the screen's edge on one row, and
/// the part that said it carries on was cut off.
fn hint_rows(hint: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    // Wrapped at word boundaries, a line can need one more row than its length alone says.
    let rows = match hint.chars().count().div_ceil(width) {
        0 | 1 => 1,
        n => n + 1,
    };
    u16::try_from(rows)
        .unwrap_or(HINT_ROWS_MAX)
        .min(HINT_ROWS_MAX)
}

/// What the line under the status bar says. A transient status/alert takes precedence over the
/// static keybind hint, and a core notice (an invite link, a join, a consent) over the hint but
/// not over a status the user's own last command produced after it (a notice that arrives later
/// clears that status: `event_loop`).
fn hint_text(ui: &UiState, vm: &ViewModel) -> String {
    if let Some(msg) = ui.status_message.as_ref() {
        return format!(" {msg}");
    }
    if let Some(notice) = vm.notice.as_ref() {
        return format!(" {notice}");
    }
    match ui.screen {
        Screen::ChannelList => {
            " ↑/↓ select · Enter open · t tunnels · k keyring · d decisions · :new <name> · :join · :attach · Ctrl-C quit"
        }
        Screen::Channel => {
            " Tab switch pane · ↑/↓ select · Ctrl-R reply · Enter send, or go to the quoted · PgUp/PgDn scroll · :to <name> · :urgent · :share <path> · :link · : command · Esc back"
        }
        Screen::Tunnels => " ↑/↓ select · x close the selected tunnel · : command · Esc back",
        Screen::Serve if vm.serve_preview.is_some() => " Enter share it · Esc back to the list",
        Screen::Serve => " ↑/↓ select · Enter preview · :serve <port> · Esc back to the room",
        Screen::Keyring => " : command · Esc back",
        Screen::Decisions => " what this node decided, newest first · : command · Esc back",
    }
    .to_owned()
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
