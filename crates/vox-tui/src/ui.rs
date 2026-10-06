//! The ratatui view (ADR-015 §"Navigation & input", §"Accessibility").
//!
//! A pure render: [`render`] draws the current [`ViewModel`] + [`UiState`] into a
//! ratatui [`Frame`]. The binary only ever draws to the **alternate screen**, so
//! decrypted text rendered here never enters the terminal's primary buffer /
//! scrollback (ADR-015 at-rest screen claim). Because rendering is a pure function
//! of state into a `Frame`, it is covered by `TestBackend` render-snapshot tests.
//!
//! ## Accessibility (ADR-015)
//! State is **never** signalled by colour alone: trust and reachability each render
//! as a text label (so they survive `NO_COLOR`, monochrome terminals, and screen
//! readers).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use vox_core::hash::Digest32;

use crate::state::{Focus, Mode, Prompt, Screen, UiState};
use crate::theme;
use crate::viewmodel::{MemberView, MessageView, Reachability, SyncStatus, Trust, ViewModel};

/// The honest non-leaking marker for an entry not decryptable to you (ADR-015).
pub const UNDECRYPTABLE_MARKER: &str = "[locked — not shared with you]";

/// Prefixed to a message that arrived after the rows below it were already shown — a member
/// who was offline, or a sync that caught up (ADR-023 decision 1). It sits in its true place in
/// history; without the marker it would go unseen above what the reader already read.
pub const LATE_MARKER: &str = "[late] ";
/// What begins the line under a message this node sent that names who has read it (ADR-028 R-6).
pub const READ_BY: &str = "read by ";
/// What marks a room's retention: in its header, and before each line saying it changed (ADR-028
/// R-7).
pub const RETENTION: &str = "⏱";

/// Where a member stands with you, in words: whether you trust it, and whether it reads you here.
/// Nothing for yourself.
#[must_use]
pub fn trust_label(t: Trust) -> Option<&'static str> {
    match t {
        Trust::You => None,
        Trust::Trusted { reads_you: true } => Some("trusted · reads you"),
        Trust::Trusted { reads_you: false } => Some("trusted · cannot read you yet"),
        Trust::NotTrusted { reads_you: true } => Some("not trusted · still reads you"),
        Trust::NotTrusted { reads_you: false } => Some("not trusted · you don't read each other"),
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
    // inspector; the tunnels view and the keyring view (#472) have the window to themselves.
    if ui.screen == Screen::Tunnels {
        render_tunnels(frame, chunks[0], vm, ui);
    } else if ui.screen == Screen::Keyring {
        render_keyring(frame, chunks[0], vm);
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
    let h = 5u16.saturating_add(note_rows).min(area.height);
    let y = area.height.saturating_sub(h);
    let overlay = Rect::new(area.x, y, area.width, h);
    let step = format!("{}/{}", p.step + 1, p.kind.fields().len());
    let mut body = vec![Line::from(format!(
        "{} ({step}): {}",
        p.label(),
        p.display()
    ))];
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

/// The inspector's width beside a room: 48 columns, where a member named by its 26-character
/// fingerprint and "(not in keyring)", and the longest trust label under it, fit; half the room's
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
        let lock = if c.open { "" } else { " 🔒" };
        items.push(ListItem::new(format!(
            "{marker}{}{lock}{unread}  [{}]",
            c.local_name,
            reachability_label(c.reachability)
        )));
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
        (&channel.retention, &channel.retention_changes),
        ui.timeline_scroll,
        focused(ui, Focus::Timeline),
    );
    render_composer(frame, body[1], &ui.composer, focused(ui, Focus::Composer));
    // Members above, and under them what is shared in the room (V030-25), when anything is.
    let side = if channel.shared.is_empty() {
        vec![cols[1]]
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),
                Constraint::Length(
                    u16::try_from(channel.shared.len().saturating_add(2)).unwrap_or(u16::MAX),
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
        let items: Vec<ListItem> = channel
            .shared
            .iter()
            .map(|s| ListItem::new(Line::from(s.clone())))
            .collect();
        frame.render_widget(List::new(items).block(pane_block("Shared", false)), *area);
    }
}

fn focused(ui: &UiState, pane: Focus) -> bool {
    ui.screen == Screen::Channel && ui.focus == pane && matches!(ui.mode, Mode::Normal)
}

fn render_timeline(
    frame: &mut Frame,
    area: Rect,
    held_back: &[String],
    timeline: &[MessageView],
    (retention, changes): (&str, &[(u64, String)]),
    scroll: usize,
    focus: bool,
) -> (usize, Vec<Digest32>) {
    // A retention change is one line in its place among the messages (ADR-028 R-7), by its time.
    let said = |text: &str| {
        Line::from(Span::styled(
            format!("{RETENTION} {text}"),
            Style::default().add_modifier(Modifier::DIM | Modifier::ITALIC),
        ))
    };
    let oldest = timeline.first().map_or(u64::MAX, |m| m.timestamp);
    let (before, among): (Vec<_>, Vec<_>) = changes.iter().partition(|(at, _)| at / 1_000 < oldest);
    let mut among = among.into_iter().rev().peekable();
    // Who this room holds back for equivocating comes first, one line each (V210-66).
    let notices = held_back.iter().map(|n| {
        Line::from(Span::styled(
            format!("! {n}"),
            Style::default().add_modifier(Modifier::BOLD),
        ))
    });
    // Built newest first and only as far back as the window reaches (V210-120): every frame built
    // a line for every message the room had ever held, so a long room cost each frame its history.
    let lines = timeline
        .iter()
        .rev()
        .flat_map(move |m| {
            // The changes newer than this message come before it: lines run newest first.
            let mut newer: Vec<(Option<Digest32>, Line)> = Vec::new();
            while let Some((_, text)) = among.next_if(|(at, _)| at / 1_000 >= m.timestamp) {
                newer.push((None, said(text)));
            }
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
            // Under a message it sent, who has read it, or where it is while nobody is known to
            // have (ADR-028 R-6). Lines run newest first here, so it goes before the message's own.
            let under = if m.read_by.is_empty() {
                m.whereabouts.clone()
            } else {
                format!("{READ_BY}{}", m.read_by)
            };
            let read_by = (!under.is_empty()).then(|| {
                Line::from(Span::styled(
                    format!("  {under}"),
                    Style::default().add_modifier(Modifier::DIM),
                ))
            });
            newer.into_iter().chain(
                read_by
                    .into_iter()
                    .chain(std::iter::once(Line::from(spans)))
                    .map(move |l| (Some(m.entry_hash), l)),
            )
        })
        .chain(before.into_iter().rev().map(|(_, text)| (None, said(text))))
        .chain(notices.rev().map(|l| (None, l)));
    // The pane shows its newest lines, `scroll` lines up from the end (V210-82): drawn from the
    // top, a room that outgrew the pane hid every new message below its bottom edge. The lines
    // are wrapped here, not by the widget, so the count the window is taken from is the count
    // drawn; only as many as the window reaches back are.
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let height = usize::from(area.height.saturating_sub(2));
    let want = height.saturating_add(scroll);
    let mut rows: Vec<Line> = Vec::new();
    // Which message each row belongs to, so the frame can say which messages it showed.
    let mut owners: Vec<Option<Digest32>> = Vec::new();
    for (owner, l) in lines {
        for row in wrap(l, width).into_iter().rev() {
            rows.push(row);
            owners.push(owner);
        }
        if rows.len() >= want {
            break;
        }
    }
    rows.reverse();
    owners.reverse();
    // Only a window that reached the oldest line can be short of `want`, so this is the most
    // there is to scroll; the scroll drawn is returned, and PageDown moves from it at once.
    let scroll = scroll.min(rows.len().saturating_sub(height));
    let bottom = rows.len() - scroll;
    let window = bottom.saturating_sub(height)..bottom;
    let shown: Vec<Line> = rows[window.clone()].to_vec();
    let mut on_screen: Vec<Digest32> = owners[window].iter().flatten().copied().collect();
    on_screen.dedup();
    // The room's header always says its retention (ADR-028 R-7).
    let title = if scroll > 0 {
        format!("Timeline · {RETENTION} {retention} (scrolled — End: newest)")
    } else {
        format!("Timeline · {RETENTION} {retention}")
    };
    let p = Paragraph::new(shown).block(pane_block(&title, focus));
    frame.render_widget(p, area);
    (scroll, on_screen)
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
            // Always words, never colour alone (a11y).
            let mut lines = vec![Line::from(format!("{marker}{}", m.nickname))];
            if let Some(label) = trust_label(m.trust) {
                lines.push(Line::from(format!("    {label}")));
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
                let mut lines = vec![Line::from(format!("  {}", vox_text::shown(alias, 64)))];
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

fn pane_block(title: &str, focus: bool) -> Block<'_> {
    let b = Block::default().borders(Borders::ALL).title(title);
    if focus {
        focus_block(b.title(format!("{title} [focus]")))
    } else {
        b.border_style(theme::fg(theme::LINE_HAIR))
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
    let mlock = if vm.mlock_active {
        String::new()
    } else {
        "  ⚠ mlock unavailable (zeroize-only)".to_owned()
    };
    // The keyring window (ADR-028 K-9): whether a keyring change will ask for the passphrase.
    let keyring = if vm.attached {
        format!("  ·  {}", keyring_label(vm.keyring_open_secs))
    } else {
        String::new()
    };
    let text = format!(" sync: {}  ·  {lock}{keyring}{mlock}", sync_label(vm.sync));
    frame.render_widget(Paragraph::new(text), area);
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
/// not over a status the user's own last command produced.
fn hint_text(ui: &UiState, vm: &ViewModel) -> String {
    if let Some(msg) = ui.status_message.as_ref() {
        return format!(" {msg}");
    }
    if let Some(notice) = vm.notice.as_ref() {
        return format!(" {notice}");
    }
    match ui.screen {
        Screen::ChannelList => {
            " ↑/↓ select · Enter open · t tunnels · k keyring · :new <name> · :join · :node <name> · :attach · Ctrl-C quit"
        }
        Screen::Channel => {
            " Tab switch pane · Enter send · PgUp/PgDn scroll · :link · : command · Esc back"
        }
        Screen::Tunnels => " ↑/↓ select · x close the selected tunnel · : command · Esc back",
        Screen::Keyring => " : command · Esc back",
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
