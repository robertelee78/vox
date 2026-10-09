// The main window (ADR-028 W-1, W-2; ADR-014 M-13): a sidebar with the node, its rooms grouped by
// what they need from the person and the nodes on this Mac; the room's timeline; an inspector with
// its members and their trust; and a status bar with the node, its peers and the keyring window.
// The keyring is a view of this window, not a window of its own.

import AppKit
import SwiftUI

struct MainWindow: View {
    @ObservedObject var model: NodeModel
    /// The sidebar's width at launch, the one last kept, read once for this window.
    @State private var sidebarIdeal = Columns.width(.sidebar)

    var body: some View {
        VStack(spacing: 0) {
            if model.ended != nil {
                NodeStopped(model: model)
                Divider()
            }
            NavigationSplitView {
                // Dragged wider or narrower, and remembered (Columns).
                Sidebar(model: model)
                    .onAppear { Columns.keepSidebarWidth() }
                    .navigationSplitViewColumnWidth(min: Columns.Side.sidebar.min,
                                                    ideal: sidebarIdeal,
                                                    max: Columns.Side.sidebar.max)
            } detail: {
                // Every word shown here can be selected and copied (the decider, v0.4.1): set
                // once for the whole detail, so a view added later is selectable too.
                Group {
                switch model.selection {
                case let .room(id):
                    // One view per room: its draft, To:, urgent and attachment do not carry over.
                    RoomView(model: model, room: id).id(id)
                case .keyring:
                    KeyringView(model: model)
                case .decisions:
                    DecisionsView(model: model)
                case .services:
                    ServicesView(model: model)
                case let .offer(fingerprint):
                    OfferView(model: model, fingerprint: fingerprint).id(fingerprint)
                case nil where model.rooms.isEmpty:
                    // A node in no room yet (its first run, most often): the two ways in, here,
                    // not only in the File menu.
                    VStack(spacing: Space.s12) {
                        Text("You are in no room yet.").title()
                        Text("Make a room and share its link, or join one with the link and "
                            + "passphrase someone sent you.")
                            .secondaryText()
                            .multilineTextAlignment(.center)
                        HStack {
                            Button("New Room…") { model.sheet = .newRoom }
                                .keyboardShortcut(.defaultAction)
                                .buttonStyle(.voxPrimary)
                                .accessibilityIdentifier("empty-new-room")
                            Button("Join Room…") { model.sheet = .joinRoom }
                                .accessibilityIdentifier("empty-join-room")
                        }
                    }
                    .accessibilityElement(children: .contain)
                    .accessibilityIdentifier("no-room-yet")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                case nil:
                    Text("Pick a room.")
                        .secondaryText()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                }
                .textSelection(.enabled)
            }
            Hairline()
            StatusBar(model: model)
                .raisedSurface()
                .textSelection(.enabled)
        }
        .contentSurface()
        // The Dock says how many things need the person, the same count as the sidebar's NEEDS
        // YOU: rooms (a message to them, or a Session waiting on them) and trust offers. Gone
        // while nothing does, and when the window is.
        .onAppear { DockBadge.show(model.needsYouCount) }
        .onChange(of: model.needsYouCount) { DockBadge.show($0) }
        .onDisappear { DockBadge.show(0) }
        .sheet(item: $model.sheet) { NodeSheets(model: model, sheet: $0).textSelection(.enabled) }
        .sheet(item: $model.card) { node in
            NodeCard(model: model, node: node) { model.card = nil }.textSelection(.enabled)
                .panelSurface()
        }
        .toolbar {
            // W-2: a key moves to the next room that needs the person; Control-N, as in the TUI.
            Button("Next Room That Needs You") { Task { await model.nextNeedingYou() } }
                .keyboardShortcut("n", modifiers: .control)
                .accessibilityIdentifier("next-needs-you")
            // The inspector, shown or hidden, as the sidebar's own button does for the sidebar.
            Button { model.inspectorShown.toggle() } label: {
                Label(model.inspectorShown ? "Hide Inspector" : "Show Inspector",
                      systemImage: "sidebar.right")
            }
            .help(model.inspectorShown ? "Hide Inspector (⌥⌘I)" : "Show Inspector (⌥⌘I)")
            .accessibilityIdentifier("toggle-inspector")
        }
    }
}

/// The node, its rooms by need with counts, the keyring, and the nodes on this Mac.
private struct Sidebar: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        // Selected at once, then read: the list never sees the old selection come back.
        List(selection: Binding(get: { model.selection },
                                set: { s in
                                    model.select(s)
                                    Task { await model.show(s) }
                                })) {
            // Who you are, first (G5): the node's mark, its name, and that it is attached.
            Section {
                NodeIdentity(name: model.node, attached: model.ended == nil)
                    .copyMenu([("Copy Name", model.node)])
                    .accessibilityIdentifier(model.ended == nil ? "attached" : "detached")
                    .background(SidebarHighlightOff())
            }
            ForEach([RoomGroup.needsYou, .active, .quiet], id: \.self) { need in
                let rooms = model.group(need)
                // A trust offer waiting needs the person too (ADR-028 K-15, W-2).
                let offers = need == .needsYou ? model.offers : []
                let count = rooms.count + offers.count
                Section {
                    ForEach(rooms) { room in
                        RoomRow(room: room, selected: model.selection == .room(room.id))
                            .tag(NodeModel.Selection.room(room.id))
                            .sidebarRow(model.selection == .room(room.id))
                            .copyMenu([("Copy Name", room.name)])
                    }
                    ForEach(offers, id: \.fingerprint) { offer in
                        OfferRow(offer: offer).tag(NodeModel.Selection.offer(offer.fingerprint))
                            .sidebarRow(model.selection == .offer(offer.fingerprint))
                            .copyMenu([("Copy Fingerprint", offer.fingerprint)])
                    }
                } header: {
                    Text("\(need.words) (\(count))")
                        .eyebrow()
                        .accessibilityIdentifier("group-\(need.words)")
                        .accessibilityLabel("\(need.words) (\(count))")
                }
            }
            Section {
                Text("Keyring").tag(NodeModel.Selection.keyring)
                    .sidebarRow(model.selection == .keyring)
                    .accessibilityIdentifier("keyring")
                Text("Decision record").tag(NodeModel.Selection.decisions)
                    .sidebarRow(model.selection == .decisions)
                    .accessibilityIdentifier("decisions")
                Text("Services").tag(NodeModel.Selection.services)
                    .sidebarRow(model.selection == .services)
                    .accessibilityIdentifier("services")
            }
        }
        .listStyle(.sidebar)
        // The nodes on this Mac, at the sidebar's foot (G5), whatever the rooms above scroll to.
        .safeAreaInset(edge: .bottom, spacing: 0) { OnThisMachine(nodes: model.nodes) }
        // On bg.panel, not the system's sidebar material (L-6), drawn where the sidebar's
        // vibrancy cannot tint it (PanelFill).
        .scrollContentBackground(.hidden)
        .background(PanelFill())
        .foregroundStyle(VoxTokens.Colors.textPrimary)
        // The sidebar's rows keep macOS's sidebar size (System Settings, Appearance, Sidebar icon
        // size), never the conversation's text size (the decider, v0.4.1).
        .font(nil)
        .environment(\.defaultMinListRowHeight, Theme.scaled(24))
    }
}

extension View {
    /// A sidebar row's fill while it is the one selected: the selection token, on which
    /// text.primary is 7.86:1 (WCAG 2.1 1.4.3, #450). The system's own highlight, which ignores
    /// `.tint` and drew text.primary at 3.1:1, is off (`SidebarHighlightOff`); the row is still the
    /// list's selection, so arrow keys move it and VoiceOver says it is selected.
    fileprivate func sidebarRow(_ selected: Bool) -> some View {
        listRowBackground(SelectionFill(selected: selected).padding(.horizontal, Space.s8))
    }
}

/// The selected row's fill, drawn by an AppKit view that takes no vibrancy: a SwiftUI shape there
/// was blended with the sidebar's material, and #1767b5 read #3e7bbd (text.primary about 4.0:1).
/// Its colour is the token's, resolved for the view's appearance, so Increase Contrast gives
/// `hex_hc`.
/// The sidebar's surface, bg.panel exactly as the token file has it (L-6). Drawn by SwiftUI, a
/// colour in the sidebar is blended by its material: the look case read #16171a as #1d1e21. An
/// AppKit view that refuses vibrancy draws the token itself, as SelectionFill does.
private struct PanelFill: NSViewRepresentable {
    func makeNSView(context: Context) -> Fill { Fill() }
    func updateNSView(_ view: Fill, context: Context) { view.needsDisplay = true }

    final class Fill: NSView {
        override var allowsVibrancy: Bool { false }
        override func draw(_ dirty: NSRect) {
            NSColor(named: "BgPanel")?.setFill()
            bounds.fill()
        }
    }
}

private struct SelectionFill: NSViewRepresentable {
    let selected: Bool

    func makeNSView(context: Context) -> Fill { Fill() }
    func updateNSView(_ view: Fill, context: Context) {
        view.selected = selected
        view.needsDisplay = true
    }

    final class Fill: NSView {
        var selected = false
        override var allowsVibrancy: Bool { false }
        override func draw(_ dirty: NSRect) {
            guard selected, let color = NSColor(named: "Selection") else { return }
            color.setFill()
            NSBezierPath(roundedRect: bounds, xRadius: 5, yRadius: 5).fill()
            // The accent bar at the leading edge: the selection's mark, 9.54:1 against the panel
            // (the fill alone is 1.94:1), so the selection never rests on its fill (the decider,
            // v0.4.1: grey, with ice for focus and live state).
            if let accent = NSColor(named: "Accent") {
                accent.setFill()
                NSBezierPath(roundedRect: NSRect(x: bounds.minX + 2, y: bounds.minY + 5, width: 3,
                                                 height: Swift.max(bounds.height - 10, 0)),
                             xRadius: 1.5, yRadius: 1.5).fill()
            }
        }
    }
}

/// Turns off the sidebar table's own selection highlight, from inside one of its rows: the
/// selected row is drawn by `sidebarRow` instead. Selection, keyboard and accessibility are the
/// table's as before; only the drawing of the highlight changes.
/// The acting node at the top of the sidebar (G5): its mark, its name, and an ice dot with "node
/// attached", the dot in the accent because attached is live (L-3).
private struct NodeIdentity: View {
    let name: String
    /// False once the node stopped or was detached from outside (P12): said, not hidden.
    var attached = true

    var body: some View {
        HStack(alignment: .center, spacing: Space.s8) {
            Text("◈").font(Theme.title).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Space.s4) {
                Text(name).fontWeight(.semibold)
                HStack(spacing: Space.s4) {
                    Circle().fill(attached ? VoxTokens.Colors.accent : VoxTokens.Colors.danger)
                        .frame(width: 6, height: 6)
                    Text(attached ? "node attached" : "node detached").secondaryText()
                }
            }
        }
        .padding(.vertical, Space.s4)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("node \(name), \(attached ? "attached" : "detached")")
    }
}

/// The nodes on this Mac and their state, at the foot of the sidebar (G5): one daemon holds them,
/// each a separate identity.
private struct OnThisMachine: View {
    let nodes: [NodeSummary]

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s4) {
            Hairline()
            Text("ON THIS MACHINE").eyebrow().secondaryText()
                .accessibilityAddTraits(.isHeader)
                .accessibilityIdentifier("on-this-machine")
                .padding(.top, Space.s8)
            ForEach(nodes, id: \.name) { node in
                HStack {
                    Text(node.name)
                    Spacer()
                    Text(node.state).secondaryText()
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(node.name) \(node.state)")
                .copyMenu([("Copy Name", node.name), ("Copy Fingerprint", node.fingerprint)])
                .accessibilityIdentifier("node-\(node.name)")
            }
            Text("Separate identities. One daemon.").secondaryText()
                .padding(.top, Space.s4)
        }
        .padding(.horizontal, Space.s16)
        .padding(.bottom, Space.s12)
        .background(PanelFill())
        .foregroundStyle(VoxTokens.Colors.textPrimary)
    }
}

private struct SidebarHighlightOff: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { Finder() }
    func updateNSView(_ view: NSView, context: Context) { (view as? Finder)?.apply() }

    final class Finder: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            apply()
        }

        func apply() {
            var up = superview
            while let v = up, !(v is NSTableView) { up = v.superview }
            (up as? NSTableView)?.selectionHighlightStyle = .none
        }
    }
}

/// A room in the sidebar: its name, and its unread in words.
private struct RoomRow: View {
    let room: NodeModel.Room
    /// Whether it is the row selected: its second line then takes selection.secondary, which
    /// reads on the selection's fill (text.secondary would not: 3.66:1).
    var selected = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s4) {
            Text(room.name).fontWeight(room.need == .quiet ? .regular : .bold)
            if room.need != .quiet {
                if selected {
                    Text(room.words).eyebrow().foregroundStyle(VoxTokens.Colors.selectionSecondary)
                } else {
                    Text(room.words).eyebrow().secondaryText()
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier("room-\(room.name)")
        .accessibilityLabel("\(room.name), \(room.need.words), \(room.words)")
    }
}

/// **The timeline's keyboard** (WCAG 2.1.1, 2.4.7): an AppKit view behind the timeline that
/// takes first responder and its keys. SwiftUI's own focus would not do: a `.focusable()` scroll
/// view on macOS 13 and 14 did not take focus set from a menu while the sidebar's list held it,
/// so the keys went to the sidebar. This view takes it from Tab (with keyboard navigation on),
/// from View > Focus Timeline, and from a click on a row; it says when it has it, so the row the
/// keyboard is on is outlined, and draws no ring of its own.
///
/// It takes the keyboard only when asked (Tab, Focus Timeline, a row clicked), never on its own:
/// a view that took first responder whenever AppKit or SwiftUI offered it held it while a sheet
/// or popover was being presented, and the sheet or popover never showed (#450).
private struct TimelineKeys: NSViewRepresentable {
    /// Whether the keyboard is on the timeline, as this view says.
    @Binding var focused: Bool
    /// A key, answered with whether it did anything (a key that does nothing goes on up).
    let key: (TimelineKey) -> Bool
    /// What ⌘C and Edit › Copy copy while the keyboard is on the timeline: the selected
    /// messages, or nil when none is.
    let copied: () -> String?

    func makeNSView(context: Context) -> KeyView {
        let view = KeyView()
        view.onFocus = report
        view.onKey = key
        view.onCopy = copied
        return view
    }

    func updateNSView(_ view: KeyView, context: Context) {
        view.onKey = key
        view.onFocus = report
        view.onCopy = copied
    }

    /// Whether the view has the keyboard, written only when it changes, so a render does not
    /// follow every responder call.
    private func report(_ has: Bool) {
        DispatchQueue.main.async { if focused != has { focused = has } }
    }

    final class KeyView: NSView, NSMenuItemValidation {
        var onFocus: ((Bool) -> Void)?
        var onKey: ((TimelineKey) -> Bool)?
        var onCopy: (() -> String?)?

        /// ⌘C and Edit › Copy: the selected messages, one line each (v0.4.1).
        @objc func copy(_ sender: Any?) {
            guard let lines = onCopy?(), !lines.isEmpty else { return NSSound.beep() }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(lines, forType: .string)
        }

        func validateMenuItem(_ item: NSMenuItem) -> Bool {
            item.action == #selector(copy(_:)) ? !(onCopy?() ?? "").isEmpty : true
        }
        private var asked: NSObjectProtocol?
        /// Set while Focus Timeline or a row's click hands it the keyboard.
        private var taking = false
        /// Whether it has the keyboard, as last said.
        private var has = false

        /// Asked for, or Tab (or ⇧Tab) reaching it: never offered by AppKit or SwiftUI on their
        /// own, as when a sheet or popover is presented or closes.
        override var acceptsFirstResponder: Bool {
            if taking { return true }
            guard let event = NSApp.currentEvent else { return false }
            return event.type == .keyDown && event.keyCode == 48
        }
        override var canBecomeKeyView: Bool { acceptsFirstResponder }
        override var focusRingType: NSFocusRingType {
            get { .none }
            set {}
        }

        /// Clicks go to the rows in front of it, never to it.
        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        private func say(_ now: Bool) {
            guard now != has else { return }
            has = now
            onFocus?(now)
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let asked { NotificationCenter.default.removeObserver(asked) }
            asked = nil
            guard window != nil else { return }
            // View > Focus Timeline, or a click on a row: the keyboard comes here.
            asked = NotificationCenter.default.addObserver(
                forName: .voxFocusTimeline, object: nil, queue: .main
            ) { [weak self] _ in
                guard let self, let window = self.window else { return }
                // Not while a sheet or popover is up: it has the keyboard, and keeps it.
                guard window.attachedSheet == nil,
                      !(window.childWindows ?? []).contains(where: \.isVisible) else { return }
                if window.firstResponder !== self {
                    self.taking = true
                    window.makeFirstResponder(self)
                    self.taking = false
                }
                // Back from a Quick Look the keyboard opened, which had taken the keys.
                if !window.isKeyWindow { window.makeKey() }
            }
            setAccessibilityElement(false)
        }

        override func becomeFirstResponder() -> Bool {
            guard acceptsFirstResponder else { return false }
            say(true)
            return true
        }

        override func resignFirstResponder() -> Bool {
            say(false)
            return true
        }

        override func keyDown(with event: NSEvent) {
            // Tab and ⇧Tab move on, as from any control (with keyboard navigation on).
            if event.keyCode == 48 {
                if event.modifierFlags.contains(.shift) {
                    window?.selectPreviousKeyView(self)
                } else {
                    window?.selectNextKeyView(self)
                }
                return
            }
            let shift = event.modifierFlags.contains(.shift)
            let key: TimelineKey?
            switch event.keyCode {
            case 126: key = shift ? .extendUp : .up
            case 125: key = shift ? .extendDown : .down
            case 36, 76: key = .open // Return, Enter
            case 49: key = .look // Space
            case 53: key = .close // Escape
            default: key = nil
            }
            // Only the bare key (⇧ only with ↑/↓): ⌘↑ and the like are the menus' and the system's;
            // but ⌘↑ on a reply goes to the message it quotes (ADR-028 R-9).
            let held = event.modifierFlags.intersection([.command, .option, .control, .shift])
            if event.keyCode == 126, held == .command, onKey?(.quoted) == true { return }
            let bare = event.modifierFlags.intersection([.command, .option, .control]).isEmpty
            if let key, bare, onKey?(key) == true { return }
            super.keyDown(with: event)
        }
    }
}

/// A key the timeline acts on.
private enum TimelineKey {
    /// ⇧↑ and ⇧↓ add the message above or below to the selection (v0.4.1); `quoted`: ⌘↑ on a
    /// reply, to the message it quotes (ADR-028 R-9).
    case up, down, extendUp, extendDown, open, look, close, quoted
}

/// The room on screen: its timeline and a field to post, with its members beside it.
private struct RoomView: View {
    /// The conversation's text size, for its spacing (L-1a): this view sets it on the timeline and
    /// the composer, so it reads it from Theme rather than from its own environment.
    private var scale: Double { Theme.scale }
    @ObservedObject var model: NodeModel
    let room: String
    @State private var draft = ""
    @StateObject private var window = WindowSeen()
    /// A file dropped, pasted or chosen, waiting for its To: and note.
    @State private var attaching: Attaching?
    /// The pulled copy Quick Look shows.
    @State private var looking: URL?
    /// Whether the keyboard opened it, so the keyboard goes back to the timeline when it closes.
    @State private var lookFromKeys = false
    /// Escape and Space while Quick Look shows, wherever the keys go: the preview's own window
    /// takes them, and would keep them (WCAG 2.1.2).
    @State private var previewKeys: Any?

/// What the composer posts is addressed to, and whether it is urgent (M-15).
    @State private var to: Set<String> = []
    @State private var urgent = false
    /// The rows inside the visible part of the timeline, as last measured.
    @State private var inView: Set<String> = []
    /// The newest message when the messages last changed: if it was in view, the timeline follows
    /// the next one; scrolled up to read, it stays (as the TUI does, V210-82).
    @State private var newest: String?
    /// What is shown just changed, and has not been scrolled to its newest line yet.
    @State private var opened = false
    /// Whether the keyboard is on the timeline (WCAG 2.1.1): ↑/↓ move the selection, Return
    /// opens the selected message's first action, Space Quick Looks its pulled file.
    @State private var timelineFocused = false
    /// Each drawn row's frame in the timeline, for a drag across rows.
    @State private var rowFrames: [String: CGRect] = [:]
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The inspector's width: the one last dragged to, kept across launches (Columns).
    @State private var inspectorWidth = Columns.width(.inspector)

    var body: some View {
        // The timeline and the inspector, with a divider the person drags; the inspector's width is
        // remembered (Columns), and it can be hidden (View > Hide Inspector). Its width is the one
        // dragged to, not HSplitView's: that gave the inspector its maximum and ignored the width
        // kept from last time.
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                RoomHeader(model: model, room: room)
                Divider()
                if !model.roomServices.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: Space.s8 * scale) {
                            ForEach(model.roomServices, id: \.address) { service in
                                let selected = model.selectedService?.address == service.address
                                // A button, so a click anywhere on the card selects it, as AppKit
                                // takes clicks, and VoiceOver can press it; a tap gesture on it
                                // (with or without a shape) let clicks through unanswered.
                                Button { model.selectedService = service } label: {
                                    ServiceCard(service: service)
                                        .selectionMark(selected)
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .accessibilityIdentifier("service-\(service.address)")
                                .accessibilityLabel("service \(service.address), shared by \(service.by), \(service.kind)")
                                .accessibilityAddTraits(selected ? .isSelected : [])
                            }
                        }
                        .voxPadding(Space.s8)
                    }
                    Hairline()
                }
                Text(model.timelineTitle)
                    .secondaryText()
                    .lineLimit(1).truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .voxPadding(.horizontal, Space.s12).voxPadding(.top, Space.s8)
                    .accessibilityIdentifier("timeline-title")
                // Who this node and a member do not yet read each other with (R-5, D4).
                if let banner = model.notMutual {
                    StateMark(kind: .attention, words: banner)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .voxPadding(.horizontal, Space.s12).voxPadding(.top, Space.s4)
                        .accessibilityIdentifier("trust-banner")
                }
                if let header = model.sessionHeader {
                    Text(header)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .voxPadding(.horizontal, Space.s12).voxPadding(.top, Space.s4)
                        .accessibilityIdentifier("session-header")
                }
                Group {
                    GeometryReader { viewport in
                        ScrollViewReader { scroller in
                            // A scroll view of its own, not a List: a List's rows are cells whose frames
                            // do not measure in this coordinate space, so what is in view could not be
                            // told.
                            ScrollView {
                                let items = model.timelineItems
                                let days = TimelineTime.dividers(items)
                                LazyVStack(alignment: .leading, spacing: Space.s12 * scale) {
                                    ForEach(items) { item in
                                        // A new day starts above the first line that falls on it.
                                        if let day = days[item.id] {
                                            DayDivider(key: day, words: TimelineTime.dayWords(item.millis))
                                        }
                                        // What was unread as the room came on screen starts here.
                                        if let id = item.message?.id, id == model.unreadFrom {
                                            UnreadDivider(count: model.unreadCount)
                                        }
                                        if let message = item.message {
                                            MessageRow(model: model, message: message, me: model.me,
                                                       quote: model.quote(of: message),
                                                       jump: { model.jumpTo = $0 },
                                                       readBy: model.readBy[message.id] ?? [],
                                                       whereabouts: model.whereabouts[message.id],
                                                       pulledBy: model.pulledBy[message.id] ?? [],
                                                       pulled: model.pulled[message.id]) { looking = $0 }
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .voxPadding(Space.s4)
                                                .selectable(model.selectedMessages.contains(message.id),
                                                            focused: timelineFocused
                                                                && model.selectedMessage == message.id) {
                                                    clicked(message.id)
                                                }
                                                .reportsFrame(of: message.id)
                                                .id(message.id)
                                        } else if let notice = item.notice {
                                            // What was done to the room: a line among the
                                            // messages, not one of them (ADR-028 R-1, R-7).
                                            Text(notice).secondaryText().italic()
                                                .voxPadding(.horizontal, Space.s4)
                                                .accessibilityIdentifier(item.id)
                                                .reportsFrame(of: item.id)
                                                .id(item.id)
                                        } else if let entry = item.entry, let session = model.shownSession,
                                                  let room = model.roomOnScreen {
                                            SessionEntryRow(model: model, room: room, session: session,
                                                            entry: entry) { looking = $0 }
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                // Selected like a message: ↑/↓ reach it (P14).
                                                .selectable(model.selectedMessages.contains(item.id),
                                                            focused: timelineFocused
                                                                && model.selectedMessage == item.id) {
                                                    clicked(item.id)
                                                }
                                                .accessibilityIdentifier("entry-row-\(entry.id)")
                                                .reportsFrame(of: item.id)
                                                .id(item.id)
                                        }
                                    }
                                }
                                .voxPadding(Space.s12)
                                // A drag from one message to another selects them and those
                                // between (v0.4.1); a drag inside one message selects its words.
                                .simultaneousGesture(
                                    DragGesture(minimumDistance: 6, coordinateSpace: .named("timeline"))
                                        .onChanged { drag in dragged(from: drag.startLocation, to: drag.location) }
                                        .onEnded { drag in
                                            if dragged(from: drag.startLocation, to: drag.location) {
                                                // The keyboard takes it, so ⌘C copies the rows.
                                                NotificationCenter.default.post(name: .voxFocusTimeline,
                                                                                object: nil)
                                            }
                                        })
                            }
                            .coordinateSpace(name: "timeline")
                            // **Operable from the keyboard** (WCAG 2.1.1, 2.4.7): see
                            // `TimelineKeys`. The focused row is outlined by `selectable`.
                            .background(TimelineKeys(focused: $timelineFocused, key: { key in
                                switch key {
                                case .up: return move(.up, scroller)
                                case .down: return move(.down, scroller)
                                case .extendUp: return move(.up, scroller, extending: true)
                                case .extendDown: return move(.down, scroller, extending: true)
                                case .open: return openSelected()
                                case .look: return toggleLook()
                                case .close: return closeLook()
                                case .quoted:
                                    guard let quoted = selected.flatMap({ model.quote(of: $0) }) else {
                                        return false
                                    }
                                    model.jumpTo = quoted.id
                                    return true
                                }
                            }, copied: {
                                model.selectedMessages.isEmpty ? nil : model.copiedLines
                            }))
                            // A quote clicked, or ⌘↑ on a reply: the message it quotes, scrolled to
                            // and selected (ADR-028 R-9). One this room does not hold stays where
                            // it is.
                            .onChange(of: model.jumpTo) { id in
                                guard let id else { return }
                                model.jumpTo = nil
                                guard model.byID[id] != nil else { return }
                                select(id)
                                withAnimation(Theme.motion(reduced: reduceMotion)) {
                                    scroller.scrollTo(id, anchor: .center)
                                }
                                NotificationCenter.default.post(name: .voxFocusTimeline, object: nil)
                            }
                            .onReceive(NotificationCenter.default.publisher(for: .voxFocusTimeline)) { _ in
                                // Taken: the newest row, when none was selected: a message, or in a
                                // Session its newest entry (P14).
                                if model.selectedMessage == nil,
                                   let last = model.timelineItems.last(where: { $0.message != nil || $0.entry != nil }) {
                                    select(last.id)
                                    scroller.scrollTo(last.id)
                                }
                            }
                            .onPreferenceChange(RowFrames.self) { frames in
                                rowFrames = frames
                                // Seen: at least half of the row inside the timeline's bounds.
                                let bounds = CGRect(origin: .zero, size: viewport.size)
                                inView = Set(frames.compactMap { id, frame in
                                    let shown = frame.intersection(bounds)
                                    return !shown.isNull && shown.height * 2 >= frame.height ? id : nil
                                })
                                markSeen()
                            }
                            // A room opens at its newest message: loaded before the view
                            // appeared, its count never changed and it stayed at the top, so the
                            // newest rows were never in view, and never read.
                            .onAppear {
                                if let last = model.followItem {
                                    scroller.scrollTo(last, anchor: .bottom)
                                }
                                newest = model.followItem
                            }
                            // A request ⌘J or a notification landed on, centred once its
                            // Session's entries are drawn (P1).
                            .onChange(of: model.selectedRequest) { ref in centre(ref, scroller) }
                            .onChange(of: model.sessionEntries.count) { _ in
                                centre(model.selectedRequest, scroller)
                            }
                            // What is shown changed (General, All, a Session): it opens at its
                            // newest line, or, a Session with a request waiting, at that request,
                            // centred, so going to an approval shows it (P7).
                            .onChange(of: model.showing) { _ in
                                openAtNewest(scroller)
                                // A Session's lines are read after it is chosen: it is opened
                                // again at its newest once they land.
                                opened = model.showsSessionToRead
                                newest = model.followItem
                            }
                            // Each new line followed while the newest was in view: by the last
                            // real line's identity and the count (a Session's note, kept at the
                            // end, is not a line to follow), so a Session follows its output
                            // as General follows its messages.
                            .onChange(of: model.followSignature) { _ in
                                // A request gone to (⌘J, a notification) stays where it was
                                // centred: new output does not scroll it away (P1, P7).
                                if model.selectedRequest != nil, !opened {
                                    newest = model.followItem
                                    return
                                }
                                if opened, !model.showsSessionToRead {
                                    opened = false
                                    openAtNewest(scroller)
                                } else {
                                    let following = newest == nil || inView.contains(newest ?? "")
                                    if following, let last = model.followItem {
                                        scroller.scrollTo(last, anchor: .bottom)
                                    }
                                }
                                newest = model.followItem
                            }
                        }
                    }
                    .background(WindowReader(seen: window))
                    .onChange(of: window.seen) { _ in markSeen() }
                    .onChange(of: model.showing) { _ in updateLooking() }
                    .onDisappear { if model.lookingAt == room { model.lookingAt = nil } }
                    // A row whose body has just arrived is read now, even if its frame is
                    // unchanged (no new measure to trigger it).
                    .onChange(of: model.messages) { _ in markSeen() }
                    // A file dropped on the timeline, or pasted into it, is attached (M-24, F-1).
                    .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                        firstFile(in: providers) { attaching = Attaching(url: $0) }
                    }
                    .onPasteCommand(of: [.fileURL]) { providers in
                        _ = firstFile(in: providers) { attaching = Attaching(url: $0) }
                    }
                    .accessibilityIdentifier("timeline")
                    .accessibilityLabel("Timeline")
                    .quickLookPreview($looking)
                    .onChange(of: looking) { url in
                        if let previewKeys { NSEvent.removeMonitor(previewKeys) }
                        previewKeys = nil
                        if url != nil {
                            let shown = $looking
                            previewKeys = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
                                let bare = event.modifierFlags
                                    .intersection([.command, .option, .control, .shift]).isEmpty
                                guard bare, event.keyCode == 53 || event.keyCode == 49 else { return event }
                                // Space is a space wherever text is being typed.
                                if event.keyCode == 49,
                                   (event.window?.firstResponder as? NSTextView)?.isEditable == true {
                                    return event
                                }
                                shown.wrappedValue = nil
                                return nil
                            }
                        } else if lookFromKeys {
                            lookFromKeys = false
                            DispatchQueue.main.async {
                                NotificationCenter.default.post(name: .voxFocusTimeline, object: nil)
                            }
                        }
                    }
                    .onDisappear {
                        if let previewKeys { NSEvent.removeMonitor(previewKeys) }
                        previewKeys = nil
                    }
                }
                // A Session has no room composer (CL-1): the room's composer never speaks into
                // a Session. An open one's own composer is for a member with drive only (CL-3).
                if !model.showingSession {
                    // Who here cannot read this node, or be read by it, and why: reading needs
                    // trust both ways (ADR-028 R-5), which a newcomer is not told anywhere else.
                    TrustBanner(model: model)
                    composer
                } else if let s = model.shownSession, s.canDrive, s.open, let room = model.roomOnScreen {
                    Hairline()
                    // One composer per Session: a draft for one never shows in another (D12).
                    SessionComposer(model: model, room: room, session: s)
                        .id("\(room)/\(s.nodeFingerprint)/\(s.sessionId)")
                }
            }
            // The conversation, the timeline and the composer, at the text size View > Bigger and
            // Smaller set (the decider, v0.4.1); the inspector beside it keeps a steady size.
            .conversationScale(Theme.scale)
            // At least wide enough for the composer's field beside its To: and Urgent.
            .frame(minWidth: Theme.scaled(400), maxWidth: .infinity)
            if model.inspectorShown {
                ColumnDivider(width: $inspectorWidth, side: .inspector)
                Inspector(model: model, room: room)
                    .raisedSurface()
                    .frame(width: inspectorWidth)
            }
        }
        // On the room, not its timeline: ⌘O, ⌘↩ and a file from the Finder Services item work
        // wherever the room's focus is.
        .sheet(item: $attaching) { file in
            AttachSheet(model: model, file: file) { attaching = nil }.textSelection(.enabled)
                .panelSurface()
        }
        .onChange(of: model.attachAsked) { _ in
            // After the update, not inside it: a modal panel run from within a view update did
            // not open (⌘O, seen in the QE pass). The room's sheet only while the room is shown.
            guard !model.showingSession else { return }
            DispatchQueue.main.async {
                if let url = chooseFile() { attaching = Attaching(url: url) }
            }
        }
        // Only while the room's own composer is on screen: never a General draft sent while a
        // Session is shown (D2).
        .onChange(of: model.urgentAsked) { _ in if !model.showingSession { send(urgent: true) } }
        // The room's draft, To: and Urgent are kept while the app runs, as the room was left
        // (D12); in memory only.
        .onAppear {
            let kept = model.roomDrafts[room] ?? RoomDraft()
            draft = kept.text
            to = kept.to
            urgent = kept.urgent
        }
        .onChange(of: draft) { model.roomDrafts[room, default: RoomDraft()].text = $0 }
        .onChange(of: to) { model.roomDrafts[room, default: RoomDraft()].to = $0 }
        .onChange(of: urgent) { model.roomDrafts[room, default: RoomDraft()].urgent = $0 }
        .onChange(of: model.incoming) { url in
            if let url {
                attaching = Attaching(url: url)
                model.incoming = nil
            }
        }
        .onAppear {
            if let url = model.incoming {
                attaching = Attaching(url: url)
                model.incoming = nil
            }
        }
    }

    /// The room's composer, To: and urgent, under its own conversation and All.
    @ViewBuilder private var composer: some View {
        Hairline()
        if let reply = model.replyTo {
            HStack {
                // The message replied to, as a link to it (ADR-028 R-9).
                Button { model.jumpTo = reply.id } label: {
                    Text("Replying to \(reply.authorName.isEmpty ? String(reply.author.prefix(12)) : reply.authorName): \(reply.text.prefix(60))")
                        .lineLimit(1).secondaryText()
                }
                .buttonStyle(.plain)
                .help("Go to the message you are replying to")
                .accessibilityIdentifier("replying-to-quote")
                Spacer()
                Button("Cancel") { model.replyTo = nil }.buttonStyle(.borderless)
            }
            .voxPadding(.horizontal, Space.s12).voxPadding(.top, Space.s8)
            .accessibilityIdentifier("replying-to")
        }
        if !mentions.isEmpty {
            // Typing @ offers the keyring's members of this room by name (ADR-028 K-4).
            HStack(spacing: Space.s8 * scale) {
                ForEach(mentions) { member in
                    Button("@\(member.name)") { mention(member) }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("mention-\(member.name)")
                }
                Spacer()
            }
            .voxPadding(.horizontal, Space.s12).voxPadding(.top, Space.s8)
        }
        HStack(spacing: Space.s8 * scale) {
            Button {
                if let url = chooseFile() { attaching = Attaching(url: url) }
            } label: {
                Image(systemName: "paperclip")
            }
            .buttonStyle(.borderless)
            .help("Attach a file or folder")
            .accessibilityLabel("Attach a file or folder")
            .accessibilityIdentifier("attach")
            // Who posts (E-4): the node this window acts as, before the field.
            Text("\(model.node) ▸").font(Theme.mono).secondaryText()
                .accessibilityLabel("posting as \(model.node)")
                .accessibilityIdentifier("compose-as")
            // Up to 12 lines, so a long message is read before it goes; Return sends, ⌥↩ adds a
            // line (P19).
            TextField("Message \(model.roomName(room))…", text: $draft, axis: .vertical)
                .lineLimit(1...12)
                .accessibilityLabel("Message \(model.roomName(room)), as \(model.node)")
                .textFieldStyle(.plain)
                .frame(minWidth: Theme.scaled(160), maxWidth: .infinity)
                .layoutPriority(1)
                .onSubmit { send(urgent: urgent) }
                .accessibilityIdentifier("compose")
            ComposerAddress(model: model, to: $to, urgent: $urgent)
        }
        .voxPadding(Space.s12)
    }

    /// Post the draft, To: and replying as set; urgent when asked (⌘↩ or the switch).
    private func send(urgent now: Bool) {
        // An @alias typed in full addresses that member, as ticking it in To: does (K-4).
        let named = draft.split(whereSeparator: \.isWhitespace).compactMap { word -> String? in
            guard word.hasPrefix("@") else { return nil }
            let alias = word.dropFirst().trimmingCharacters(in: .punctuationCharacters.subtracting(["#"]))
            return mentionable.first { $0.name == alias }?.id
        }
        let (text, recipients, re) = (draft, Array(to.union(named)), model.replyTo?.id ?? "")
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        // A detached node posts nothing: the draft stays until it is attached again.
        guard model.ended == nil else { return }
        draft = ""
        urgent = false
        model.replyTo = nil
        Task { await model.post(text, to: recipients, urgent: now, re: re) }
    }

    /// The members an @alias can name (ADR-028 K-4): those in the keyring, by the names the node
    /// gives them (an alias the same as another but for case carries its fingerprint's start).
    private var mentionable: [NodeModel.MemberRow] { model.members.filter { $0.trust != .none } }

    /// The @word being typed at the end of the draft: what follows "@", or nil.
    private var mentioning: String? {
        guard let at = draft.lastIndex(of: "@"),
              at == draft.startIndex || draft[draft.index(before: at)].isWhitespace else { return nil }
        let word = draft[draft.index(after: at)...]
        return word.contains(where: \.isWhitespace) ? nil : String(word)
    }

    /// The members the @word being typed could name, by the start of their names.
    private var mentions: [NodeModel.MemberRow] {
        guard let typed = mentioning?.lowercased() else { return [] }
        return mentionable.filter { $0.name.lowercased().hasPrefix(typed) }
    }

    /// `member` picked for the @word being typed: written in full, and addressed (K-4).
    private func mention(_ member: NodeModel.MemberRow) {
        guard let at = draft.lastIndex(of: "@") else { return }
        draft = String(draft[..<at]) + "@\(member.name) "
        to.insert(member.id)
    }

    /// ↑/↓ on the timeline: the selection moves to the message before or after it, scrolled into
    /// view; with none selected, ↑ takes the newest and ↓ the oldest.
    private func move(_ direction: MoveCommandDirection, _ scroller: ScrollViewProxy,
                      extending: Bool = false) -> Bool {
        // Every drawn row with an identity: a message, or a Session's entry or request (P14).
        let ids = model.timelineItems.filter { $0.message != nil || $0.entry != nil }.map(\.id)
        guard !ids.isEmpty else { return false }
        let at = model.selectedMessage.flatMap { ids.firstIndex(of: $0) }
        let next: Int
        switch direction {
        case .up: next = at.map { max($0 - 1, 0) } ?? ids.count - 1
        case .down: next = at.map { min($0 + 1, ids.count - 1) } ?? 0
        default: return false
        }
        if extending { extend(to: ids[next]) } else { select(ids[next]) }
        withAnimation(Theme.motion(reduced: reduceMotion)) {
            scroller.scrollTo(ids[next])
        }
        return true
    }

    /// The messages in the timeline's order, oldest first.
    private var messageIDs: [String] { model.timelineItems.compactMap { $0.message?.id } }

    /// One message selected, alone: where a range starts.
    private func select(_ id: String) {
        model.selectedMessage = id
        model.selectedMessages = [id]
        model.selectionAnchor = id
    }

    /// The messages from the range's start to `id`, selected; the keyboard on `id`.
    private func extend(to id: String) {
        let ids = messageIDs
        guard let from = ids.firstIndex(of: model.selectionAnchor ?? id),
              let to = ids.firstIndex(of: id) else { return select(id) }
        model.selectedMessages = Set(ids[min(from, to)...max(from, to)])
        model.selectedMessage = id
    }

    /// A row clicked: alone; with ⌘, added or taken out; with ⇧, the range to it. The keyboard
    /// follows, as in a list.
    private func clicked(_ id: String) {
        let flags = NSEvent.modifierFlags
        if flags.contains(.command) {
            if model.selectedMessages.contains(id) {
                model.selectedMessages.remove(id)
            } else {
                model.selectedMessages.insert(id)
            }
            model.selectedMessage = id
            model.selectionAnchor = id
        } else if flags.contains(.shift), model.selectionAnchor != nil {
            extend(to: id)
        } else {
            select(id)
        }
        NotificationCenter.default.post(name: .voxFocusTimeline, object: nil)
    }

    /// A drag in the timeline from `start` to `now`: when it reaches from one message to another,
    /// those two and every message between are selected. Whether it did.
    @discardableResult
    private func dragged(from start: CGPoint, to now: CGPoint) -> Bool {
        let rows = rowFrames.filter { model.byID[$0.key] != nil }
        // The row under `y`, else the nearest (the gaps between rows, or past the last).
        func row(at y: CGFloat) -> String? {
            func away(_ f: CGRect) -> CGFloat { y < f.minY ? f.minY - y : y > f.maxY ? y - f.maxY : 0 }
            return rows.min { away($0.value) < away($1.value) }?.key
        }
        guard let first = row(at: start.y), let last = row(at: now.y), first != last else { return false }
        model.selectionAnchor = first
        extend(to: last)
        return true
    }

    /// Scroll the request `reference`'s entry to the middle of the timeline, once it is drawn.
    private func centre(_ reference: String?, _ scroller: ScrollViewProxy) {
        guard let reference,
              let entry = model.sessionEntries.first(where: { $0.request?.reference == reference }) else { return }
        withAnimation(Theme.motion(reduced: reduceMotion)) {
            scroller.scrollTo("entry-\(entry.id)", anchor: .center)
        }
    }

    /// The selected message, as the timeline shows it.
    private var selected: RoomMessage? {
        model.messages.first { $0.id == model.selectedMessage }
    }

    /// Return: the selected message's first action — its pulled file in Quick Look, else its link
    /// card's link (http and https only, as the card itself opens). Whether there was one.
    private func openSelected() -> Bool {
        guard let message = selected else { return false }
        if lookSelected() { return true }
        if let card = message.card, let url = URL(string: card.url),
           ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
            NSWorkspace.shared.open(url)
            return true
        }
        return false
    }

    /// Space: the selected message's pulled file in Quick Look. Whether there was one.
    private func lookSelected() -> Bool {
        guard let id = model.selectedMessage, let path = model.pulled[id] else { return false }
        looking = URL(fileURLWithPath: path)
        lookFromKeys = true
        return true
    }

    /// Space: Quick Look on the selected row's pulled file, or, while it shows, off again (as in
    /// the Finder). Whether it did either.
    private func toggleLook() -> Bool {
        closeLook() || lookSelected()
    }

    /// Escape: Quick Look closed, if it shows, while the keys are still the timeline's (the preview
    /// taking them is `previewKeys`'s). Whether it showed.
    private func closeLook() -> Bool {
        guard looking != nil else { return false }
        looking = nil
        return true
    }

    /// What is shown, at its newest line; or a Session's request waiting for an answer, centred.
    private func openAtNewest(_ scroller: ScrollViewProxy) {
        if model.selectedRequest != nil {
            centre(model.selectedRequest, scroller)
        } else if let waiting = model.waitingEntry {
            scroller.scrollTo(waiting, anchor: .center)
        } else if let last = model.followItem {
            scroller.scrollTo(last, anchor: .bottom)
        }
    }

    /// Tell the model whether this room's own timeline is being looked at as it grows: in a window
    /// in front of the person, General or All shown (not a Session), and its newest message in
    /// view, so the next one is drawn in view as it lands (D18).
    private func updateLooking() {
        var ownTimeline = true
        if case .session = model.showing { ownTimeline = false }
        let following = newest == nil || inView.contains(newest ?? "")
        let now = window.seen && ownTimeline && following ? room : nil
        if model.lookingAt != now { model.lookingAt = now }
    }

    /// The rows in view are read, only while the window is in front of the person (R-6).
    private func markSeen() {
        readLog.debug("seen check in \(room, privacy: .public): window seen \(window.seen), \(inView.count) rows in view")
        updateLooking()
        guard window.seen else { return }
        for id in inView {
            if let message = model.byID[id] { model.drawn(message, in: room) }
        }
    }
}

/// One message in the timeline.
private struct MessageRow: View {
    @Environment(\.voxTextScale) private var scale
    /// What opens its author's card (D4); not observed, so a row redraws only with its own data.
    let model: NodeModel
    let message: RoomMessage
    let me: String
    /// What it replies to, quoted (ADR-028 R-9): the message's id, and "<who>: <first line>", or
    /// nil words while this room does not hold it.
    let quote: (id: String, words: String?)?
    /// Go to a quoted message.
    let jump: (String) -> Void
    /// Who has read it, when it is this node's own (R-6).
    let readBy: [String]
    /// Where it is while nobody has read it, when it is this node's own (R-6, D9).
    let whereabouts: String?
    /// Who has pulled it, verified, when it is this node's own share (#498).
    let pulledBy: [String]
    /// Where this node's verified copy of the file it shares is, once pulled.
    let pulled: String?
    /// Open a pulled copy with Quick Look.
    let look: (URL) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s4 * scale) {
            HStack(spacing: Space.s8 * scale) {
                if message.author == me {
                    Text(author).fontWeight(.bold)
                } else {
                    // Its card: who it is, who trusts whom, and Trust…, Compare…, Remove… (K-5).
                    Text(author).fontWeight(.bold)
                        .nodeCard(model, message.author, name: author)
                        .accessibilityIdentifier("author-\(message.id)")
                }
                // Its time of day; the whole date and time on hover and to VoiceOver.
                Text(TimelineTime.short(message.createdMillis))
                    .font(Theme.mono).secondaryText()
                    .help(TimelineTime.full(message.createdMillis))
                    .accessibilityLabel(TimelineTime.full(message.createdMillis))
                    .accessibilityValue(TimelineTime.short(message.createdMillis))
                    .accessibilityIdentifier("time-\(message.id)")
                if message.urgent { StateMark(kind: .attention, words: "urgent") }
                if message.to.contains(me) { Text("to you").eyebrow() }
                if message.late {
                    // ADR-023: it took its place above messages already shown.
                    Text("arrived late").eyebrow().secondaryText()
                        .accessibilityIdentifier("late-\(message.id)")
                }
            }
            if let quote {
                // The message it replies to, one level, as a link to it (ADR-028 R-9).
                Button { jump(quote.id) } label: {
                    Text("re \(quote.words ?? "a message this room does not hold yet")")
                        .italic().secondaryText().lineLimit(1).truncationMode(.tail)
                }
                .buttonStyle(.plain)
                .disabled(quote.words == nil)
                .help(quote.words == nil ? "This room does not hold it yet" : "Go to the message it replies to (⌘↑)")
                .accessibilityIdentifier("quote-\(message.id)")
            }
            if let file = message.file {
                FileCard(file: file, image: message.image, pulled: pulled, look: look)
            }
            if message.file == nil || !(message.file?.note.isEmpty ?? true) {
                Text(message.owed ? "not received yet" : shownText)
                    .textSelection(.enabled)
            }
            if let card = message.card {
                LinkCardView(card: card)
            }
            if !pulledBy.isEmpty {
                // No label of its own: a selectable Text with one sends SwiftUI's accessibility
                // into endless recursion. Its words are what it says.
                Text("pulled by \(pulledBy.joined(separator: ", "))")
                    .caption().secondaryText()
                    .accessibilityIdentifier("pulled-by-\(message.id)")
            }
            if !readBy.isEmpty {
                Text("read by \(readBy.joined(separator: ", "))")
                    .caption().secondaryText()
                    .accessibilityIdentifier("read-by-\(message.id)")
            } else if let whereabouts, message.author == me {
                // No label of its own, as above: its words are what it says.
                Text(whereabouts)
                    .caption().secondaryText()
                    .accessibilityIdentifier("whereabouts-\(message.id)")
            }
        }
        // VoiceOver reads the row first as one sentence, in the order it is drawn; its parts
        // (the file's buttons, the link) stay reachable inside it (WCAG 1.3.1, 4.1.2).
        .accessibilityElement(children: .contain)
        .accessibilityLabel(spoken)
    }

    /// The row as one sentence: who, to whom, how, what, and what became of it.
    private var spoken: String {
        var parts = [author]
        if message.to.contains(me) { parts.append("to you") }
        if message.urgent { parts.append("urgent") }
        if message.late { parts.append("arrived late") }
        parts.append("at \(TimelineTime.full(message.createdMillis))")
        var said = parts.joined(separator: ", ") + ": "
        if let file = message.file {
            said += "\(file.folder ? "folder" : "file") \(file.name)"
            if !file.note.isEmpty { said += ", \(file.note)" }
        } else {
            said += message.owed ? "not received yet" : message.text
        }
        if let card = message.card, !card.title.isEmpty { said += ", link: \(card.title)" }
        if !pulledBy.isEmpty { said += ", pulled by \(pulledBy.joined(separator: ", "))" }
        if !readBy.isEmpty {
            said += ", read by \(readBy.joined(separator: ", "))"
        } else if let whereabouts, message.author == me {
            said += ", \(whereabouts)"
        }
        return said
    }

    /// A share's text is its note.
    private var shownText: String { message.file?.note ?? message.text }

    private var author: String { NodeModel.author(message, me: me) }
}

/// The node stopped under the window (detached elsewhere, or the daemon stopped): said at the top,
/// with the way back. The window and everything typed in it stay; attaching the same node again
/// picks up where it was. Start Over goes back to reaching the daemon, as at launch.
private struct NodeStopped: View {
    @ObservedObject var model: NodeModel
    @State private var field = SecureFieldHolder()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StateMark(kind: .danger, words: "Node \(model.node) is detached: \(model.ended ?? "")")
                .textSelection(.enabled)
                .accessibilityIdentifier("node-stopped")
            Text("Nothing you typed is lost. Type node \(model.node)'s identity passphrase to attach "
                + "it again; leave it empty if it needs none.")
                .secondaryText()
            HStack {
                SecureInput(holder: field) { again() }
                    .frame(width: Theme.scaled(260))
                    .accessibilityIdentifier("node-stopped-passphrase")
                    .accessibilityLabel("Identity passphrase for node \(model.node)")
                Button("Attach Again") { again() }
                    .accessibilityIdentifier("node-stopped-attach")
                Button("Start Over") { Task { await AppModel.shared.start() } }
                    .accessibilityIdentifier("node-stopped-start-over")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
    }

    private func again() {
        let secret = field.take()
        Task { await model.attachAgain(secret) }
    }
}

/// A line above the composer while any member and this node cannot read each other, saying which
/// way trust is missing and what to do. Members are named as the room names them: this node's
/// alias, else the start of the fingerprint.
private struct TrustBanner: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        let cut = model.members.filter { $0.trust != .mutual }
        if !cut.isEmpty {
            HStack(spacing: 8) {
                StateMark(kind: .attention, words: words(cut))
                    .accessibilityIdentifier("trust-banner")
                Spacer()
                if cut.count == 1, let member = cut.first, member.trust == .none,
                   model.offers.contains(where: { $0.fingerprint == member.id }) {
                    Button("Trust \(member.name)…") { Task { await model.show(.offer(member.id)) } }
                        .accessibilityIdentifier("trust-banner-offer")
                } else if cut.contains(where: { $0.trust == .none }) {
                    Button("Show Keyring") { Task { await model.show(.keyring) } }
                        .accessibilityIdentifier("trust-banner-keyring")
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
        }
    }

    private func words(_ cut: [NodeModel.MemberRow]) -> String {
        guard cut.count == 1, let m = cut.first else {
            return "\(cut.count) members here and you can't read each other yet: reading needs both "
                + "sides to trust each other."
        }
        switch (m.trust, m.trustsYou) {
        case (.oneWay, _):
            return "You trust \(m.name). Waiting for \(m.name) to trust you back before you can read each other."
        case (.none, true):
            return "\(m.name) trusts you. Trust \(m.name) too, and you can read each other."
        default:
            return "You and \(m.name) can't read each other yet: each of you has to trust the other."
        }
    }
}

/// The Dock icon's badge.
enum DockBadge {
    static func show(_ count: Int) {
        NSApp.dockTile.badgeLabel = count > 0 ? "\(count)" : nil
    }
}

/// The room's own header, pinned above its timeline: its name, how many members it has, what the
/// timeline shows (General, All, or a Session), and its retention, which is always said (R-7).
/// The window takes the room's name as its title, so the Window menu and ⌘` say which room it is.
private struct RoomHeader: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("ROOM").eyebrow().secondaryText()
            Text(model.roomName(room)).fontWeight(.semibold)
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
                .accessibilityIdentifier("room-header-name")
                .accessibilityAddTraits(.isHeader)
            Text(model.roomHeaderMeta)
                .secondaryText()
                .lineLimit(1).truncationMode(.middle)
                .accessibilityIdentifier("room-header-meta")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12).padding(.vertical, 8)
        .navigationTitle(model.roomName(room))
        .navigationSubtitle(model.roomHeaderMeta)
    }
}

/// Where a new day starts in the timeline: its words between two hairlines.
private struct DayDivider: View {
    /// The day, "2026-10-04", as the divider's identifier says it.
    let key: String
    let words: String

    var body: some View {
        HStack(spacing: 8) {
            VStack { Divider() }
            Text(words).caption().secondaryText()
            VStack { Divider() }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .ignore)
        .accessibilityAddTraits(.isHeader)
        .accessibilityLabel(words)
        .accessibilityIdentifier("day-\(key)")
    }
}

/// Where what was unread when the room came on screen starts.
private struct UnreadDivider: View {
    let count: Int

    var body: some View {
        let words = count == 1 ? "1 unread" : "\(count) unread"
        HStack(spacing: 8) {
            VStack { Divider() }
            Text(words).caption()
            VStack { Divider() }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(words)
        .accessibilityIdentifier("unread-divider")
    }
}

/// A file or folder offered in the room (ADR-028 F-1): its name, size and SHA-256, as the share's
/// signed announcement states them.
private struct FileCard: View {
    @Environment(\.voxTextScale) private var scale
    let file: FileOffer
    /// The image's preview its share announced (ADR-028 F-9): shown while the sharer is offline.
    let image: ImagePreview?
    /// This node's verified copy, once pulled (F-3, F-4).
    let pulled: String?
    let look: (URL) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: Space.s12 * scale) {
            if let image, let thumb = NSImage(data: image.thumb) {
                Image(nsImage: thumb)
                    .resizable()
                    .aspectRatio(CGFloat(image.width) / CGFloat(max(image.height, 1)), contentMode: .fit)
                    .frame(maxWidth: 160, maxHeight: 120)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.control * scale))
                    .accessibilityLabel("image \(image.width) by \(image.height)")
                    .accessibilityIdentifier("thumb-\(file.name)")
            } else {
                Image(systemName: file.folder ? "folder" : "doc")
                    .voxFont(VoxTokens.Fonts.appGlyph)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: Space.s4 * scale) {
                Text(file.name).fontWeight(.bold)
                Text("\(ByteCountFormatter.string(fromByteCount: Int64(file.size), countStyle: .file))"
                    + "  ·  sha256 \(file.sha256.prefix(16))…")
                    .voxFont(VoxTokens.Fonts.appMono).secondaryText()
                if let pulled {
                    // Opened only once verified: a copy is linked into place only after its size
                    // and SHA-256 matched the signed announcement (F-11).
                    HStack {
                        Button("Quick Look") { look(URL(fileURLWithPath: pulled)) }
                            .accessibilityIdentifier("quick-look-\(file.name)")
                        Button("Show in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: pulled)])
                        }
                    }
                }
            }
        }
        .voxPadding(Space.s8)
        .cardOutline()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("file-\(file.name)")
        .accessibilityLabel("\(file.folder ? "folder" : "file") \(file.name), \(file.size) bytes")
    }
}

/// A link's card (ADR-028 F-10): what the sender's node found at the message's first link, carried
/// in the message, so drawing it fetches nothing. Opening the link is the person's own choice.
private struct LinkCardView: View {
    @Environment(\.voxTextScale) private var scale
    let card: LinkCard

    var body: some View {
        HStack(alignment: .top, spacing: Space.s12 * scale) {
            if let data = card.image, let picture = NSImage(data: data) {
                Image(nsImage: picture).resizable().aspectRatio(contentMode: .fit)
                    .frame(maxWidth: 72, maxHeight: 72)
                    .clipShape(RoundedRectangle(cornerRadius: Radius.control * scale))
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: Space.s4 * scale) {
                if !card.title.isEmpty { Text(card.title).fontWeight(.bold) }
                if !card.description.isEmpty { Text(card.description).secondaryText().lineLimit(3) }
                // Clickable only for http and https (a whitelist): the link is the peer's, and any
                // other scheme (file:, an app's own) is drawn as text, never opened.
                if let url = URL(string: card.url),
                   ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
                    // A link, drawn as one: not in the app's button style.
                    Link(card.url, destination: url).caption().lineLimit(1)
                        .truncationMode(.middle)
                        .buttonStyle(.plain)
                        .foregroundStyle(VoxTokens.Colors.accent)
                } else {
                    Text(card.url).caption().lineLimit(1).truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
        }
        .voxPadding(Space.s8)
        .cardOutline()
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("card-\(card.url)")
    }
}

/// A service a member shares in the room: its address, who shares it, and what it is (ADR-028 S-2).
private struct ServiceCard: View {
    @Environment(\.voxTextScale) private var scale
    let service: SharedService

    var body: some View {
        HStack(spacing: Space.s8 * scale) {
            Image(systemName: "point.3.connected.trianglepath.dotted").accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Space.s4 * scale) {
                Text(service.address).voxFont(VoxTokens.Fonts.appMono).textSelection(.enabled)
                Text("by \(service.by)  ·  \(service.kind)\(service.udp && service.kind != "udp" ? "/udp" : "")")
                    .caption().secondaryText()
            }
        }
        .voxPadding(Space.s8)
        .cardOutline()
    }
}

/// The room's Sessions (ADR-029 CL-2), then its members and their trust (L-4).
private struct Inspector: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        // It scrolls (P13): a room with many Sessions or members cut off the bottom, the family
        // LAN section with it. Each section's heading stays in view while its rows scroll.
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Space.s8, pinnedViews: [.sectionHeaders]) {
                Section {
                    SessionsList(model: model, heading: false)
                } header: {
                    heading("SESSIONS")
                }
                Section {
                    ForEach(model.members) { member in
                        TrustMark(name: member.name, trust: member.trust)
                            .nodeCard(model, member.id, name: member.name)
                            .accessibilityIdentifier("member-\(member.name)")
                        // What this node's keyring grants it (K-14), once it is in the keyring.
                        if member.trust.inKeyring {
                            Text(Capability.words(member.drive)).eyebrow().secondaryText()
                                .padding(.leading, Space.s20)
                                .accessibilityIdentifier("member-capability-\(member.name)")
                        }
                        // The platform its node says it runs on (ADR-020 §4.9b): its claim, said
                        // as one.
                        if let platform = model.platforms[member.id] {
                            // Selectable, so its label is on a container that hides the Text: a
                            // selectable Text with its own label sent SwiftUI's accessibility into
                            // endless recursion, and the app crashed when read.
                            HStack {
                                Text("says it runs on \(Platform.words(platform))")
                                    .font(Theme.mono).secondaryText()
                            }
                            .padding(.leading, Space.s20)
                            .accessibilityElement(children: .ignore)
                            .accessibilityLabel("\(member.name) says it runs on \(Platform.words(platform))")
                            .accessibilityIdentifier("member-platform-\(member.name)")
                        }
                    }
                    Hairline().padding(.vertical, Space.s8)
                    FamilyLan(model: model, room: room)
                } header: {
                    heading("MEMBERS")
                }
            }
            .padding(Space.s12)
        }
        .frame(maxHeight: .infinity, alignment: .topLeading)
        // A container, so each row keeps its own identifier (member-<name>) under this one.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("inspector")
    }

    /// A section's heading, pinned while its rows scroll under it: drawn on the inspector's own
    /// surface, so the rows do not show through.
    private func heading(_ words: String) -> some View {
        Text(words).eyebrow().secondaryText()
            .accessibilityAddTraits(.isHeader)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, Space.s4)
            .background(VoxTokens.Colors.bgRaised)
    }
}

/// A node's claimed platform in words, as the CLI and the TUI say it: "macOS 26.2 (aarch64)",
/// leaving out what it did not say.
enum Platform {
    static func words(_ p: NodePlatform) -> String {
        let os = [p.os, p.osVersion].filter { !$0.isEmpty }.joined(separator: " ")
        return p.arch.isEmpty ? os : "\(os) (\(p.arch))"
    }
}

/// The room's family LAN (ADR-013): a toggle. The LAN helper it needs is asked for only when the
/// LAN is turned on, in a sheet that says where to allow it and goes on by itself once it is
/// (ADR-014 M-12).
private struct FamilyLan: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        Text("FAMILY LAN").eyebrow().secondaryText()
            .accessibilityAddTraits(.isHeader)
        Toggle("On this room's LAN", isOn: Binding(
            get: { model.lanOn.contains(room) },
            set: { on in
                Task { if on { await model.turnLanOn(room) } else { await model.setLan(room, on: false) } }
            }))
            .accessibilityIdentifier("family-lan")
            .sheet(isPresented: Binding(get: { model.lanAsking == room },
                                        set: { if !$0 { model.cancelLanAsk() } })) {
                LanHelperSheet(model: model, room: room)
                    .panelSurface()
            }
        if let said = model.lanSaid[room] {
            Text(said).font(Theme.mono).secondaryText().textSelection(.enabled)
                .accessibilityIdentifier("family-lan-said")
        }
        if let failed = model.lanFailed[room] {
            StateMark(kind: .danger, words: failed).textSelection(.enabled)
                .accessibilityIdentifier("family-lan-failed")
        }
        if model.lanHelperReady {
            Button("Remove the LAN Helper") { Task { await model.removeLanHelper() } }
                .accessibilityIdentifier("family-lan-remove")
        }
    }
}

/// Asking for the LAN helper, once someone turns a family LAN on: what it is, the exact place to
/// allow it, and a wait that ends by itself when macOS says it is allowed, noticed on every
/// refresh and as soon as Vox is back in front.
private struct LanHelperSheet: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            // A room's name is its content: never uppercased.
            Text("Family LAN for \u{201C}\(name)\u{201D}").caption().secondaryText()
            Text("Allow Vox's LAN helper").title()
                .accessibilityAddTraits(.isHeader)
            Text("The family LAN needs one helper that runs as root and creates network interfaces "
                + "for Vox, and nothing else.")
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: Space.s8) {
                Text("1. Open System Settings › General › Login Items & Extensions.")
                Text("2. Under \u{201C}Allow in the Background\u{201D}, turn on Vox.")
                Text("3. Come back here; Vox notices and turns the LAN on.")
            }
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("lan-helper-steps")
            HStack(spacing: Space.s8) {
                ProgressView().controlSize(.small)
                Text("Waiting for you to allow it…").secondaryText()
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("lan-helper-waiting")
            HStack {
                Spacer()
                Button("Cancel") { model.cancelLanAsk() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("lan-helper-cancel")
                Button("Open Login Items") { Daemon.openLoginItems() }
                    .accessibilityIdentifier("lan-helper-open")
            }
        }
        .padding(Space.s20)
        .frame(width: 460)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.recheckLanHelper() }
        }
        // A container, so its steps and its wait keep their own identifiers: given to the whole
        // sheet without it, the identifier replaced every one of theirs.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("lan-helper-sheet")
    }

    private var name: String { model.rooms.first { $0.id == room }?.name ?? String(room.prefix(12)) }
}

/// The node, its peers and the keyring window (W-1, K-9); and the last thing that failed, in the
/// daemon's words (M-7).
private struct StatusBar: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        HStack(spacing: Space.s16) {
            Text("node \(model.node)")
            Text(model.peers == 1 ? "1 peer" : "\(model.peers) peers")
            Text(model.keyring)
            if model.notifying == false {
                // M-23: said where the person works, so a missing notification is explained.
                Text("notifications off (System Settings, Notifications, Vox)")
                    .accessibilityIdentifier("notifications-off")
            }
            Spacer()
            if let ended = model.ended {
                StateMark(kind: .danger, words: ended)
            } else if let outcome = model.outcome {
                // What the last operation came to, kept until the next starts or it is dismissed
                // (P6): done, refused and not known each said as itself.
                OutcomeMark(outcome: outcome, id: "status-outcome-\(outcome.kindName)")
                Button {
                    model.clearOutcome()
                } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Dismiss")
                .accessibilityIdentifier("status-dismiss")
            }
        }
        .font(Theme.mono)
        .padding(.horizontal, Space.s12)
        .padding(.vertical, Space.s8)
        // A container, so "notifications-off" keeps its identifier; its label says the whole bar.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("status")
        .accessibilityLabel(words)
    }

    /// The bar, in words.
    private var words: String {
        var parts = ["node \(model.node)", model.peers == 1 ? "1 peer" : "\(model.peers) peers",
                     model.keyring]
        if model.notifying == false {
            parts.append("notifications off (System Settings, Notifications, Vox)")
        }
        if let ended = model.ended {
            parts.append(ended)
        } else if let outcome = model.outcome {
            parts.append(outcome.said)
        }
        return parts.filter { !$0.isEmpty }.joined(separator: ", ")
    }
}

extension RoomGroup {
    /// The group, as the sidebar heads it (the TUI's words).
    var words: String { roomGroupWords(group: self) }
}

/// What one operation came to, as a person reads it (P6): done plainly, refused as a danger, and
/// not known whether it was done as an attention, each with its own words; nothing when there is
/// none.
struct OutcomeMark: View {
    let outcome: Outcome?
    /// Where it is shown, as its identifier says it; else its kind (`outcome-refused`).
    var id: String? = nil

    var body: some View {
        if let outcome {
            StateMark(kind: outcome.kind == .done ? .plain
                          : outcome.kind == .refused ? .danger : .attention,
                      words: outcome.said)
                .textSelection(.enabled)
                .accessibilityIdentifier(id ?? "outcome-\(outcome.kindName)")
        }
    }
}

extension Outcome {
    /// Its words, with what it was where that is not plain from them.
    var said: String {
        switch kind {
        case .done, .refused: return words
        case .unknown: return "Not known whether it was done. \(words)"
        }
    }

    /// Its kind, as an identifier says it.
    var kindName: String {
        switch kind {
        case .done: return "done"
        case .refused: return "refused"
        case .unknown: return "unknown"
        }
    }
}
