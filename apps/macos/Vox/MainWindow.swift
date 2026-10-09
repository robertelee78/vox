// The main window (ADR-028 W-1, W-2; ADR-014 M-13): a sidebar with the node, its rooms grouped by
// what they need from the person and the nodes on this Mac; the room's timeline; an inspector with
// its members and their trust; and a status bar with the node, its peers and the keyring window.
// The keyring is a view of this window, not a window of its own.

import AppKit
import SwiftUI

struct MainWindow: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        VStack(spacing: 0) {
            NavigationSplitView {
                Sidebar(model: model)
                    .navigationSplitViewColumnWidth(min: Theme.scaled(220), ideal: Theme.scaled(260))
            } detail: {
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
                case nil:
                    Text("Pick a room.")
                        .secondaryText()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            Divider()
            StatusBar(model: model)
        }
        .contentSurface()
        .sheet(item: $model.sheet) { NodeSheets(model: model, sheet: $0) }
        .toolbar {
            // W-2: a key moves to the next room that needs the person; Control-N, as in the TUI.
            Button("Next Room That Needs You") { Task { await model.nextNeedingYou() } }
                .keyboardShortcut("n", modifiers: .control)
                .accessibilityIdentifier("next-needs-you")
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
            Section {
                StateMark(kind: .live, words: "node \(model.node), attached")
                    .font(Theme.text)
                    .accessibilityIdentifier("attached")
                    .background(SidebarHighlightOff())
            }
            ForEach([RoomGroup.needsYou, .active, .quiet], id: \.self) { need in
                let rooms = model.group(need)
                // A trust offer waiting needs the person too (ADR-028 K-15, W-2).
                let offers = need == .needsYou ? model.offers : []
                let count = rooms.count + offers.count
                Section {
                    ForEach(rooms) { room in
                        RoomRow(room: room).tag(NodeModel.Selection.room(room.id))
                            .sidebarRow(model.selection == .room(room.id))
                    }
                    ForEach(offers, id: \.fingerprint) { offer in
                        OfferRow(offer: offer).tag(NodeModel.Selection.offer(offer.fingerprint))
                            .sidebarRow(model.selection == .offer(offer.fingerprint))
                    }
                } header: {
                    Text("\(need.words) (\(count))")
                        .eyebrow()
                        .accessibilityIdentifier("group-\(need.words)")
                        .accessibilityLabel("\(need.words) (\(count))")
                }
            }
            Section {
                Text("Keyring").font(Theme.text).tag(NodeModel.Selection.keyring)
                    .sidebarRow(model.selection == .keyring)
                    .accessibilityIdentifier("keyring")
                Text("Decision record").font(Theme.text).tag(NodeModel.Selection.decisions)
                    .sidebarRow(model.selection == .decisions)
                    .accessibilityIdentifier("decisions")
                Text("Services").font(Theme.text).tag(NodeModel.Selection.services)
                    .sidebarRow(model.selection == .services)
                    .accessibilityIdentifier("services")
            }
            Section {
                ForEach(model.nodes, id: \.name) { node in
                    StateMark(kind: node.state == "attached" ? .live : .plain,
                              words: "\(node.name) \(node.state)")
                        .font(Theme.text)
                        .accessibilityIdentifier("node-\(node.name)")
                }
            } header: {
                Text("nodes on this Mac").eyebrow().accessibilityAddTraits(.isHeader)
            }
        }
        .listStyle(.sidebar)
        // The sidebar's rows in the app's face and size: a sidebar list sets its own otherwise.
        .font(Theme.text)
        .environment(\.defaultMinListRowHeight, Theme.scaled(24))
    }
}

extension View {
    /// A sidebar row's fill while it is the one selected: the selection token, on which
    /// text.primary is 4.89:1 (WCAG 2.1 1.4.3, #450). The system's own highlight, which ignores
    /// `.tint` and drew text.primary at 3.1:1, is off (`SidebarHighlightOff`); the row is still the
    /// list's selection, so arrow keys move it and VoiceOver says it is selected.
    fileprivate func sidebarRow(_ selected: Bool) -> some View {
        listRowBackground(SelectionFill(selected: selected).padding(.horizontal, 10))
    }
}

/// The selected row's fill, drawn by an AppKit view that takes no vibrancy: a SwiftUI shape there
/// was blended with the sidebar's material, and #1767b5 read #3e7bbd (text.primary about 4.0:1).
/// Its colour is the token's, resolved for the view's appearance, so Increase Contrast gives
/// `hex_hc`.
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
        }
    }
}

/// Turns off the sidebar table's own selection highlight, from inside one of its rows: the
/// selected row is drawn by `sidebarRow` instead. Selection, keyboard and accessibility are the
/// table's as before; only the drawing of the highlight changes.
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

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(room.name).font(Theme.text).fontWeight(room.need == .quiet ? .regular : .bold)
            if room.need != .quiet {
                Text(room.words).eyebrow().secondaryText()
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

    func makeNSView(context: Context) -> KeyView {
        let view = KeyView()
        view.onFocus = report
        view.onKey = key
        return view
    }

    func updateNSView(_ view: KeyView, context: Context) {
        view.onKey = key
        view.onFocus = report
    }

    /// Whether the view has the keyboard, written only when it changes, so a render does not
    /// follow every responder call.
    private func report(_ has: Bool) {
        DispatchQueue.main.async { if focused != has { focused = has } }
    }

    final class KeyView: NSView {
        var onFocus: ((Bool) -> Void)?
        var onKey: ((TimelineKey) -> Bool)?
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
            let key: TimelineKey?
            switch event.keyCode {
            case 126: key = .up
            case 125: key = .down
            case 36, 76: key = .open // Return, Enter
            case 49: key = .look // Space
            case 53: key = .close // Escape
            default: key = nil
            }
            // Only the bare key: ⌘↑ and the like are the menus' and the system's.
            let bare = event.modifierFlags.intersection([.command, .option, .control]).isEmpty
            if let key, bare, onKey?(key) == true { return }
            super.keyDown(with: event)
        }
    }
}

/// A key the timeline acts on.
private enum TimelineKey {
    case up, down, open, look, close
}

/// The room on screen: its timeline and a field to post, with its members beside it.
private struct RoomView: View {
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
    /// Whether the keyboard is on the timeline (WCAG 2.1.1): ↑/↓ move the selection, Return
    /// opens the selected message's first action, Space Quick Looks its pulled file.
    @State private var timelineFocused = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                if !model.roomServices.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
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
                        .padding(8)
                    }
                    Divider()
                }
                Text(model.timelineTitle)
                    .secondaryText()
                    .lineLimit(1).truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12).padding(.top, 8)
                    .accessibilityIdentifier("timeline-title")
                if let header = model.sessionHeader {
                    Text(header)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12).padding(.top, 4)
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
                                LazyVStack(alignment: .leading, spacing: 10) {
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
                                            MessageRow(message: message, me: model.me,
                                                       readBy: model.readBy[message.id] ?? [],
                                                       pulledBy: model.pulledBy[message.id] ?? [],
                                                       pulled: model.pulled[message.id]) { looking = $0 }
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .padding(4)
                                                .selectable(model.selectedMessage == message.id,
                                                            focused: timelineFocused
                                                                && model.selectedMessage == message.id) {
                                                    model.selectedMessage = message.id
                                                    // Clicked: the keyboard follows, as in a list.
                                                    NotificationCenter.default.post(
                                                        name: .voxFocusTimeline, object: nil)
                                                }
                                                .reportsFrame(of: message.id)
                                                .id(message.id)
                                        } else if let notice = item.notice {
                                            // What was done to the room: a line among the
                                            // messages, not one of them (ADR-028 R-1, R-7).
                                            Text(notice).secondaryText().italic()
                                                .padding(.horizontal, 4)
                                                .accessibilityIdentifier(item.id)
                                                .id(item.id)
                                        } else if let entry = item.entry, let session = model.shownSession {
                                            SessionEntryRow(model: model, session: session,
                                                            entry: entry) { looking = $0 }
                                                .id(item.id)
                                        }
                                    }
                                }
                                .padding(12)
                            }
                            .coordinateSpace(name: "timeline")
                            // **Operable from the keyboard** (WCAG 2.1.1, 2.4.7): see
                            // `TimelineKeys`. The focused row is outlined by `selectable`.
                            .background(TimelineKeys(focused: $timelineFocused) { key in
                                switch key {
                                case .up: return move(.up, scroller)
                                case .down: return move(.down, scroller)
                                case .open: return openSelected()
                                case .look: return toggleLook()
                                case .close: return closeLook()
                                }
                            })
                            .onReceive(NotificationCenter.default.publisher(for: .voxFocusTimeline)) { _ in
                                // Taken: the newest row, when none was selected.
                                if model.selectedMessage == nil, let last = model.messages.last {
                                    model.selectedMessage = last.id
                                    scroller.scrollTo(last.id)
                                }
                            }
                            .onPreferenceChange(RowFrames.self) { frames in
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
                                if let last = model.messages.last {
                                    scroller.scrollTo(last.id, anchor: .bottom)
                                }
                                newest = model.messages.last?.id
                            }
                            .onChange(of: model.messages.count) { _ in
                                let following = newest == nil || inView.contains(newest ?? "")
                                if following, let last = model.messages.last {
                                    scroller.scrollTo(last.id, anchor: .bottom)
                                }
                                newest = model.messages.last?.id
                            }
                        }
                    }
                    .background(WindowReader(seen: window))
                    .onChange(of: window.seen) { _ in markSeen() }
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
                    composer
                } else if let s = model.shownSession, s.canDrive, s.open {
                    Divider()
                    SessionComposer(model: model, session: s)
                }
            }
            Divider()
            Inspector(model: model, room: room)
                .frame(width: Theme.scaled(240))
        }
        // On the room, not its timeline: ⌘O, ⌘↩ and a file from the Finder Services item work
        // wherever the room's focus is.
        .sheet(item: $attaching) { file in
            AttachSheet(model: model, file: file) { attaching = nil }
        }
        .onChange(of: model.attachAsked) { _ in
            // After the update, not inside it: a modal panel run from within a view update did
            // not open (⌘O, seen in the QE pass).
            DispatchQueue.main.async {
                if let url = chooseFile() { attaching = Attaching(url: url) }
            }
        }
        .onChange(of: model.urgentAsked) { _ in send(urgent: true) }
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
        Divider()
        if let reply = model.replyTo {
            HStack {
                Text("Replying to \(reply.authorName.isEmpty ? String(reply.author.prefix(12)) : reply.authorName): \(reply.text.prefix(60))")
                    .lineLimit(1).secondaryText()
                Spacer()
                Button("Cancel") { model.replyTo = nil }.buttonStyle(.borderless)
            }
            .padding(.horizontal, 12).padding(.top, 8)
            .accessibilityIdentifier("replying-to")
        }
        HStack(spacing: 8) {
            Button {
                if let url = chooseFile() { attaching = Attaching(url: url) }
            } label: {
                Image(systemName: "paperclip")
            }
            .buttonStyle(.borderless)
            .help("Attach a file or folder")
            .accessibilityLabel("Attach a file or folder")
            .accessibilityIdentifier("attach")
            TextField("Say something to the room", text: $draft)
                .accessibilityLabel("Message to the room")
                .textFieldStyle(.plain)
                .frame(minWidth: Theme.scaled(160), maxWidth: .infinity)
                .layoutPriority(1)
                .onSubmit { send(urgent: urgent) }
                .accessibilityIdentifier("compose")
            ComposerAddress(model: model, to: $to, urgent: $urgent)
        }
        .padding(12)
    }

    /// Post the draft, To: and replying as set; urgent when asked (⌘↩ or the switch).
    private func send(urgent now: Bool) {
        let (text, recipients, re) = (draft, Array(to), model.replyTo?.id ?? "")
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        draft = ""
        urgent = false
        model.replyTo = nil
        Task { await model.post(text, to: recipients, urgent: now, re: re) }
    }

    /// ↑/↓ on the timeline: the selection moves to the message before or after it, scrolled into
    /// view; with none selected, ↑ takes the newest and ↓ the oldest.
    private func move(_ direction: MoveCommandDirection, _ scroller: ScrollViewProxy) -> Bool {
        let ids = model.timelineItems.compactMap { $0.message?.id }
        guard !ids.isEmpty else { return false }
        let at = model.selectedMessage.flatMap { ids.firstIndex(of: $0) }
        let next: Int
        switch direction {
        case .up: next = at.map { max($0 - 1, 0) } ?? ids.count - 1
        case .down: next = at.map { min($0 + 1, ids.count - 1) } ?? 0
        default: return false
        }
        model.selectedMessage = ids[next]
        withAnimation(Theme.motion(reduced: reduceMotion)) {
            scroller.scrollTo(ids[next])
        }
        return true
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

    /// The rows in view are read, only while the window is in front of the person (R-6).
    private func markSeen() {
        readLog.debug("seen check in \(room, privacy: .public): window seen \(window.seen), \(inView.count) rows in view")
        guard window.seen else { return }
        for id in inView {
            if let message = model.byID[id] { model.drawn(message, in: room) }
        }
    }
}

/// One message in the timeline.
private struct MessageRow: View {
    let message: RoomMessage
    let me: String
    /// Who has read it, when it is this node's own (R-6).
    let readBy: [String]
    /// Who has pulled it, verified, when it is this node's own share (#498).
    let pulledBy: [String]
    /// Where this node's verified copy of the file it shares is, once pulled.
    let pulled: String?
    /// Open a pulled copy with Quick Look.
    let look: (URL) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(author).fontWeight(.bold)
                // Its time of day; the whole date and time on hover and to VoiceOver.
                Text(TimelineTime.short(message.createdMillis))
                    .font(Theme.mono).secondaryText()
                    .help(TimelineTime.full(message.createdMillis))
                    .accessibilityLabel(TimelineTime.full(message.createdMillis))
                    .accessibilityIdentifier("time-\(message.id)")
                if message.urgent { StateMark(kind: .attention, words: "urgent") }
                if message.to.contains(me) { Text("to you").eyebrow() }
                if message.late {
                    // ADR-023: it took its place above messages already shown.
                    Text("arrived late").eyebrow().secondaryText()
                        .accessibilityIdentifier("late-\(message.id)")
                }
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
                Text("pulled by \(pulledBy.joined(separator: ", "))")
                    .caption().secondaryText()
                    .accessibilityIdentifier("pulled-by-\(message.id)")
                    .accessibilityLabel("pulled by \(pulledBy.joined(separator: ", "))")
            }
            if !readBy.isEmpty {
                Text("read by \(readBy.joined(separator: ", "))")
                    .caption().secondaryText()
                    .accessibilityIdentifier("read-by-\(message.id)")
                    .accessibilityLabel("read by \(readBy.joined(separator: ", "))")
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
        if !readBy.isEmpty { said += ", read by \(readBy.joined(separator: ", "))" }
        return said
    }

    /// A share's text is its note.
    private var shownText: String { message.file?.note ?? message.text }

    private var author: String {
        if message.author == me { return "you" }
        return message.authorName.isEmpty ? String(message.author.prefix(12)) : message.authorName
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
    let file: FileOffer
    /// The image's preview its share announced (ADR-028 F-9): shown while the sharer is offline.
    let image: ImagePreview?
    /// This node's verified copy, once pulled (F-3, F-4).
    let pulled: String?
    let look: (URL) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            if let image, let thumb = NSImage(data: image.thumb) {
                Image(nsImage: thumb)
                    .resizable()
                    .aspectRatio(CGFloat(image.width) / CGFloat(max(image.height, 1)), contentMode: .fit)
                    .frame(maxWidth: 160, maxHeight: 120)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                    .accessibilityLabel("image \(image.width) by \(image.height)")
                    .accessibilityIdentifier("thumb-\(file.name)")
            } else {
                Image(systemName: file.folder ? "folder" : "doc")
                    .font(Theme.glyph)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(file.name).fontWeight(.bold)
                Text("\(ByteCountFormatter.string(fromByteCount: Int64(file.size), countStyle: .file))"
                    + "  ·  sha256 \(file.sha256.prefix(16))…")
                    .font(Theme.mono).secondaryText()
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
        .padding(8)
        .cardOutline()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("file-\(file.name)")
        .accessibilityLabel("\(file.folder ? "folder" : "file") \(file.name), \(file.size) bytes")
    }
}

/// A link's card (ADR-028 F-10): what the sender's node found at the message's first link, carried
/// in the message, so drawing it fetches nothing. Opening the link is the person's own choice.
private struct LinkCardView: View {
    let card: LinkCard

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            if let data = card.image, let picture = NSImage(data: data) {
                Image(nsImage: picture).resizable().aspectRatio(contentMode: .fit)
                    .frame(maxWidth: 72, maxHeight: 72)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 2) {
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
        .padding(8)
        .cardOutline()
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("card-\(card.url)")
    }
}

/// A service a member shares in the room: its address, who shares it, and what it is (ADR-028 S-2).
private struct ServiceCard: View {
    let service: SharedService

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "point.3.connected.trianglepath.dotted").accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(service.address).font(Theme.mono).textSelection(.enabled)
                Text("by \(service.by)  ·  \(service.kind)\(service.udp && service.kind != "udp" ? "/udp" : "")")
                    .caption().secondaryText()
            }
        }
        .padding(8)
        .cardOutline()
    }
}

/// The room's Sessions (ADR-029 CL-2), then its members and their trust (L-4).
private struct Inspector: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            SessionsList(model: model)
            Divider().padding(.vertical, 8)
            Text("MEMBERS").eyebrow().secondaryText()
                .accessibilityAddTraits(.isHeader)
            ForEach(model.members) { member in
                TrustMark(name: member.name, trust: member.trust)
                    .accessibilityIdentifier("member-\(member.name)")
                // What this node's keyring grants it (K-14), once it is in the keyring.
                if member.trust != .none {
                    Text(Capability.words(member.drive)).eyebrow().secondaryText()
                        .padding(.leading, 18)
                        .accessibilityIdentifier("member-capability-\(member.name)")
                }
                // The platform its node says it runs on (ADR-020 §4.9b): its claim, said as one.
                if let platform = model.platforms[member.id] {
                    Text("says it runs on \(Platform.words(platform))")
                        .font(Theme.mono).secondaryText()
                        .padding(.leading, 18)
                        // Not selectable: a selectable Text with its own label sent SwiftUI's
                        // accessibility into endless recursion, and the app crashed when read.
                        .accessibilityLabel("\(member.name) says it runs on \(Platform.words(platform))")
                        .accessibilityIdentifier("member-platform-\(member.name)")
                }
            }
            Divider().padding(.vertical, 8)
            FamilyLan(model: model, room: room)
            Spacer()
        }
        .padding(12)
        .frame(maxHeight: .infinity, alignment: .topLeading)
        // A container, so each row keeps its own identifier (member-<name>) under this one.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("inspector")
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

/// The room's family LAN (ADR-013): offered only once the LAN helper is approved, and before
/// that, what approving it grants (ADR-014 M-12).
private struct FamilyLan: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        Text("FAMILY LAN").eyebrow().secondaryText()
            .accessibilityAddTraits(.isHeader)
        if model.lanHelperReady {
            Toggle("On this room's LAN", isOn: Binding(
                get: { model.lanOn.contains(room) },
                set: { on in Task { await model.setLan(room, on: on) } }))
                .accessibilityIdentifier("family-lan")
            if let said = model.lanSaid[room] {
                Text(said).font(Theme.mono).secondaryText().textSelection(.enabled)
                    .accessibilityIdentifier("family-lan-said")
            }
            Button("Remove the LAN Helper") { Task { await model.removeLanHelper() } }
                .accessibilityIdentifier("family-lan-remove")
        } else {
            Text("The family LAN needs Vox's LAN helper: one root process that creates network "
                + "interfaces for Vox and nothing else. Approve it once in System Settings.")
                .secondaryText()
                .accessibilityIdentifier("family-lan-why")
            Button("Allow the LAN Helper") { Task { await model.allowLanHelper() } }
                .accessibilityIdentifier("family-lan-allow")
        }
        if let failed = model.lanFailed[room] {
            StateMark(kind: .danger, words: failed).textSelection(.enabled)
        }
    }
}

/// The node, its peers and the keyring window (W-1, K-9); and the last thing that failed, in the
/// daemon's words (M-7).
private struct StatusBar: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        HStack(spacing: 16) {
            Text("node \(model.node)")
            Text(model.peers == 1 ? "1 peer" : "\(model.peers) peers")
            Text(model.keyring)
            if let did = model.did {
                Text(did)
            }
            if model.notifying == false {
                // M-23: said where the person works, so a missing notification is explained.
                Text("notifications off (System Settings, Notifications, Vox)")
                    .accessibilityIdentifier("notifications-off")
            }
            Spacer()
            if let ended = model.ended {
                StateMark(kind: .danger, words: ended)
            } else if let said = model.said {
                StateMark(kind: .danger, words: said).textSelection(.enabled)
            }
        }
        .font(Theme.mono)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        // A container, so "notifications-off" keeps its identifier; its label says the whole bar.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("status")
        .accessibilityLabel(words)
    }

    /// The bar, in words.
    private var words: String {
        var parts = ["node \(model.node)", model.peers == 1 ? "1 peer" : "\(model.peers) peers",
                     model.keyring]
        if let did = model.did { parts.append(did) }
        if model.notifying == false {
            parts.append("notifications off (System Settings, Notifications, Vox)")
        }
        if let ended = model.ended { parts.append(ended) } else if let said = model.said {
            parts.append(said)
        }
        return parts.filter { !$0.isEmpty }.joined(separator: ", ")
    }
}

extension RoomGroup {
    /// The group, as the sidebar heads it (the TUI's words).
    var words: String { roomGroupWords(group: self) }
}
