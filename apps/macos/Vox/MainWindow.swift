// The main window (ADR-028 W-1, W-2; ADR-014 M-13): a sidebar with the node, its rooms grouped by
// what they need from the person and the nodes on this Mac; the room's timeline; an inspector with
// its members and their trust; and a status bar with the node, its peers and the keyring window.
// The keyring is a view of this window, not a window of its own.

import SwiftUI

struct MainWindow: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        VStack(spacing: 0) {
            NavigationSplitView {
                Sidebar(model: model)
                    .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            } detail: {
                switch model.selection {
                case let .room(id):
                    RoomView(model: model, room: id)
                case .keyring:
                    KeyringView(model: model)
                case .decisions:
                    DecisionsView(model: model)
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
        List(selection: Binding(get: { model.selection },
                                set: { s in Task { await model.show(s) } })) {
            Section {
                StateMark(kind: .live, words: "node \(model.node), attached")
                    .accessibilityIdentifier("attached")
            }
            ForEach([RoomGroup.needsYou, .active, .quiet], id: \.self) { need in
                let rooms = model.group(need)
                Section {
                    ForEach(rooms) { room in
                        RoomRow(room: room).tag(NodeModel.Selection.room(room.id))
                    }
                } header: {
                    Text("\(need.words) (\(rooms.count))")
                        .font(Theme.eyebrow)
                        .accessibilityIdentifier("group-\(need.words)")
                        .accessibilityLabel("\(need.words) (\(rooms.count))")
                }
            }
            Section {
                Text("Keyring").tag(NodeModel.Selection.keyring)
                    .accessibilityIdentifier("keyring")
                Text("Decision record").tag(NodeModel.Selection.decisions)
                    .accessibilityIdentifier("decisions")
            }
            Section {
                ForEach(model.nodes, id: \.name) { node in
                    StateMark(kind: node.state == "attached" ? .live : .plain,
                              words: "\(node.name) \(node.state)")
                        .accessibilityIdentifier("node-\(node.name)")
                }
            } header: {
                Text("nodes on this Mac").font(Theme.eyebrow)
            }
        }
        .listStyle(.sidebar)
    }
}

/// A room in the sidebar: its name, and its unread in words.
private struct RoomRow: View {
    let room: NodeModel.Room

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(room.name).fontWeight(room.need == .quiet ? .regular : .bold)
            if room.need != .quiet {
                Text(room.words).font(Theme.eyebrow).secondaryText()
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier("room-\(room.name)")
        .accessibilityLabel("\(room.name), \(room.need.words), \(room.words)")
    }
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

/// What the composer posts is addressed to, and whether it is urgent (M-15).
    @State private var to: Set<String> = []
    @State private var urgent = false
    /// The rows inside the visible part of the timeline, as last measured.
    @State private var inView: Set<String> = []

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                if !model.roomServices.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(model.roomServices, id: \.address) { service in
                                ServiceCard(service: service)
                                    .background(model.selectedService?.address == service.address
                                                ? VoxTokens.Colors.textSecondary.opacity(0.15) : Color.clear)
                                    .onTapGesture { model.selectedService = service }
                            }
                        }
                        .padding(8)
                    }
                    Divider()
                }
                if model.roomHasAgents {
                    Picker("", selection: $model.showLanes) {
                        Text("Timeline").tag(false)
                        Text("Lanes").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 220)
                    .padding(8)
                    .accessibilityIdentifier("lanes-toggle")
                }
                if model.showLanes && model.roomHasAgents {
                    LanesView(model: model)
                } else {
                    GeometryReader { viewport in
                        ScrollViewReader { scroller in
                            // A scroll view of its own, not a List: a List's rows are cells whose frames
                            // do not measure in this coordinate space, so what is in view could not be
                            // told.
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 10) {
                                    ForEach(model.messages, id: \.id) { message in
                                        MessageRow(message: message, me: model.me,
                                                   readBy: model.readBy[message.id] ?? [],
                                                   pulled: model.pulled[message.id]) { looking = $0 }
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .padding(4)
                                            .background(model.selectedMessage == message.id
                                                        ? VoxTokens.Colors.textSecondary.opacity(0.15) : Color.clear)
                                            .contentShape(Rectangle())
                                            .onTapGesture { model.selectedMessage = message.id }
                                            .reportsFrame(of: message.id)
                                            .id(message.id)
                                    }
                                }
                                .padding(12)
                            }
                            .coordinateSpace(name: "timeline")
                            .onPreferenceChange(RowFrames.self) { frames in
                                // Seen: at least half of the row inside the timeline's bounds.
                                let bounds = CGRect(origin: .zero, size: viewport.size)
                                inView = Set(frames.compactMap { id, frame in
                                    let shown = frame.intersection(bounds)
                                    return !shown.isNull && shown.height * 2 >= frame.height ? id : nil
                                })
                                markSeen()
                            }
                            .onChange(of: model.messages.count) { _ in
                                if let last = model.messages.last {
                                    scroller.scrollTo(last.id, anchor: .bottom)
                                }
                            }
                        }
                    }
                    .background(WindowReader(seen: window))
                    .onChange(of: window.seen) { _ in markSeen() }
                    // A file dropped on the timeline, or pasted into it, is attached (M-24, F-1).
                    .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                        firstFile(in: providers) { attaching = Attaching(url: $0) }
                    }
                    .onPasteCommand(of: [.fileURL]) { providers in
                        _ = firstFile(in: providers) { attaching = Attaching(url: $0) }
                    }
                    .accessibilityIdentifier("timeline")
                    .sheet(item: $attaching) { file in
                        AttachSheet(model: model, file: file) { attaching = nil }
                    }
                    .quickLookPreview($looking)
                    .onChange(of: model.attachAsked) { _ in
                        if let url = chooseFile() { attaching = Attaching(url: url) }
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
                        .textFieldStyle(.plain)
                        .onSubmit { send(urgent: urgent) }
                        .accessibilityIdentifier("compose")
                    ComposerAddress(model: model, to: $to, urgent: $urgent)
                }
                .padding(12)
            }
            Divider()
            Inspector(model: model, room: room)
                .frame(width: 240)
        }
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

    /// The rows in view are read, only while the window is in front of the person (R-6).
    private func markSeen() {
        guard window.seen else { return }
        for message in model.messages where inView.contains(message.id) {
            model.drawn(message)
        }
    }
}

/// One message in the timeline.
private struct MessageRow: View {
    let message: RoomMessage
    let me: String
    /// Who has read it, when it is this node's own (R-6).
    let readBy: [String]
    /// Where this node's verified copy of the file it shares is, once pulled.
    let pulled: String?
    /// Open a pulled copy with Quick Look.
    let look: (URL) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(author).fontWeight(.bold)
                if message.urgent { StateMark(kind: .attention, words: "urgent") }
                if message.to.contains(me) { Text("to you").font(Theme.eyebrow) }
                if message.late {
                    // ADR-023: it took its place above messages already shown.
                    Text("arrived late").font(Theme.eyebrow).secondaryText()
                        .accessibilityIdentifier("late-\(message.id)")
                }
            }
            if let file = message.file {
                FileCard(file: file, pulled: pulled, look: look)
            }
            if message.file == nil || !(message.file?.note.isEmpty ?? true) {
                Text(message.owed ? "not received yet" : shownText)
                    .textSelection(.enabled)
            }
            if !readBy.isEmpty {
                Text("read by \(readBy.joined(separator: ", "))")
                    .font(Theme.eyebrow).secondaryText()
                    .accessibilityIdentifier("read-by-\(message.id)")
                    .accessibilityLabel("read by \(readBy.joined(separator: ", "))")
            }
        }
    }

    /// A share's text is its note.
    private var shownText: String { message.file?.note ?? message.text }

    private var author: String {
        if message.author == me { return "you" }
        return message.authorName.isEmpty ? String(message.author.prefix(12)) : message.authorName
    }
}

/// A file or folder offered in the room (ADR-028 F-1): its name, size and SHA-256, as the share's
/// signed announcement states them.
private struct FileCard: View {
    let file: FileOffer
    /// This node's verified copy, once pulled (F-3, F-4).
    let pulled: String?
    let look: (URL) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: file.folder ? "folder" : "doc")
                .font(.system(size: 22))
                .accessibilityHidden(true)
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
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(VoxTokens.Colors.textSecondary.opacity(0.4)))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("file-\(file.name)")
        .accessibilityLabel("\(file.folder ? "folder" : "file") \(file.name), \(file.size) bytes")
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
                    .font(Theme.eyebrow).secondaryText()
            }
        }
        .padding(8)
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(VoxTokens.Colors.textSecondary.opacity(0.4)))
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier("service-\(service.address)")
        .accessibilityLabel("service \(service.address), shared by \(service.by), \(service.kind)")
    }
}

/// The room's members and their trust (L-4).
private struct Inspector: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MEMBERS").font(Theme.eyebrow).secondaryText()
            ForEach(model.members) { member in
                TrustMark(name: member.name, trust: member.trust)
                    .accessibilityIdentifier("member-\(member.name)")
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

/// The room's family LAN (ADR-013): offered only once the LAN helper is approved, and before
/// that, what approving it grants (ADR-014 M-12).
private struct FamilyLan: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        Text("FAMILY LAN").font(Theme.eyebrow).secondaryText()
        if model.lanHelperReady {
            Toggle("On this room's LAN", isOn: Binding(
                get: { model.lanOn.contains(room) },
                set: { on in Task { await model.setLan(room, on: on) } }))
                .accessibilityIdentifier("family-lan")
            if let said = model.lanSaid[room] {
                Text(said).font(Theme.mono).secondaryText().textSelection(.enabled)
                    .accessibilityIdentifier("family-lan-said")
            }
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
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("status")
    }
}

extension RoomGroup {
    /// The group, as the sidebar heads it (the TUI's words).
    var words: String { roomGroupWords(group: self) }
}
