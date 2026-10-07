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
                    // One view per room: its draft, To:, urgent and attachment do not carry over.
                    RoomView(model: model, room: id).id(id)
                case .keyring:
                    KeyringView(model: model)
                case .decisions:
                    DecisionsView(model: model)
                case .services:
                    ServicesView(model: model)
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
                        .eyebrow()
                        .accessibilityIdentifier("group-\(need.words)")
                        .accessibilityLabel("\(need.words) (\(rooms.count))")
                }
            }
            Section {
                Text("Keyring").tag(NodeModel.Selection.keyring)
                    .accessibilityIdentifier("keyring")
                Text("Decision record").tag(NodeModel.Selection.decisions)
                    .accessibilityIdentifier("decisions")
                Text("Services").tag(NodeModel.Selection.services)
                    .accessibilityIdentifier("services")
            }
            Section {
                ForEach(model.nodes, id: \.name) { node in
                    StateMark(kind: node.state == "attached" ? .live : .plain,
                              words: "\(node.name) \(node.state)")
                        .accessibilityIdentifier("node-\(node.name)")
                }
            } header: {
                Text("nodes on this Mac").eyebrow()
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
                Text(room.words).eyebrow().secondaryText()
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
    /// The newest message when the messages last changed: if it was in view, the timeline follows
    /// the next one; scrolled up to read, it stays (as the TUI does, V210-82).
    @State private var newest: String?

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
                Group {
                    GeometryReader { viewport in
                        ScrollViewReader { scroller in
                            // A scroll view of its own, not a List: a List's rows are cells whose frames
                            // do not measure in this coordinate space, so what is in view could not be
                            // told.
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 10) {
                                    ForEach(model.timelineItems) { item in
                                        if let message = item.message {
                                            MessageRow(message: message, me: model.me,
                                                       readBy: model.readBy[message.id] ?? [],
                                                       pulledBy: model.pulledBy[message.id] ?? [],
                                                       pulled: model.pulled[message.id]) { looking = $0 }
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                                .padding(4)
                                                .selectable(model.selectedMessage == message.id) {
                                                    model.selectedMessage = message.id
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
                                        }
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
                    .quickLookPreview($looking)
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
                        .frame(minWidth: 160, maxWidth: .infinity)
                        .layoutPriority(1)
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
                    .eyebrow().secondaryText()
                    .accessibilityIdentifier("pulled-by-\(message.id)")
                    .accessibilityLabel("pulled by \(pulledBy.joined(separator: ", "))")
            }
            if !readBy.isEmpty {
                Text("read by \(readBy.joined(separator: ", "))")
                    .eyebrow().secondaryText()
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
                    Link(card.url, destination: url).eyebrow().lineLimit(1)
                        .truncationMode(.middle)
                } else {
                    Text(card.url).eyebrow().lineLimit(1).truncationMode(.middle)
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
                    .eyebrow().secondaryText()
            }
        }
        .padding(8)
        .cardOutline()
    }
}

/// The room's members and their trust (L-4).
private struct Inspector: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MEMBERS").eyebrow().secondaryText()
            ForEach(model.members) { member in
                TrustMark(name: member.name, trust: member.trust)
                    .accessibilityIdentifier("member-\(member.name)")
                // What this node's keyring grants it (K-14), once it is in the keyring.
                if member.trust != .none {
                    Text(Capability.words(member.drive)).eyebrow().secondaryText()
                        .padding(.leading, 18)
                        .accessibilityIdentifier("member-capability-\(member.name)")
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

/// The room's family LAN (ADR-013): offered only once the LAN helper is approved, and before
/// that, what approving it grants (ADR-014 M-12).
private struct FamilyLan: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        Text("FAMILY LAN").eyebrow().secondaryText()
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
