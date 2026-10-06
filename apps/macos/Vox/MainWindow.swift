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

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                if !model.roomServices.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(model.roomServices, id: \.address) { ServiceCard(service: $0) }
                        }
                        .padding(8)
                    }
                    Divider()
                }
                ScrollViewReader { scroller in
                    List(model.messages, id: \.id) { message in
                        MessageRow(message: message, me: model.me,
                                   readBy: model.readBy[message.id] ?? [])
                            .onAppear { model.drawn(message) }
                    }
                    .onChange(of: model.messages.count) { _ in
                        if let last = model.messages.last { scroller.scrollTo(last.id, anchor: .bottom) }
                    }
                }
                Divider()
                TextField("Say something to the room", text: $draft)
                    .textFieldStyle(.plain)
                    .padding(12)
                    .onSubmit {
                        let text = draft
                        draft = ""
                        Task { await model.post(text) }
                    }
                    .accessibilityIdentifier("compose")
            }
            Divider()
            Inspector(model: model, room: room)
                .frame(width: 240)
        }
    }
}

/// One message in the timeline.
private struct MessageRow: View {
    let message: RoomMessage
    let me: String
    /// Who has read it, when it is this node's own (R-6).
    let readBy: [String]

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
                FileCard(file: file)
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
            }
        }
        .padding(8)
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(VoxTokens.Colors.textSecondary.opacity(0.4)))
        .accessibilityElement(children: .ignore)
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
