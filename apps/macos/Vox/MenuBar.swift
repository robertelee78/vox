// The menu bar extra (ADR-014 M-22, ADR-028 A-3): off until the person turns it on, offered at
// first run. It shows the node's state and keyring window, the rooms with messages addressed to it
// (the sidebar's "needs you"), the services shared to it with copy buttons, its own shares with
// stop, and its live tunnels.

import AppKit
import SwiftUI

/// Whether the person turned the menu bar extra on, kept beside vox's own settings.
enum MenuBarChoice {
    static func on() -> Bool {
        guard let file = file(), let text = try? String(contentsOf: file, encoding: .utf8) else {
            return false
        }
        return text.trimmingCharacters(in: .whitespacesAndNewlines) == "on"
    }

    static func set(_ on: Bool) {
        guard let file = file() else { return }
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try? Data((on ? "on\n" : "off\n").utf8).write(to: file, options: .atomic)
    }

    private static func file() -> URL? {
        guard let dir = try? configDir(dataRoot: "") else { return nil }
        return URL(fileURLWithPath: dir).appendingPathComponent("app/menubar")
    }
}

/// What the menu bar extra lists, read when it opens.
struct MenuBarFacts {
    struct Service: Hashable {
        let address: String
        let by: String
    }

    struct Share: Hashable {
        let room: String
        let roomName: String
        let name: String
        let tag: String
    }

    struct Tunnel: Hashable {
        let id: Int
        let peer: String
        let service: String
        let outbound: Bool
    }

    var services: [Service] = []
    var shares: [Share] = []
    var tunnels: [Tunnel] = []
}

struct MenuBarContent: View {
    @ObservedObject var app: AppModel
    @State private var facts = MenuBarFacts()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let model = app.node {
                NodeFacts(model: model, facts: facts)
                    .task { facts = await model.menuBarFacts() }
            } else {
                Text("Vox is not acting as a node yet.").secondaryText()
            }
            Divider()
            Button("Open Vox") {
                NSApp.activate(ignoringOtherApps: true)
                NSApp.windows.first { $0.identifier?.rawValue.contains("main") ?? false }?
                    .makeKeyAndOrderFront(nil)
            }
            Button("Hide This Menu Bar Item") { app.menuBar = false }
        }
        .padding(12)
        .frame(width: 320)
        .font(Theme.text)
    }
}

private struct NodeFacts: View {
    @ObservedObject var model: NodeModel
    let facts: MenuBarFacts

    var body: some View {
        StateMark(kind: .live, words: "node \(model.node), attached")
        Text(model.keyring).font(Theme.mono).secondaryText()
        section("NEEDS YOU") {
            let rooms = model.group(.needsYou)
            if rooms.isEmpty { Text("nothing addressed to you").secondaryText() }
            ForEach(rooms) { room in
                Button("\(room.name): \(room.words)") {
                    NSApp.activate(ignoringOtherApps: true)
                    Task { await model.show(.room(room.id)) }
                }
            }
        }
        section("SERVICES SHARED TO YOU") {
            if facts.services.isEmpty { Text("none").secondaryText() }
            ForEach(facts.services, id: \.self) { service in
                HStack {
                    Text(service.address).font(Theme.mono).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(service.address, forType: .string)
                    }
                    .help("by \(service.by)")
                }
            }
        }
        section("YOUR SHARES") {
            if facts.shares.isEmpty { Text("none").secondaryText() }
            ForEach(facts.shares, id: \.self) { share in
                HStack {
                    Text("\(share.name) in \(share.roomName)").lineLimit(1)
                    Spacer()
                    Button("Stop") { Task { await model.stopShare(share) } }
                }
            }
        }
        section("LIVE TUNNELS") {
            if facts.tunnels.isEmpty { Text("none").secondaryText() }
            ForEach(facts.tunnels, id: \.self) { tunnel in
                Text("\(tunnel.outbound ? "to" : "from") \(tunnel.peer): \(tunnel.service)")
                    .font(Theme.mono)
            }
        }
    }

    @ViewBuilder
    private func section(_ title: String, @ViewBuilder _ rows: () -> some View) -> some View {
        Text(title).font(Theme.eyebrow).secondaryText()
        rows()
    }
}
