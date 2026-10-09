// The services view (ADR-014 M-17; ADR-028 S-1–S-5): every service this node can see, in every
// open room, with its ready-to-copy commands (the readable address shown, the canonical one
// copied) and what reaching it needs; this node's own shares, each with Stop; and one-step
// sharing from what listens on this Mac. A view of the main window.

import AppKit
import SwiftUI

/// One open room's services, as the view lists them.
struct RoomServicesRow: Identifiable, Equatable {
    let id: String
    let name: String
    let shared: [SharedService]
    let offered: [OfferedService]
}

extension NodeModel {
    /// Every open room's services, read now.
    func readServices() async -> [RoomServicesRow] {
        var rows: [RoomServicesRow] = []
        for room in rooms where room.open {
            if let listed = try? await services(of: room.id) {
                rows.append(RoomServicesRow(id: room.id, name: room.name, shared: listed.shared,
                                            offered: listed.offered))
            }
        }
        return rows
    }

    /// Who in `room` can reach a service this node shares there, and who cannot: reach is this
    /// node's decision, so the members it trusts can (ADR-017 4.2).
    func reach(in room: String) async -> (can: [String], cannot: [String]) {
        guard let roster = try? await rosterOf(room) else { return ([], []) }
        let keyring = Set(trusted.map(\.fingerprint))
        let others = roster.filter { $0.fingerprint != me }
        let name = { (m: Member) in m.name.isEmpty ? String(m.fingerprint.prefix(12)) : m.name }
        return (others.filter { keyring.contains($0.fingerprint) }.map(name),
                others.filter { !keyring.contains($0.fingerprint) }.map(name))
    }
}

struct ServicesView: View {
    @ObservedObject var model: NodeModel
    @State private var rows: [RoomServicesRow] = []
    @State private var listening: ListeningServices?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.s16) {
                Text("Services").title()
                // What this view's last share, stop or copy did: its own, never another's (P6).
                if let did = model.outcome.flatMap({
                    $0.kind == .done && ["share", "stop-share", "copy"].contains($0.operation) ? $0.words : nil
                }) {
                    StateMark(kind: .plain, words: did).textSelection(.enabled)
                        .accessibilityIdentifier("services-did")
                }
                Text("SHARED WITH YOU").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
                let theirs = rows.flatMap { r in r.shared.filter { $0.by != "you" }.map { (r, $0) } }
                if theirs.isEmpty {
                    Text("Nothing is shared with this node in its open rooms.").secondaryText()
                }
                ForEach(theirs, id: \.1.canonical) { room, service in
                    SharedServiceBox(model: model, room: room.name, service: service)
                }
                Hairline()
                Text("YOUR SHARES").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
                let mine = rows.flatMap { r in r.offered.map { (r, $0) } }
                if mine.isEmpty { Text("This node shares nothing.").secondaryText() }
                ForEach(mine, id: \.1.tag) { room, offered in
                    HStack {
                        Text("\(offered.tag) in \(room.name)").fontWeight(.bold)
                        Text("→ \(offered.local)").font(Theme.mono).secondaryText()
                        Spacer()
                        Button("Stop") {
                            Task {
                                await model.stopService(room: room.id, tag: offered.tag)
                                rows = await model.readServices()
                            }
                        }
                        .accessibilityIdentifier("service-stop-\(offered.tag)")
                    }
                    .accessibilityElement(children: .contain)
                    .accessibilityIdentifier("service-mine-\(offered.tag)")
                }
                Hairline()
                ShareForm(model: model, listening: listening) {
                    rows = await model.readServices()
                }
            }
            .padding(Space.s24)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .accessibilityIdentifier("services-view")
        .task {
            // Read again every few seconds while on screen, each part kept only when it changed:
            // a share made or stopped elsewhere shows here.
            while !Task.isCancelled {
                let now = await model.readServices()
                if now != rows { rows = now }
                let here = await model.listeningHere()
                if here != listening { listening = here }
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }
}

/// One service shared with this node: its readable address, who shares it and its kind; each
/// command shown with the readable address and copied with the canonical one (S-1, S-3); and what
/// reaching it needs, as readiness ticks: ✓ when it holds, the missing one in amber with its fix.
private struct SharedServiceBox: View {
    @ObservedObject var model: NodeModel
    let room: String
    let service: SharedService

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            HStack(alignment: .firstTextBaseline) {
                Text(service.address).font(Theme.mono).fontWeight(.bold).textSelection(.enabled)
                Spacer()
                // The whole address, copied canonical: it reaches the same service pasted on any
                // member's machine (S-1, S-3).
                Button("Copy Address") { model.copyAddress(of: service) }
                    .accessibilityLabel("Copy the address \(service.address)")
                    .accessibilityIdentifier("copy-address-\(service.address)")
            }
            AddressAnatomy(address: service.address)
            Text("by \(service.by) in \(room)  ·  \(service.kind)").caption().secondaryText()
            ForEach(Array(service.commands.enumerated()), id: \.offset) { _, command in
                HStack(alignment: .firstTextBaseline) {
                    Text(command.what).eyebrow().secondaryText().frame(width: Theme.scaled(56), alignment: .leading)
                    Text(command.command.replacingOccurrences(of: service.canonical, with: service.address))
                        .font(Theme.mono).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Copy") { model.copyCommand(command.command) }
                        .accessibilityLabel("Copy the \(command.what) command for \(service.address)")
                        .accessibilityIdentifier("copy-\(command.what)-\(service.address)")
                }
            }
            // What reaching it needs, as ticks (the App Study's readiness, in vox-core's words, the
            // same as `vox service list` and the TUI): ✓ when it holds, and the missing one in
            // amber with its fix, never only "connection failed".
            ForEach(Array(service.needs.enumerated()), id: \.offset) { _, need in
                if need.holds {
                    Text("✓ \(need.need)").font(Theme.text).secondaryText()
                        .accessibilityLabel("\(need.need): yes")
                } else {
                    StateMark(kind: .attention, words: "missing: \(need.need) — \(need.otherwise)")
                }
            }
        }
        .padding(Space.s12)
        .cardOutline()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("service-box-\(service.address)")
    }
}

/// One-step sharing (S-4): what listens on this Mac, with its program; picked, a suggested name,
/// the address members will use, what sharing it does and who in the room can and cannot reach
/// it, all said before it is shared.
///
/// **Share acts only on what is on screen** (D15, E-5). The preview is the picked service's and
/// the audience the picked room's, each kept with what it describes: a new pick clears the
/// preview, a new room clears the audience, an answer that comes back for a pick or a room no
/// longer chosen is dropped, and Share is offered only while endpoint, room, warnings and
/// audience all describe the one share it would make.
private struct ShareForm: View {
    @ObservedObject var model: NodeModel
    let listening: ListeningServices?
    let shared: () async -> Void
    @State private var picked: ListeningService?
    /// The preview, and the listening service it was made for.
    @State private var preview: (of: String, preview: ServicePreview)?
    @State private var name = ""
    @State private var room = ""
    /// Who can and cannot reach a share, and the room that is true of.
    @State private var reach: (room: String, can: [String], cannot: [String])?
    @State private var failed: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            Text("SHARE A SERVICE").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
            if let listening {
                ForEach(listening.services, id: \.line) { service in
                    Button {
                        Task { await pick(service) }
                    } label: {
                        Text(service.line).font(Theme.mono).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                    .padding(Space.s4)
                    .selectionMark(picked?.line == service.line)
                    .accessibilityIdentifier("listening-\(service.port)")
                }
                Text(listening.mayBeMissing).secondaryText()
            } else {
                ProgressView()
            }
            if let picked, let preview = preview.flatMap({ $0.of == picked.line ? $0.preview : nil }) {
                TextField("Name", text: $name).accessibilityIdentifier("share-name")
                    .accessibilityLabel("Service name")
                Picker("Room", selection: $room) {
                    ForEach(model.rooms.filter(\.open)) { Text($0.name).tag($0.id) }
                }
                .accessibilityIdentifier("share-room")
                .onChange(of: room) { r in Task { await audience(of: r) } }
                Text("Members will use \(shownTag).\(model.node).\(roomName).vox (each by their own name for this node).")
                    .accessibilityIdentifier("share-address")
                ForEach(preview.warnings, id: \.self) { warning in
                    StateMark(kind: .attention, words: warning).accessibilityIdentifier("share-warning")
                }
                if let reach, reach.room == room {
                    Text(reach.can.isEmpty ? "No one in \(roomName) can reach it: you trust none of its members."
                         : "Can reach it: \(reach.can.joined(separator: ", ")).")
                        .accessibilityIdentifier("share-can")
                    if !reach.cannot.isEmpty {
                        Text("Cannot reach it (not in your keyring): \(reach.cannot.joined(separator: ", ")).")
                            .secondaryText()
                    }
                } else {
                    Text("Finding who in \(roomName) can reach it…").secondaryText()
                        .accessibilityIdentifier("share-can-pending")
                }
                Button("Share \(picked.program ?? "it") in \(roomName)") {
                    Task { await share(preview, of: picked) }
                }
                .disabled(name.isEmpty || room.isEmpty || reach?.room != room)
                .accessibilityIdentifier("share-submit")
            }
            // Said whether or not a preview came: a failed preview left nothing on screen, so a
            // click on a listening service seemed to do nothing.
            if let failed {
                StateMark(kind: .danger, words: failed).textSelection(.enabled)
                    .accessibilityIdentifier("share-said")
            }
        }
    }

    private var roomName: String { model.rooms.first { $0.id == room }?.name ?? "the room" }

    /// The tag the share takes: datagram services keep `udp/`.
    private var shownTag: String { name }

    private func pick(_ service: ListeningService) async {
        // The last pick's preview goes at once: it is not this service's.
        picked = service
        preview = nil
        failed = nil
        do {
            let p = try await model.previewShare(port: service.port, udp: service.udp)
            // An answer for a service no longer picked is dropped.
            guard picked?.line == service.line else { return }
            preview = (service.line, p)
            name = p.name
            if room.isEmpty, let first = model.rooms.first(where: \.open) { room = first.id }
            await audience(of: room)
        } catch {
            guard picked?.line == service.line else { return }
            preview = nil
            failed = sentence(error)
        }
    }

    /// Who in `room` can reach a share, kept only while `room` is still the one chosen.
    private func audience(of room: String) async {
        if reach?.room != room { reach = nil }
        let found = await model.reach(in: room)
        guard self.room == room else { return }
        reach = (room, found.can, found.cannot)
    }

    private func share(_ preview: ServicePreview, of service: ListeningService) async {
        // What Share was offered for, checked again as it acts.
        guard picked?.line == service.line, reach?.room == room else { return }
        let tag = preview.tag.hasPrefix("udp/") ? "udp/\(name)" : name
        if let why = await model.shareService(room: room, tag: tag, local: preview.local) {
            failed = why
        } else {
            picked = nil
            self.preview = nil
            await shared()
        }
    }
}

/// A service's readable address broken into its parts, each labelled (G3, ADR-017 S-1):
/// `<service>.<node>.<room>.vox`, where the node and the room are this node's own aliases, so a
/// person sees the names are theirs. The service and the room are one DNS label each; whatever is
/// between them is the node part.
struct AddressAnatomy: View {
    let address: String

    /// The parts with what each is, or nil for an address of another form.
    static func parts(of address: String) -> [(part: String, what: String)]? {
        guard address.hasSuffix(".vox") else { return nil }
        let labels = address.dropLast(4).split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 3, let service = labels.first, let room = labels.last,
              !service.isEmpty, !room.isEmpty else { return nil }
        let node = labels.dropFirst().dropLast().joined(separator: ".")
        guard !node.isEmpty else { return nil }
        return [(String(service), "service"), (node, "your node alias"),
                (String(room), "your room alias"), ("vox", "Vox address")]
    }

    var body: some View {
        if let parts = Self.parts(of: address) {
            HStack(alignment: .top, spacing: Space.s4) {
                ForEach(Array(parts.enumerated()), id: \.offset) { n, p in
                    if n > 0 { Text(".").font(Theme.mono).secondaryText().accessibilityHidden(true) }
                    VStack(alignment: .leading, spacing: 0) {
                        Text(p.part).font(Theme.mono)
                        Text(p.what).caption().secondaryText()
                    }
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(parts.map { "\($0.part), \($0.what)" }.joined(separator: "; "))
            .accessibilityIdentifier("service-anatomy-\(address)")
        }
    }
}
