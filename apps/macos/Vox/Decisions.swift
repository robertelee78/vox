// The decision record (ADR-014 M-18, ADR-028 §7): what this node decided — refusals and changes
// of access — newest first, filterable by the node it was about. A view of the main window.

import SwiftUI

struct DecisionsView: View {
    @ObservedObject var model: NodeModel
    private var events: [DecisionEvent] { model.decisionEvents }
    /// The node the record is filtered to, by fingerprint; nil for every node.
    @State private var about: String?
    /// The room it is filtered to, by ID; nil for every room and none.
    @State private var inRoom: String?

    private var shown: [DecisionEvent] {
        events.filter { (about == nil || $0.by == about) && (inRoom == nil || $0.room == inRoom) }
    }

    /// Each room the record names, once, by this node's name for it.
    private var roomsNamed: [(String, String)] {
        Set(events.map(\.room).filter { !$0.isEmpty }).map { id in
            (id, model.rooms.first { $0.id == id }?.name ?? String(id.prefix(12)))
        }.sorted { $0.1 < $1.1 }
    }

    /// Each node the record names, once, by this node's name for it.
    private var nodes: [(String, String)] {
        var seen: [String: String] = [:]
        for e in events where seen[e.by] == nil { seen[e.by] = name(e) }
        return seen.sorted { $0.value < $1.value }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Decision record").title()
            // Two filters that share the room's width: they fit the window's narrowest.
            HStack {
                Picker("About", selection: $about) {
                    Text("every node").tag(String?.none)
                    ForEach(nodes, id: \.0) { Text($0.1).tag(String?.some($0.0)) }
                }
                .frame(minWidth: Theme.scaled(140), maxWidth: Theme.scaled(220))
                .accessibilityIdentifier("decisions-about")
                Picker("Room", selection: $inRoom) {
                    Text("every room").tag(String?.none)
                    ForEach(roomsNamed, id: \.0) { Text($0.1).tag(String?.some($0.0)) }
                }
                .frame(minWidth: Theme.scaled(140), maxWidth: Theme.scaled(220))
                .accessibilityIdentifier("decisions-room")
            }
            Text("What this node refused, and every change of who reaches it, kept 14 days and "
                + "never sent anywhere. Newest first.").secondaryText()
            if shown.isEmpty {
                Text("Nothing decided yet.").secondaryText()
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: Space.s12) {
                    ForEach(Array(shown.enumerated()), id: \.offset) { index, event in
                        DecisionRow(event: event, who: name(event))
                            .accessibilityIdentifier("decision-\(index)")
                    }
                }
            }
        }
        .padding(Space.s24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task {
            // Read again every few seconds while on screen: the node appends as it decides.
            while !Task.isCancelled {
                let now = await model.decisions()
                if now != model.decisionEvents { model.decisionEvents = now }
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    /// The node's name for whom an event is about (K-3): its alias, else a short fingerprint
    /// marked "not in keyring".
    private func name(_ e: DecisionEvent) -> String {
        if !e.alias.isEmpty { return e.alias }
        if let trusted = model.trusted.first(where: { $0.fingerprint == e.by }) { return trusted.name }
        return "\(e.by.prefix(12)) (not in keyring)"
    }
}

private struct DecisionRow: View {
    let event: DecisionEvent
    let who: String

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s4) {
            HStack(spacing: Space.s8) {
                StateMark(kind: kind, words: event.decided)
                Text(event.asked)
                Text("·").secondaryText()
                Text(who).fontWeight(.bold)
                Spacer()
                Text(Date(timeIntervalSince1970: Double(event.atMillis) / 1000),
                     format: .dateTime.month().day().hour().minute().second())
                    .font(Theme.mono).secondaryText()
            }
            Text(event.why).secondaryText().textSelection(.enabled)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(event.decided): \(event.asked), \(who): \(event.why)")
    }

    private var kind: StateMark.Kind {
        switch event.decided {
        case "refused", "cut": return .danger
        case "untrusted", "stopped": return .attention
        default: return .plain
        }
    }
}
