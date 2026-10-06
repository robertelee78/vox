// The lanes view (ADR-014 M-15; ADR-028 W-3–W-6): one column per member of a room with agents'
// nodes, each that member's posts in this room — a filter of the room's own timeline, not a
// second record — headed by its alias, trust glyph and one state chip derived by the node;
// what changed since the person last looked; and coordination traffic folded into one counted
// line.

import SwiftUI

extension NodeModel {
    /// Whether the room on screen has agents' nodes as members, so the lanes view is offered: a
    /// member whose lane is working, ready or done, or that announced a session.
    var roomHasAgents: Bool {
        lanes.contains { ["working", "ready", "done"].contains($0.state) }
            || messages.contains { $0.kind == "hello" && $0.author != me }
    }
}

struct LanesView: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        ScrollView(.horizontal) {
            HStack(alignment: .top, spacing: 12) {
                ForEach(model.lanes, id: \.fingerprint) { lane in
                    LaneColumn(model: model, lane: lane)
                        .frame(width: 280)
                }
            }
            .padding(12)
        }
    }
}

private struct LaneColumn: View {
    @ObservedObject var model: NodeModel
    let lane: Lane

    private var name: String { lane.name.isEmpty ? String(lane.fingerprint.prefix(12)) : lane.name }

    private var trust: Trust {
        model.members.first { $0.id == lane.fingerprint }?.trust ?? .none
    }

    /// This member's posts in the room, oldest first.
    private var posts: [RoomMessage] { model.messages.filter { $0.author == lane.fingerprint } }

    var body: some View {
        let talk = posts.filter { $0.level != .coordination }
        let coordination = posts.count - talk.count
        let looked = model.laneLooked[lane.fingerprint]
        let new = looked.flatMap { id in posts.firstIndex { $0.id == id } }
            .map { posts.count - 1 - $0 } ?? posts.count
        VStack(alignment: .leading, spacing: 8) {
            TrustMark(name: name, trust: trust)
            StateMark(kind: chip, words: lane.state)
                .accessibilityIdentifier("lane-state-\(name)")
                .accessibilityLabel("\(name): \(lane.state)")
            if new > 0 {
                Text("\(new) new since you looked").font(Theme.eyebrow).secondaryText()
            }
            Divider()
            ForEach(talk.suffix(20), id: \.id) { post in
                VStack(alignment: .leading, spacing: 2) {
                    Text(post.kind == "say" ? "" : post.kind).font(Theme.eyebrow).secondaryText()
                    Text(post.owed ? "not received yet" : post.text).textSelection(.enabled)
                    if let readers = model.readBy[post.id], !readers.isEmpty {
                        Text("read by \(readers.joined(separator: ", "))")
                            .font(Theme.eyebrow).secondaryText()
                    }
                }
            }
            if coordination > 0 {
                // ADR-020 6.6: coordination traffic, counted, not shown one by one.
                Text("\(coordination) coordination \(coordination == 1 ? "post" : "posts")")
                    .font(Theme.eyebrow).secondaryText()
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(VoxTokens.Colors.textSecondary.opacity(0.4)))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("lane-\(name)")
        .onDisappear {
            if let last = posts.last { model.laneLooked[lane.fingerprint] = last.id }
        }
    }

    private var chip: StateMark.Kind {
        switch lane.state {
        case "needs you": return .attention
        case "working": return .live
        default: return .plain
        }
    }
}

/// To: and urgent for what the composer posts (M-15): the members ticked are written into `to` as
/// whole fingerprints; urgent may interrupt their agents mid-turn.
struct ComposerAddress: View {
    @ObservedObject var model: NodeModel
    @Binding var to: Set<String>
    @Binding var urgent: Bool

    var body: some View {
        HStack(spacing: 8) {
            Menu {
                ForEach(model.members) { member in
                    Toggle(member.name, isOn: Binding(
                        get: { to.contains(member.id) },
                        set: { on in if on { to.insert(member.id) } else { to.remove(member.id) } }))
                }
            } label: {
                Text(to.isEmpty ? "To: the room" : "To: " + model.members
                    .filter { to.contains($0.id) }.map(\.name).joined(separator: ", "))
            }
            .fixedSize()
            .accessibilityIdentifier("compose-to")
            Toggle("Urgent", isOn: $urgent)
                .accessibilityIdentifier("compose-urgent")
                .accessibilityLabel(urgent ? "Urgent, on" : "Urgent, off")
        }
        .font(Theme.eyebrow)
    }
}
