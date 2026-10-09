// The selected keyring entry's card (G2, from the website's App Study, "Trust has a direction."):
// who trusts whom, one sentence per direction (D4's words), the rooms the trust covers now and
// later, and what removing the node would change (ADR-028 E-5), behind a disclosure.

import SwiftUI

extension Effects {
    /// What removing a node from the keyring does, said before it is done (E-5).
    static func removing(_ alias: String) -> String {
        "Removing \(alias): it reads nothing you write from now on, and you read nothing it "
            + "writes. What it already read stays read. Its live sessions into your services are "
            + "cut. Your sender key is rotated, and everyone you still trust is re-keyed."
    }
}

extension Trust {
    /// This node's direction, to `name`: it is in the keyring, so this node trusts it (G2).
    static func youTrust(_ name: String) -> String {
        "You trust \(name). Your node releases your sender keys to \(name) in the rooms you share."
    }

    /// `name`'s direction, to this node, as far as this node knows (G2, R-5).
    static func theyTrust(_ name: String, _ back: Bool) -> String {
        back
            ? "\(name) trusts you too. Each node accepts the other's keys: you read each other."
            : "\(name)'s trust in you has not reached this node yet: waiting for the other side. "
                + "Until it does, neither reads the other."
    }
}

struct KeyringCard: View {
    @ObservedObject var model: NodeModel
    let node: TrustedNode
    @State private var shared: [String]?
    @State private var showRemoval = false

    var body: some View {
        let back = model.trustsBack.contains(node.fingerprint)
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("UNDERSTANDING \(node.name.uppercased())'S ACCESS").eyebrow().secondaryText()
            // The label sits on a container, not the Text (see Services: a selectable Text with
            // its own label recursed in SwiftUI's accessibility and crashed, #579).
            HStack(spacing: 0) { Text("\(node.name) \(back ? "⇄" : "→") you").title() }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(node.name), \(back ? "trusted both ways" : "waiting for the other side")")
                .accessibilityIdentifier("keyring-card-heading")
            VStack(alignment: .leading, spacing: Space.s4) {
                Text("you → \(node.name)").fontWeight(.bold)
                Text(Trust.youTrust(node.name))
                    .accessibilityIdentifier("keyring-card-yours")
            }
            VStack(alignment: .leading, spacing: Space.s4) {
                Text("\(node.name) → you").fontWeight(.bold)
                Text(Trust.theyTrust(node.name, back))
                    .accessibilityIdentifier("keyring-card-theirs")
            }
            Group {
                switch shared {
                case nil:
                    Text("Reading the rooms you share…").secondaryText()
                case let rooms? where rooms.isEmpty:
                    Text("You share no room with \(node.name) yet. Trust covers any room you share "
                        + "later, and the services shared there.")
                case let rooms?:
                    Text("Shared rooms: \(rooms.joined(separator: " · ")). Trust also covers the "
                        + "services you share in them, and any rooms you share later.")
                }
            }
            .accessibilityIdentifier("keyring-card-rooms")
            Button(showRemoval ? "Hide what removing \(node.name) would change"
                   : "What would removing \(node.name) change?") { showRemoval.toggle() }
                .accessibilityIdentifier("keyring-card-removal-open")
            if showRemoval {
                Text(Effects.removing(node.name))
                    .secondaryText()
                    .accessibilityIdentifier("keyring-card-removal")
            }
        }
        .padding(Space.s12)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("keyring-card")
        .task(id: node.fingerprint) { shared = await model.sharedRooms(with: node.fingerprint) }
    }
}
